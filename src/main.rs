use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    extract::{ConnectInfo, Json, Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tower_http::cors::CorsLayer;
use tracing::info;

// ---------------------------------------------------------------------------
// Data models
// ---------------------------------------------------------------------------

/// A peer registered in a session.
#[derive(Clone, Serialize)]
struct Peer {
    /// Which role this peer claimed ("host" or "client").
    role: String,
    /// Public address as seen by the API server.
    public_addr: SocketAddr,
    /// X25519 public key (32 bytes, base64-encoded).
    #[serde(skip_serializing_if = "Option::is_none")]
    public_key: Option<String>,
    /// NAT candidates the peer advertises (public + local IP:port pairs).
    candidates: Vec<String>,
    /// When the peer last contacted us.
    #[serde(skip)]
    last_seen: Instant,
}

/// A session groups exactly two peers (host + client) under a shared token.
#[derive(Clone)]
struct Session {
    peers: HashMap<String, Peer>, // keyed by role
    created: Instant,
}

type SessionMap = Arc<RwLock<HashMap<String, Session>>>;

#[derive(Clone)]
struct AppState {
    sessions: SessionMap,
}

// ---------------------------------------------------------------------------
// Request / response DTOs
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct RegisterRequest {
    token: String,
    role: String, // "host" or "client"
    /// Optional local IP:port candidates the peer already knows about.
    #[serde(default)]
    candidates: Vec<String>,
}

#[derive(Serialize)]
struct RegisterResponse {
    status: &'static str,
    role: String,
    partner_joined: bool,
}

#[derive(Deserialize)]
struct KeyUploadRequest {
    token: String,
    role: String,
    /// Base64-encoded 32-byte X25519 public key.
    public_key: String,
}

#[derive(Serialize)]
struct KeyResponse {
    status: &'static str,
    /// Partner's base64-encoded public key, if available.
    partner_key: Option<String>,
}

#[derive(Deserialize)]
struct CandidatesRequest {
    token: String,
    role: String,
    candidates: Vec<String>,
}

#[derive(Serialize)]
struct CandidatesResponse {
    status: &'static str,
    partner_candidates: Vec<String>,
}

#[derive(Serialize)]
struct SessionStatus {
    token: String,
    host_joined: bool,
    client_joined: bool,
    host_has_key: bool,
    client_has_key: bool,
    host_candidates: Vec<String>,
    client_candidates: Vec<String>,
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn partner_role(role: &str) -> &str {
    match role {
        "host" => "client",
        "client" => "host",
        _ => "unknown",
    }
}

fn validate_role(role: &str) -> Result<(), (StatusCode, Json<ErrorBody>)> {
    if role != "host" && role != "client" {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: "role must be \"host\" or \"client\"".into(),
            }),
        ));
    }
    Ok(())
}

fn validate_public_key(key_b64: &str) -> Result<(), (StatusCode, Json<ErrorBody>)> {
    match BASE64.decode(key_b64) {
        Ok(bytes) if bytes.len() == 32 => Ok(()),
        _ => Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: "public_key must be 32 bytes base64-encoded".into(),
            }),
        )),
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// POST /api/register — register a peer into a session by token + role.
async fn register(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(req): Json<RegisterRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorBody>)> {
    validate_role(&req.role)?;

    let mut sessions = state.sessions.write().await;
    let session = sessions.entry(req.token.clone()).or_insert_with(|| Session {
        peers: HashMap::new(),
        created: Instant::now(),
    });

    if session.peers.contains_key(&req.role) && session.peers[&req.role].public_addr != addr {
        return Err((
            StatusCode::CONFLICT,
            Json(ErrorBody {
                error: format!("role \"{}\" already taken in this session", req.role),
            }),
        ));
    }

    let partner_joined = session.peers.contains_key(partner_role(&req.role));

    session.peers.insert(
        req.role.clone(),
        Peer {
            role: req.role.clone(),
            public_addr: addr,
            public_key: None,
            candidates: req.candidates,
            last_seen: Instant::now(),
        },
    );

    info!(token = %req.token, role = %req.role, addr = %addr, "peer registered");

    Ok(Json(RegisterResponse {
        status: "ok",
        role: req.role,
        partner_joined,
    }))
}

/// POST /api/key — upload your X25519 public key and get partner's key back.
async fn key_exchange(
    State(state): State<AppState>,
    Json(req): Json<KeyUploadRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorBody>)> {
    validate_role(&req.role)?;
    validate_public_key(&req.public_key)?;

    let mut sessions = state.sessions.write().await;
    let session = sessions.get_mut(&req.token).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorBody {
                error: "session not found".into(),
            }),
        )
    })?;

    let peer = session.peers.get_mut(&req.role).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorBody {
                error: "peer not registered in session".into(),
            }),
        )
    })?;

    peer.public_key = Some(req.public_key);
    peer.last_seen = Instant::now();

    let partner_key = session
        .peers
        .get(partner_role(&req.role))
        .and_then(|p| p.public_key.clone());

    Ok(Json(KeyResponse {
        status: "ok",
        partner_key,
    }))
}

/// POST /api/candidates — share NAT candidates and get partner's candidates.
async fn candidates(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(req): Json<CandidatesRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorBody>)> {
    validate_role(&req.role)?;

    let mut sessions = state.sessions.write().await;
    let session = sessions.get_mut(&req.token).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorBody {
                error: "session not found".into(),
            }),
        )
    })?;

    let peer = session.peers.get_mut(&req.role).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorBody {
                error: "peer not registered in session".into(),
            }),
        )
    })?;

    // Always include the server-observed public address as a candidate.
    let mut all_candidates = req.candidates;
    let pub_candidate = addr.to_string();
    if !all_candidates.contains(&pub_candidate) {
        all_candidates.push(pub_candidate);
    }
    peer.candidates = all_candidates;
    peer.last_seen = Instant::now();

    let partner_candidates = session
        .peers
        .get(partner_role(&req.role))
        .map(|p| p.candidates.clone())
        .unwrap_or_default();

    Ok(Json(CandidatesResponse {
        status: "ok",
        partner_candidates,
    }))
}

/// GET /api/session/:token — poll session status.
async fn session_status(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorBody>)> {
    let sessions = state.sessions.read().await;
    let session = sessions.get(&token).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorBody {
                error: "session not found".into(),
            }),
        )
    })?;

    let host = session.peers.get("host");
    let client = session.peers.get("client");

    Ok(Json(SessionStatus {
        token,
        host_joined: host.is_some(),
        client_joined: client.is_some(),
        host_has_key: host.and_then(|p| p.public_key.as_ref()).is_some(),
        client_has_key: client.and_then(|p| p.public_key.as_ref()).is_some(),
        host_candidates: host.map(|p| p.candidates.clone()).unwrap_or_default(),
        client_candidates: client.map(|p| p.candidates.clone()).unwrap_or_default(),
    }))
}

/// GET /health — simple liveness check.
async fn health() -> &'static str {
    "ok"
}

// ---------------------------------------------------------------------------
// Session cleanup
// ---------------------------------------------------------------------------

const SESSION_TTL: Duration = Duration::from_secs(5 * 60); // 5 minutes
const CLEANUP_INTERVAL: Duration = Duration::from_secs(30);

async fn cleanup_loop(sessions: SessionMap) {
    loop {
        tokio::time::sleep(CLEANUP_INTERVAL).await;
        let mut map = sessions.write().await;
        let before = map.len();
        map.retain(|token, session| {
            let dominated_by = session
                .peers
                .values()
                .map(|p| p.last_seen)
                .max()
                .unwrap_or(session.created);
            let alive = dominated_by.elapsed() < SESSION_TTL;
            if !alive {
                info!(token = %token, "session expired");
            }
            alive
        });
        let removed = before - map.len();
        if removed > 0 {
            info!(removed, remaining = map.len(), "cleanup sweep");
        }
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "st_api_server=info,tower_http=info".into()),
        )
        .init();

    let state = AppState {
        sessions: Arc::new(RwLock::new(HashMap::new())),
    };

    // Background cleanup
    tokio::spawn(cleanup_loop(state.sessions.clone()));

    let app = Router::new()
        .route("/health", get(health))
        .route("/api/register", post(register))
        .route("/api/key", post(key_exchange))
        .route("/api/candidates", post(candidates))
        .route("/api/session/{token}", get(session_status))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let bind = std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:3000".into());
    let addr: SocketAddr = bind.parse().expect("invalid BIND_ADDR");
    info!(%addr, "starting API server");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}
