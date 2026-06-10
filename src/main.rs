use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    extract::{ConnectInfo, Json, State},
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
    /// Stable peer identifier (generated once per process lifetime).
    #[serde(skip_serializing_if = "Option::is_none")]
    peer_id: Option<String>,
    /// Human-readable hostname.
    #[serde(skip_serializing_if = "Option::is_none")]
    hostname: Option<String>,
    /// Public IP as seen by the API server (without ephemeral port).
    public_ip: String,
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
    peers: HashMap<String, Peer>,       // keyed by role
    punch_nonces: HashMap<String, u64>, // keyed by role
    relay_nonces: HashMap<String, u64>, // keyed by role
}

type SessionMap = Arc<RwLock<HashMap<String, Session>>>;

#[derive(Clone)]
struct AppState {
    sessions: SessionMap,
    /// Externally reachable port of the TCP relay listener (None = relay disabled).
    relay_port: Option<u16>,
}

// ---------------------------------------------------------------------------
// Request / response DTOs
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct RegisterRequest {
    token: String,
    role: String, // "host" or "client"
    /// Stable peer identifier (generated once per process lifetime).
    #[serde(default)]
    peer_id: Option<String>,
    /// Human-readable hostname.
    #[serde(default)]
    hostname: Option<String>,
    /// Optional local IP:port candidates the peer already knows about.
    #[serde(default)]
    candidates: Vec<String>,
}

#[derive(Deserialize)]
struct UnregisterRequest {
    token: String,
    role: String,
    #[serde(default)]
    peer_id: Option<String>,
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

#[derive(Deserialize)]
struct PunchRequest {
    token: String,
    role: String,
    nonce: u64,
}

#[derive(Deserialize)]
struct SessionStatusRequest {
    token: String,
    /// Role of the polling peer ("host"/"client"), if known. Polling is a sign
    /// of life, so refresh that peer's `last_seen` here — otherwise a peer that
    /// has gone quiet except for session polls ages out at SESSION_TTL.
    #[serde(default)]
    role: Option<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    host_peer_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_peer_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    host_hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_hostname: Option<String>,
    host_punch_nonce: u64,
    client_punch_nonce: u64,
    host_relay_nonce: u64,
    client_relay_nonce: u64,
    /// TCP relay port peers can dial (on the same host as this API) when both
    /// direct connection and UDP hole punching fail. Absent when disabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    relay_port: Option<u16>,
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
    if req.token.len() > MAX_TOKEN_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: "token too long".into(),
            }),
        ));
    }
    if req
        .peer_id
        .as_ref()
        .is_some_and(|s| s.len() > MAX_STRING_FIELD_LEN)
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: "peer_id too long".into(),
            }),
        ));
    }
    if req
        .hostname
        .as_ref()
        .is_some_and(|s| s.len() > MAX_STRING_FIELD_LEN)
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: "hostname too long".into(),
            }),
        ));
    }

    let mut sessions = state.sessions.write().await;

    // Reject new sessions when the server is at capacity.
    if !sessions.contains_key(&req.token) && sessions.len() >= MAX_SESSIONS {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorBody {
                error: "too many active sessions".into(),
            }),
        ));
    }

    let session = sessions
        .entry(req.token.clone())
        .or_insert_with(|| Session {
            peers: HashMap::new(),
            punch_nonces: HashMap::new(),
            relay_nonces: HashMap::new(),
        });

    let partner_joined = session.peers.contains_key(partner_role(&req.role));

    // Candidates are now provided by the peer itself (including STUN-discovered
    // public addresses). The API server just stores them as-is.
    // Truncate to prevent oversized candidate lists.
    let mut candidates: Vec<String> = req
        .candidates
        .into_iter()
        .filter(|c| c.len() <= MAX_STRING_FIELD_LEN)
        .collect();
    candidates.truncate(MAX_CANDIDATES);

    // Preserve existing fields on re-registration.
    let prev = session.peers.get(&req.role);
    let is_new = prev.is_none();
    let public_key = prev.and_then(|p| p.public_key.clone());
    // Don't let a register carrying an empty (not-yet-gathered) candidate list
    // clobber candidates the same peer uploaded moments earlier — e.g. a
    // periodic re-register firing before STUN finished. Preserve the previous
    // list when the incoming one is empty (mirrors the public_key-preserve).
    let candidates = if candidates.is_empty() {
        prev.map(|p| p.candidates.clone()).unwrap_or_default()
    } else {
        candidates
    };
    // peer_id is the stable identity clients use to merge a host's LAN and public
    // variants into one entry. Require it (non-empty) so an identity-less host can
    // never be advertised; the host always sends one.
    let peer_id = req.peer_id.or_else(|| prev.and_then(|p| p.peer_id.clone()));
    let peer_id = match peer_id {
        Some(p) if !p.is_empty() => p,
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorBody {
                    error: "peer_id required".into(),
                }),
            ));
        }
    };
    let hostname = req
        .hostname
        .or_else(|| prev.and_then(|p| p.hostname.clone()));

    if is_new {
        info!(
            role = %req.role,
            peer_id = %peer_id,
            hostname = hostname.as_deref().unwrap_or("-"),
            addr = %addr.ip(),
            "peer registered"
        );
    }

    session.peers.insert(
        req.role.clone(),
        Peer {
            role: req.role.clone(),
            peer_id: Some(peer_id),
            hostname,
            public_ip: addr.ip().to_string(),
            public_key,
            candidates,
            last_seen: Instant::now(),
        },
    );

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
    ConnectInfo(_addr): ConnectInfo<SocketAddr>,
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

    // Candidates are provided by the peer itself (including STUN-discovered
    // public addresses). Just store them (truncated to cap).
    let mut cands: Vec<String> = req
        .candidates
        .into_iter()
        .filter(|c| c.len() <= MAX_STRING_FIELD_LEN)
        .collect();
    cands.truncate(MAX_CANDIDATES);
    peer.candidates = cands;
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

/// POST /api/punch — record a monotonic punch request nonce for a peer.
async fn request_punch(
    State(state): State<AppState>,
    Json(req): Json<PunchRequest>,
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
    peer.last_seen = Instant::now();

    let entry = session.punch_nonces.entry(req.role).or_insert(0);
    *entry = (*entry).max(req.nonce);

    Ok(Json(serde_json::json!({"status": "ok"})))
}

/// POST /api/relay — record a monotonic TCP-relay request nonce for a peer.
/// The partner sees it on its next session poll and dials the relay listener.
async fn request_relay(
    State(state): State<AppState>,
    Json(req): Json<PunchRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorBody>)> {
    validate_role(&req.role)?;
    if state.relay_port.is_none() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorBody {
                error: "relay disabled".into(),
            }),
        ));
    }

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
    peer.last_seen = Instant::now();

    let entry = session.relay_nonces.entry(req.role).or_insert(0);
    *entry = (*entry).max(req.nonce);

    Ok(Json(serde_json::json!({"status": "ok"})))
}

/// POST /api/session — poll session status.
async fn session_status(
    State(state): State<AppState>,
    Json(req): Json<SessionStatusRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorBody>)> {
    let token = req.token;
    let mut sessions = state.sessions.write().await;
    let session = sessions.get_mut(&token).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorBody {
                error: "session not found".into(),
            }),
        )
    })?;

    // Polling is a sign of life — refresh the polling peer so a peer that has
    // gone quiet except for session polls doesn't age out at SESSION_TTL
    // mid-handshake (e.g. during a slow hole punch).
    if let Some(role) = req.role.as_deref() {
        if let Some(peer) = session.peers.get_mut(role) {
            peer.last_seen = Instant::now();
        }
    }

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
        host_peer_id: host.and_then(|p| p.peer_id.clone()),
        client_peer_id: client.and_then(|p| p.peer_id.clone()),
        host_hostname: host.and_then(|p| p.hostname.clone()),
        client_hostname: client.and_then(|p| p.hostname.clone()),
        host_punch_nonce: session.punch_nonces.get("host").copied().unwrap_or(0),
        client_punch_nonce: session.punch_nonces.get("client").copied().unwrap_or(0),
        host_relay_nonce: session.relay_nonces.get("host").copied().unwrap_or(0),
        client_relay_nonce: session.relay_nonces.get("client").copied().unwrap_or(0),
        relay_port: state.relay_port,
    }))
}

/// POST /api/unregister — remove a peer from a session.
async fn unregister(
    State(state): State<AppState>,
    Json(req): Json<UnregisterRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorBody>)> {
    validate_role(&req.role)?;

    let mut sessions = state.sessions.write().await;
    if let Some(session) = sessions.get_mut(&req.token) {
        // Only remove if peer_id matches (or no peer_id check requested).
        let should_remove = match (&req.peer_id, session.peers.get(&req.role)) {
            (Some(req_id), Some(peer)) => peer.peer_id.as_deref() == Some(req_id.as_str()),
            (None, Some(_)) => true,
            _ => false,
        };
        if should_remove {
            session.peers.remove(&req.role);
            session.punch_nonces.remove(&req.role);
            session.relay_nonces.remove(&req.role);
            let log_id = req.peer_id.as_deref().unwrap_or("-");
            info!(role = %req.role, peer_id = %log_id, "peer unregistered");
            if session.peers.is_empty() {
                sessions.remove(&req.token);
            }
        }
    }

    Ok(Json(serde_json::json!({"status": "ok"})))
}

/// GET /health — simple liveness check.
async fn health() -> &'static str {
    "ok"
}

// ---------------------------------------------------------------------------
// Session cleanup
// ---------------------------------------------------------------------------

const SESSION_TTL: Duration = Duration::from_secs(120);
const CLEANUP_INTERVAL: Duration = Duration::from_secs(30);
/// Hard cap on concurrent sessions to prevent memory exhaustion.
const MAX_SESSIONS: usize = 1000;
/// Hard cap on candidate addresses per peer.
const MAX_CANDIDATES: usize = 32;
/// Hard cap on string field lengths to prevent memory abuse.
const MAX_TOKEN_LEN: usize = 256;
const MAX_STRING_FIELD_LEN: usize = 256;

async fn cleanup_loop(sessions: SessionMap) {
    loop {
        tokio::time::sleep(CLEANUP_INTERVAL).await;
        let mut map = sessions.write().await;
        let before = map.len();

        // First, prune individual stale peers within each session.
        for session in map.values_mut() {
            session.peers.retain(|_role, peer| {
                let alive = peer.last_seen.elapsed() < SESSION_TTL;
                if !alive {
                    info!(
                        role = %peer.role,
                        peer_id = peer.peer_id.as_deref().unwrap_or("-"),
                        "peer expired"
                    );
                }
                alive
            });
            session
                .punch_nonces
                .retain(|role, _| session.peers.contains_key(role));
            session
                .relay_nonces
                .retain(|role, _| session.peers.contains_key(role));
        }

        // Then remove empty sessions.
        map.retain(|_token, session| !session.peers.is_empty());
        let removed = before - map.len();
        if removed > 0 {
            info!(removed, remaining = map.len(), "cleanup sweep");
        }
    }
}

// ---------------------------------------------------------------------------
// TCP relay
// ---------------------------------------------------------------------------
//
// Last-resort transport when both direct connection and UDP hole punching
// fail (UDP blocked, hostile NATs, proxies). Both peers of a session dial
// this listener over TCP, identify themselves with one handshake line:
//
//   `STRELAY1 <role> <token_base64>\n`
//
// and once both roles of the same token are present the relay replies
// `OK\n` to each and pipes bytes verbatim in both directions. The peers run
// their ChaCha20-Poly1305 tunnel over the pipe, so the relay never sees
// plaintext media or control data. Tokens must belong to a registered
// signaling session, mirroring what /api/* endpoints already learn.

/// Cap on concurrently piped relay sessions.
const MAX_ACTIVE_RELAYS: usize = 256;
/// Cap on idle peers waiting for a partner (half-open relay connections).
const MAX_WAITING_RELAYS: usize = 256;
/// How long a lone peer may wait for its partner before being dropped.
const RELAY_PAIR_TIMEOUT: Duration = Duration::from_secs(35);
/// Tear a piped session down after this long without bytes in either
/// direction (peers exchange keepalives/feedback every ~500 ms while alive).
const RELAY_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
/// Handshake line length cap (`STRELAY1 ` + role + base64 token).
const RELAY_HELLO_MAX: usize = 512;

struct RelayWaiting {
    stream: tokio::net::TcpStream,
    since: Instant,
}

type RelayWaitMap = Arc<tokio::sync::Mutex<HashMap<String, HashMap<String, RelayWaiting>>>>;

async fn read_relay_hello(stream: &mut tokio::net::TcpStream) -> Option<(String, String)> {
    use tokio::io::AsyncReadExt;
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let read = tokio::time::timeout_at(deadline, stream.read(&mut byte)).await;
        match read {
            Ok(Ok(1)) => {
                if byte[0] == b'\n' {
                    break;
                }
                line.push(byte[0]);
                if line.len() > RELAY_HELLO_MAX {
                    return None;
                }
            }
            _ => return None,
        }
    }
    let line = String::from_utf8(line).ok()?;
    let mut parts = line.trim().split_whitespace();
    if parts.next()? != "STRELAY1" {
        return None;
    }
    let role = parts.next()?.to_string();
    if role != "host" && role != "client" {
        return None;
    }
    let token = String::from_utf8(BASE64.decode(parts.next()?).ok()?).ok()?;
    if token.is_empty() || token.len() > MAX_TOKEN_LEN {
        return None;
    }
    Some((role, token))
}

/// Pipe one direction with an idle timeout on BOTH read and write; aborts its
/// sibling via socket shutdown when it ends. The write timeout matters as much
/// as the read one: a peer that stops reading (suspend / blackhole with no RST)
/// would otherwise block `write_all` indefinitely — TCP zero-window probes keep
/// the connection "alive" so the read-side idle timeout never fires — pinning
/// the relay slot until the OS gives up (~15 min).
async fn relay_pipe_dir(
    mut from: tokio::net::tcp::OwnedReadHalf,
    mut to: tokio::net::tcp::OwnedWriteHalf,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = match tokio::time::timeout(RELAY_IDLE_TIMEOUT, from.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(n)) => n,
        };
        match tokio::time::timeout(RELAY_IDLE_TIMEOUT, to.write_all(&buf[..n])).await {
            Ok(Ok(())) => {}
            _ => break,
        }
    }
    let _ = to.shutdown().await;
}

async fn run_relay_listener(bind: String, sessions: SessionMap) {
    let listener = match tokio::net::TcpListener::bind(&bind).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(%bind, error = %e, "relay listener bind failed");
            return;
        }
    };
    info!(%bind, "relay listener started");
    run_relay_on(listener, sessions).await;
}

async fn run_relay_on(listener: tokio::net::TcpListener, sessions: SessionMap) {
    let waiting: RelayWaitMap = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    // Sweep abandoned waiters.
    {
        let waiting = Arc::clone(&waiting);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(5)).await;
                let mut map = waiting.lock().await;
                for conns in map.values_mut() {
                    conns.retain(|_role, w| w.since.elapsed() < RELAY_PAIR_TIMEOUT);
                }
                map.retain(|_t, conns| !conns.is_empty());
            }
        });
    }

    loop {
        let (mut stream, peer_addr) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "relay accept error");
                continue;
            }
        };
        let sessions = sessions.clone();
        let waiting = Arc::clone(&waiting);
        let active = Arc::clone(&active);
        tokio::spawn(async move {
            let _ = stream.set_nodelay(true);
            let Some((role, token)) = read_relay_hello(&mut stream).await else {
                return;
            };
            // Only relay for sessions the signaling side knows about.
            if !sessions.read().await.contains_key(&token) {
                tracing::warn!(%role, %peer_addr, "relay hello for unknown session");
                return;
            }

            let partner = {
                let mut map = waiting.lock().await;
                // Global cap on idle waiters (independent of MAX_ACTIVE_RELAYS,
                // which only bounds *paired* sessions) so a flood of half-open
                // relay connections can't accumulate sockets.
                let total_waiters: usize = map.values().map(|c| c.len()).sum();
                let conns = map.entry(token.clone()).or_default();
                let partner = conns.remove(partner_role(&role));
                if partner.is_none() {
                    // Don't let a second connector of the same role evict the
                    // genuine peer already waiting — that would let anyone who
                    // knows the token deny the pairing by racing in first.
                    if conns.contains_key(&role) {
                        tracing::warn!(%role, %peer_addr, "relay role already waiting; rejecting duplicate");
                        if conns.is_empty() {
                            map.remove(&token);
                        }
                        return;
                    }
                    if total_waiters >= MAX_WAITING_RELAYS {
                        tracing::warn!(%peer_addr, "relay waiter cap reached; rejecting");
                        if conns.is_empty() {
                            map.remove(&token);
                        }
                        return;
                    }
                    conns.insert(
                        role.clone(),
                        RelayWaiting {
                            stream,
                            since: Instant::now(),
                        },
                    );
                    if conns.len() == 1 {
                        info!(%role, %peer_addr, "relay peer waiting for partner");
                    }
                    return;
                }
                if map.get(&token).is_some_and(|c| c.is_empty()) {
                    map.remove(&token);
                }
                partner
            };
            let Some(partner) = partner else { return };

            if active.load(std::sync::atomic::Ordering::Relaxed) >= MAX_ACTIVE_RELAYS {
                tracing::warn!("relay at capacity; dropping session pair");
                return;
            }

            use tokio::io::AsyncWriteExt;
            let mut a = stream;
            let mut b = partner.stream;
            if a.write_all(b"OK\n").await.is_err() || b.write_all(b"OK\n").await.is_err() {
                return;
            }
            info!(%role, %peer_addr, "relay session paired");
            active.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

            let (ar, aw) = a.into_split();
            let (br, bw) = b.into_split();
            let dir1 = tokio::spawn(relay_pipe_dir(ar, bw));
            let dir2 = tokio::spawn(relay_pipe_dir(br, aw));
            let _ = dir1.await;
            let _ = dir2.await;

            active.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            info!("relay session ended");
        });
    }
}

#[cfg(test)]
mod relay_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn session_map_with(token: &str) -> SessionMap {
        let mut sessions = HashMap::new();
        sessions.insert(
            token.to_string(),
            Session {
                peers: HashMap::new(),
                punch_nonces: HashMap::new(),
                relay_nonces: HashMap::new(),
            },
        );
        Arc::new(RwLock::new(sessions))
    }

    async fn hello(stream: &mut tokio::net::TcpStream, role: &str, token: &str) {
        let line = format!("STRELAY1 {role} {}\n", BASE64.encode(token.as_bytes()));
        stream.write_all(line.as_bytes()).await.unwrap();
    }

    #[tokio::test]
    async fn pairs_and_pipes_bidirectionally() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(run_relay_on(listener, session_map_with("tok")));

        let mut host = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        hello(&mut host, "host", "tok").await;
        hello(&mut client, "client", "tok").await;

        let mut ok = [0u8; 3];
        host.read_exact(&mut ok).await.unwrap();
        assert_eq!(&ok, b"OK\n");
        client.read_exact(&mut ok).await.unwrap();
        assert_eq!(&ok, b"OK\n");

        host.write_all(b"from-host").await.unwrap();
        client.write_all(b"from-client").await.unwrap();
        let mut buf = [0u8; 9];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"from-host");
        let mut buf = [0u8; 11];
        host.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"from-client");
    }

    #[tokio::test]
    async fn second_same_role_waiter_does_not_evict_the_first() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(run_relay_on(listener, session_map_with("tok")));

        // First host waits.
        let mut host1 = tokio::net::TcpStream::connect(addr).await.unwrap();
        hello(&mut host1, "host", "tok").await;
        // Give the relay a moment to register host1 as the waiter.
        tokio::time::sleep(Duration::from_millis(100)).await;
        // A second host races in — it must be rejected, not replace host1.
        let mut host2 = tokio::net::TcpStream::connect(addr).await.unwrap();
        hello(&mut host2, "host", "tok").await;

        // The genuine client pairs with host1 (still waiting), not host2.
        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        hello(&mut client, "client", "tok").await;

        let mut ok = [0u8; 3];
        host1.read_exact(&mut ok).await.unwrap();
        assert_eq!(&ok, b"OK\n");
        client.read_exact(&mut ok).await.unwrap();
        assert_eq!(&ok, b"OK\n");

        // host1 ↔ client pipe works.
        host1.write_all(b"hi-client").await.unwrap();
        let mut buf = [0u8; 9];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hi-client");

        // host2 was rejected: its connection is closed with no OK.
        let n = tokio::time::timeout(Duration::from_secs(2), host2.read(&mut ok))
            .await
            .expect("relay should close the duplicate")
            .unwrap();
        assert_eq!(n, 0, "duplicate host should be closed, got {:?}", &ok[..n]);
    }

    #[tokio::test]
    async fn rejects_unknown_session_token() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(run_relay_on(listener, session_map_with("tok")));

        let mut stranger = tokio::net::TcpStream::connect(addr).await.unwrap();
        hello(&mut stranger, "client", "wrong-token").await;
        // Connection is closed without OK.
        let mut buf = [0u8; 3];
        let n = tokio::time::timeout(Duration::from_secs(2), stranger.read(&mut buf))
            .await
            .expect("relay should close the connection promptly")
            .unwrap();
        assert_eq!(n, 0, "expected EOF, got {:?}", &buf[..n]);
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

    // TCP relay listener. RELAY_BIND_ADDR=off disables it; RELAY_PUBLIC_PORT
    // overrides the advertised port when the relay sits behind a port mapping.
    let relay_bind = std::env::var("RELAY_BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:3001".into());
    let relay_port = if relay_bind.eq_ignore_ascii_case("off") {
        None
    } else {
        let bound_port = relay_bind
            .rsplit(':')
            .next()
            .and_then(|p| p.parse::<u16>().ok());
        std::env::var("RELAY_PUBLIC_PORT")
            .ok()
            .and_then(|p| p.parse::<u16>().ok())
            .or(bound_port)
    };

    let state = AppState {
        sessions: Arc::new(RwLock::new(HashMap::new())),
        relay_port,
    };

    // Background cleanup
    tokio::spawn(cleanup_loop(state.sessions.clone()));

    if relay_port.is_some() {
        tokio::spawn(run_relay_listener(relay_bind, state.sessions.clone()));
    }

    let app = Router::new()
        .route("/health", get(health))
        .route("/api/register", post(register))
        .route("/api/unregister", post(unregister))
        .route("/api/key", post(key_exchange))
        .route("/api/candidates", post(candidates))
        .route("/api/punch", post(request_punch))
        .route("/api/relay", post(request_relay))
        .route("/api/session", post(session_status))
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
