use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use axum::{
    extract::{Json, State},
    http::{header, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use base64::{
    engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD},
    Engine,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use tokio::sync::{OwnedSemaphorePermit, RwLock, Semaphore};
use tower_http::cors::CorsLayer;
use tracing::info;

const SESSION_TTL: Duration = Duration::from_secs(120);
const SIGNAL_REQUEST_TTL: Duration = Duration::from_secs(60);
const RELAY_TICKET_TTL: Duration = Duration::from_secs(45);
const CLEANUP_INTERVAL: Duration = Duration::from_secs(30);
const RELAY_PAIR_TIMEOUT: Duration = Duration::from_secs(35);
const RELAY_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_SESSIONS: usize = 1000;
const MAX_CANDIDATES: usize = 32;
const MAX_TOKEN_LEN: usize = 256;
const MAX_STRING_FIELD_LEN: usize = 256;
const MAX_RELAY_TICKET_LEN: usize = 128;
const RELAY_HELLO_MAX: usize = 160;
const MAX_ACTIVE_RELAYS: usize = 256;
const MAX_WAITING_RELAYS: usize = 256;
const MAX_PREAUTH_RELAYS: usize = MAX_ACTIVE_RELAYS * 2 + MAX_WAITING_RELAYS;

type ApiError = (StatusCode, Json<ErrorBody>);
type SharedStore = Arc<RwLock<Store>>;

#[derive(Clone)]
struct AppState {
    store: SharedStore,
    relay_port: Option<u16>,
    relay_ready: Arc<AtomicBool>,
    relay_slots: Arc<Semaphore>,
    relay_waiter_slots: Arc<Semaphore>,
    relay_preauth_slots: Arc<Semaphore>,
}

impl AppState {
    fn advertised_relay_port(&self) -> Option<u16> {
        self.relay_ready
            .load(Ordering::Acquire)
            .then_some(self.relay_port)
            .flatten()
    }
}

#[derive(Default)]
struct Store {
    sessions: HashMap<String, Session>,
    tickets: HashMap<String, RelayTicket>,
}

struct Session {
    id: String,
    peers: HashMap<String, Peer>,
    punch_requests: HashMap<String, SignalRequest>,
    relay_requests: HashMap<String, SignalRequest>,
    punch_generation_high_water: HashMap<String, u64>,
    relay_generation_high_water: HashMap<String, u64>,
}

#[derive(Clone)]
struct Peer {
    role: String,
    peer_id: String,
    lease_id: String,
    hostname: Option<String>,
    public_key: Option<String>,
    candidates: Vec<String>,
    last_seen: Instant,
}

#[derive(Clone)]
struct SignalRequest {
    generation: u64,
    owner_peer_id: String,
    owner_lease_id: String,
    expected_partner_peer_id: String,
    partner_peer_id: String,
    partner_lease_id: String,
    pair_id: Option<String>,
    context: String,
    created_at: Instant,
}

#[derive(Clone)]
struct RelayTicket {
    session_id: String,
    pair_id: String,
    role: String,
    peer_id: String,
    lease_id: String,
    partner_peer_id: String,
    partner_lease_id: String,
    requester_role: String,
    request_generation: u64,
    expires_at: Instant,
}

#[derive(Deserialize)]
struct RegisterRequest {
    token: String,
    role: String,
    peer_id: String,
    lease_id: String,
    #[serde(default)]
    hostname: Option<String>,
    #[serde(default)]
    candidates: Vec<String>,
    #[serde(default)]
    public_key: Option<String>,
}

#[derive(Deserialize)]
struct OwnedRequest {
    token: String,
    role: String,
    peer_id: String,
    lease_id: String,
}

#[derive(Deserialize)]
struct KeyUploadRequest {
    token: String,
    role: String,
    peer_id: String,
    lease_id: String,
    expected_partner_peer_id: String,
    expected_partner_lease_id: String,
    public_key: String,
}

#[derive(Deserialize)]
struct CandidatesRequest {
    token: String,
    role: String,
    peer_id: String,
    lease_id: String,
    expected_partner_peer_id: String,
    expected_partner_lease_id: String,
    candidates: Vec<String>,
}

#[derive(Deserialize)]
struct SignalRequestBody {
    token: String,
    role: String,
    peer_id: String,
    lease_id: String,
    expected_partner_peer_id: String,
    expected_partner_lease_id: String,
    generation: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum RelayMode {
    Request,
    Join,
}

#[derive(Deserialize)]
struct RelayRequestBody {
    token: String,
    role: String,
    peer_id: String,
    lease_id: String,
    expected_partner_peer_id: String,
    expected_partner_lease_id: String,
    generation: u64,
    mode: RelayMode,
}

#[derive(Deserialize)]
struct SessionStatusRequest {
    token: String,
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    peer_id: Option<String>,
    #[serde(default)]
    lease_id: Option<String>,
    #[serde(default)]
    expected_partner_peer_id: Option<String>,
    #[serde(default)]
    expected_partner_lease_id: Option<String>,
}

#[derive(Serialize)]
struct RegisterResponse {
    status: &'static str,
    role: String,
    partner_joined: bool,
}

#[derive(Serialize)]
struct KeyResponse {
    status: &'static str,
    partner_key: Option<String>,
    partner_peer_id: String,
    partner_lease_id: String,
}

#[derive(Serialize)]
struct CandidatesResponse {
    status: &'static str,
    partner_candidates: Vec<String>,
    partner_peer_id: String,
    partner_lease_id: String,
}

#[derive(Clone, Serialize)]
struct PeerStatus {
    peer_id: String,
    lease_id: String,
    hostname: Option<String>,
    has_key: bool,
    candidates: Vec<String>,
}

#[derive(Clone, Serialize)]
struct SignalRequestStatus {
    generation: u64,
    owner_peer_id: String,
    owner_lease_id: String,
    expected_partner_peer_id: String,
    partner_peer_id: String,
    partner_lease_id: String,
    context: String,
}

#[derive(Serialize)]
struct SessionStatus {
    session_id: String,
    host: Option<PeerStatus>,
    client: Option<PeerStatus>,
    host_punch_request: Option<SignalRequestStatus>,
    client_punch_request: Option<SignalRequestStatus>,
    host_relay_request: Option<SignalRequestStatus>,
    client_relay_request: Option<SignalRequestStatus>,
    relay_port: Option<u16>,
}

#[derive(Serialize)]
struct RelayResponse {
    status: &'static str,
    ticket: String,
    expires_in_seconds: u64,
    relay_port: u16,
    session_id: String,
    mode: &'static str,
    generation: u64,
    owner_peer_id: String,
    owner_lease_id: String,
    partner_peer_id: String,
    partner_lease_id: String,
    context: String,
}

#[derive(Serialize)]
struct PunchResponse {
    status: &'static str,
    session_id: String,
    mode: &'static str,
    generation: u64,
    owner_peer_id: String,
    owner_lease_id: String,
    partner_peer_id: String,
    partner_lease_id: String,
    context: String,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: String,
}

#[derive(Serialize)]
struct HealthStatus {
    status: &'static str,
    relay_enabled: bool,
    relay_port: Option<u16>,
}

fn random_id() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn partner_role(role: &str) -> &str {
    match role {
        "host" => "client",
        "client" => "host",
        _ => "unknown",
    }
}

fn request_error(status: StatusCode, error: impl Into<String>) -> ApiError {
    (
        status,
        Json(ErrorBody {
            error: error.into(),
        }),
    )
}

fn validate_role(role: &str) -> Result<(), ApiError> {
    if matches!(role, "host" | "client") {
        Ok(())
    } else {
        Err(request_error(
            StatusCode::BAD_REQUEST,
            "role must be \"host\" or \"client\"",
        ))
    }
}

fn validate_field(name: &str, value: &str, max_len: usize) -> Result<(), ApiError> {
    if value.is_empty() {
        return Err(request_error(
            StatusCode::BAD_REQUEST,
            format!("{name} required"),
        ));
    }
    if value.len() > max_len {
        return Err(request_error(
            StatusCode::BAD_REQUEST,
            format!("{name} too long"),
        ));
    }
    Ok(())
}

fn validate_identity(
    role: &str,
    token: &str,
    peer_id: &str,
    lease_id: &str,
) -> Result<(), ApiError> {
    validate_role(role)?;
    validate_field("token", token, MAX_TOKEN_LEN)?;
    validate_field("peer_id", peer_id, MAX_STRING_FIELD_LEN)?;
    validate_field("lease_id", lease_id, MAX_STRING_FIELD_LEN)
}

fn validate_partner(peer_id: &str, lease_id: &str) -> Result<(), ApiError> {
    validate_field("expected_partner_peer_id", peer_id, MAX_STRING_FIELD_LEN)?;
    validate_field("expected_partner_lease_id", lease_id, MAX_STRING_FIELD_LEN)
}

fn validate_public_key(key: &str) -> Result<(), ApiError> {
    match BASE64.decode(key) {
        Ok(bytes) if bytes.len() == 32 => Ok(()),
        _ => Err(request_error(
            StatusCode::BAD_REQUEST,
            "public_key must be 32 bytes base64-encoded",
        )),
    }
}

fn peer_status(peer: &Peer) -> PeerStatus {
    PeerStatus {
        peer_id: peer.peer_id.clone(),
        lease_id: peer.lease_id.clone(),
        hostname: peer.hostname.clone(),
        has_key: peer.public_key.is_some(),
        candidates: peer.candidates.clone(),
    }
}

fn request_status(request: &SignalRequest) -> SignalRequestStatus {
    SignalRequestStatus {
        generation: request.generation,
        owner_peer_id: request.owner_peer_id.clone(),
        owner_lease_id: request.owner_lease_id.clone(),
        expected_partner_peer_id: request.expected_partner_peer_id.clone(),
        partner_peer_id: request.partner_peer_id.clone(),
        partner_lease_id: request.partner_lease_id.clone(),
        context: request.context.clone(),
    }
}

fn clear_visible_requests(session: &mut Session) {
    session.punch_requests.clear();
    session.relay_requests.clear();
}

fn reset_pair_state(session: &mut Session) {
    clear_visible_requests(session);
    session.punch_generation_high_water.clear();
    session.relay_generation_high_water.clear();
}

fn prune_session(session: &mut Session) {
    let before = session.peers.len();
    session.peers.retain(|_, peer| {
        let alive = peer.last_seen.elapsed() < SESSION_TTL;
        if !alive {
            info!(role = %peer.role, peer_id = %peer.peer_id, "peer expired");
        }
        alive
    });
    if session.peers.len() != before {
        reset_pair_state(session);
    }
    session
        .punch_requests
        .retain(|_, request| request.created_at.elapsed() < SIGNAL_REQUEST_TTL);
    session
        .relay_requests
        .retain(|_, request| request.created_at.elapsed() < SIGNAL_REQUEST_TTL);
}

fn prune_store(store: &mut Store) {
    for session in store.sessions.values_mut() {
        prune_session(session);
    }
    store
        .sessions
        .retain(|_, session| !session.peers.is_empty());
    let sessions = &store.sessions;
    store.tickets.retain(|_, ticket| {
        ticket.expires_at > Instant::now()
            && sessions
                .values()
                .any(|session| session.id == ticket.session_id)
    });
}

fn validate_owner<'a>(
    session: &'a Session,
    role: &str,
    peer_id: &str,
    lease_id: &str,
) -> Result<&'a Peer, ApiError> {
    let peer = session
        .peers
        .get(role)
        .ok_or_else(|| request_error(StatusCode::NOT_FOUND, "peer not registered in session"))?;
    if peer.peer_id != peer_id {
        return Err(request_error(
            StatusCode::CONFLICT,
            "role is registered to a different live peer",
        ));
    }
    if peer.lease_id != lease_id {
        return Err(request_error(
            StatusCode::CONFLICT,
            "role is registered to a newer process lease",
        ));
    }
    Ok(peer)
}

fn validate_expected_partner<'a>(
    session: &'a Session,
    role: &str,
    expected_peer_id: &str,
    expected_lease_id: &str,
) -> Result<&'a Peer, ApiError> {
    let partner = session
        .peers
        .get(partner_role(role))
        .ok_or_else(|| request_error(StatusCode::CONFLICT, "expected partner is not registered"))?;
    if partner.peer_id != expected_peer_id {
        return Err(request_error(
            StatusCode::CONFLICT,
            "partner identity changed",
        ));
    }
    if partner.lease_id != expected_lease_id {
        return Err(request_error(
            StatusCode::CONFLICT,
            "partner process lease changed",
        ));
    }
    Ok(partner)
}

fn session_mut<'a>(store: &'a mut Store, token: &str) -> Result<&'a mut Session, ApiError> {
    store
        .sessions
        .get_mut(token)
        .ok_or_else(|| request_error(StatusCode::NOT_FOUND, "session not found"))
}

fn make_signal_request(
    owner: &Peer,
    partner: &Peer,
    expected_partner_peer_id: String,
    generation: u64,
    pair_id: Option<String>,
) -> SignalRequest {
    SignalRequest {
        generation,
        owner_peer_id: owner.peer_id.clone(),
        owner_lease_id: owner.lease_id.clone(),
        expected_partner_peer_id,
        partner_peer_id: partner.peer_id.clone(),
        partner_lease_id: partner.lease_id.clone(),
        pair_id,
        context: random_id(),
        created_at: Instant::now(),
    }
}

fn punch_response(session: &Session, request: &SignalRequest) -> PunchResponse {
    PunchResponse {
        status: "ok",
        session_id: session.id.clone(),
        mode: "punch",
        generation: request.generation,
        owner_peer_id: request.owner_peer_id.clone(),
        owner_lease_id: request.owner_lease_id.clone(),
        partner_peer_id: request.partner_peer_id.clone(),
        partner_lease_id: request.partner_lease_id.clone(),
        context: request.context.clone(),
    }
}

fn request_matches_live_owners(session: &Session, role: &str, request: &SignalRequest) -> bool {
    let Some(owner) = session.peers.get(role) else {
        return false;
    };
    let Some(partner) = session.peers.get(partner_role(role)) else {
        return false;
    };
    owner.peer_id == request.owner_peer_id
        && owner.lease_id == request.owner_lease_id
        && partner.peer_id == request.partner_peer_id
        && partner.lease_id == request.partner_lease_id
        && request.expected_partner_peer_id == partner.peer_id
}

async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> Result<impl IntoResponse, ApiError> {
    validate_identity(&req.role, &req.token, &req.peer_id, &req.lease_id)?;
    if req
        .hostname
        .as_ref()
        .is_some_and(|hostname| hostname.len() > MAX_STRING_FIELD_LEN)
    {
        return Err(request_error(StatusCode::BAD_REQUEST, "hostname too long"));
    }
    if let Some(public_key) = req.public_key.as_deref() {
        validate_public_key(public_key)?;
    }

    let mut candidates: Vec<String> = req
        .candidates
        .into_iter()
        .filter(|candidate| candidate.len() <= MAX_STRING_FIELD_LEN)
        .collect();
    candidates.truncate(MAX_CANDIDATES);

    let mut store = state.store.write().await;
    prune_store(&mut store);
    if !store.sessions.contains_key(&req.token) && store.sessions.len() >= MAX_SESSIONS {
        return Err(request_error(
            StatusCode::TOO_MANY_REQUESTS,
            "too many active sessions",
        ));
    }
    let session = store.sessions.entry(req.token).or_insert_with(|| Session {
        id: random_id(),
        peers: HashMap::new(),
        punch_requests: HashMap::new(),
        relay_requests: HashMap::new(),
        punch_generation_high_water: HashMap::new(),
        relay_generation_high_water: HashMap::new(),
    });

    let existing = session.peers.get(&req.role).cloned();
    if let Some(peer) = existing.as_ref() {
        if peer.peer_id != req.peer_id || peer.lease_id != req.lease_id {
            return Err(request_error(
                StatusCode::CONFLICT,
                format!(
                    "{} role is already registered to a live process lease",
                    req.role
                ),
            ));
        }
    }

    let same_lease = existing
        .as_ref()
        .is_some_and(|peer| peer.lease_id == req.lease_id);
    if !same_lease {
        reset_pair_state(session);
    }
    let partner_joined = session.peers.contains_key(partner_role(&req.role));
    let public_key = req.public_key.or_else(|| {
        same_lease
            .then(|| existing.as_ref().and_then(|peer| peer.public_key.clone()))
            .flatten()
    });
    let candidates = if same_lease && candidates.is_empty() {
        existing
            .as_ref()
            .map(|peer| peer.candidates.clone())
            .unwrap_or_default()
    } else {
        candidates
    };
    let hostname = req.hostname.or_else(|| {
        same_lease
            .then(|| existing.as_ref()?.hostname.clone())
            .flatten()
    });
    let is_new_lease = !same_lease;
    session.peers.insert(
        req.role.clone(),
        Peer {
            role: req.role.clone(),
            peer_id: req.peer_id.clone(),
            lease_id: req.lease_id,
            hostname,
            public_key,
            candidates,
            last_seen: Instant::now(),
        },
    );
    if is_new_lease {
        info!(role = %req.role, peer_id = %req.peer_id, "peer lease registered");
    }

    Ok(Json(RegisterResponse {
        status: "ok",
        role: req.role,
        partner_joined,
    }))
}

async fn key_exchange(
    State(state): State<AppState>,
    Json(req): Json<KeyUploadRequest>,
) -> Result<impl IntoResponse, ApiError> {
    validate_identity(&req.role, &req.token, &req.peer_id, &req.lease_id)?;
    validate_partner(
        &req.expected_partner_peer_id,
        &req.expected_partner_lease_id,
    )?;
    validate_public_key(&req.public_key)?;
    let mut store = state.store.write().await;
    prune_store(&mut store);
    let session = session_mut(&mut store, &req.token)?;
    validate_owner(session, &req.role, &req.peer_id, &req.lease_id)?;
    let partner = validate_expected_partner(
        session,
        &req.role,
        &req.expected_partner_peer_id,
        &req.expected_partner_lease_id,
    )?
    .clone();
    let peer = session.peers.get_mut(&req.role).expect("owner validated");
    peer.public_key = Some(req.public_key);
    peer.last_seen = Instant::now();
    Ok(Json(KeyResponse {
        status: "ok",
        partner_key: partner.public_key,
        partner_peer_id: partner.peer_id,
        partner_lease_id: partner.lease_id,
    }))
}

async fn candidates(
    State(state): State<AppState>,
    Json(req): Json<CandidatesRequest>,
) -> Result<impl IntoResponse, ApiError> {
    validate_identity(&req.role, &req.token, &req.peer_id, &req.lease_id)?;
    validate_partner(
        &req.expected_partner_peer_id,
        &req.expected_partner_lease_id,
    )?;
    let mut candidates: Vec<String> = req
        .candidates
        .into_iter()
        .filter(|candidate| candidate.len() <= MAX_STRING_FIELD_LEN)
        .collect();
    candidates.truncate(MAX_CANDIDATES);
    let mut store = state.store.write().await;
    prune_store(&mut store);
    let session = session_mut(&mut store, &req.token)?;
    validate_owner(session, &req.role, &req.peer_id, &req.lease_id)?;
    let partner = validate_expected_partner(
        session,
        &req.role,
        &req.expected_partner_peer_id,
        &req.expected_partner_lease_id,
    )?
    .clone();
    let peer = session.peers.get_mut(&req.role).expect("owner validated");
    peer.candidates = candidates;
    peer.last_seen = Instant::now();
    Ok(Json(CandidatesResponse {
        status: "ok",
        partner_candidates: partner.candidates,
        partner_peer_id: partner.peer_id,
        partner_lease_id: partner.lease_id,
    }))
}

async fn request_punch(
    State(state): State<AppState>,
    Json(req): Json<SignalRequestBody>,
) -> Result<impl IntoResponse, ApiError> {
    validate_identity(&req.role, &req.token, &req.peer_id, &req.lease_id)?;
    validate_partner(
        &req.expected_partner_peer_id,
        &req.expected_partner_lease_id,
    )?;
    if req.generation == 0 {
        return Err(request_error(
            StatusCode::BAD_REQUEST,
            "generation must be non-zero",
        ));
    }
    let mut store = state.store.write().await;
    prune_store(&mut store);
    let session = session_mut(&mut store, &req.token)?;
    let owner = validate_owner(session, &req.role, &req.peer_id, &req.lease_id)?.clone();
    let partner = validate_expected_partner(
        session,
        &req.role,
        &req.expected_partner_peer_id,
        &req.expected_partner_lease_id,
    )?
    .clone();
    if let Some(previous) = session.punch_requests.get(&req.role) {
        if req.generation < previous.generation {
            return Err(request_error(
                StatusCode::CONFLICT,
                "request generation moved backwards within the lease",
            ));
        }
        if req.generation == previous.generation {
            if previous.owner_peer_id != owner.peer_id
                || previous.owner_lease_id != owner.lease_id
                || previous.partner_peer_id != partner.peer_id
                || previous.partner_lease_id != partner.lease_id
            {
                return Err(request_error(
                    StatusCode::CONFLICT,
                    "punch request ownership changed",
                ));
            }
            return Ok(Json(punch_response(session, previous)));
        }
    } else if session
        .punch_generation_high_water
        .get(&req.role)
        .is_some_and(|generation| req.generation <= *generation)
    {
        return Err(request_error(
            StatusCode::CONFLICT,
            "punch request generation was already consumed by this lease",
        ));
    }
    let role = req.role;
    let request = make_signal_request(
        &owner,
        &partner,
        req.expected_partner_peer_id,
        req.generation,
        None,
    );
    session
        .punch_generation_high_water
        .insert(role.clone(), req.generation);
    session.punch_requests.insert(role, request.clone());
    session
        .peers
        .get_mut(&owner.role)
        .expect("owner validated")
        .last_seen = Instant::now();
    Ok(Json(punch_response(session, &request)))
}

fn issue_ticket(store: &mut Store, claim: RelayTicket) -> String {
    store.tickets.retain(|_, ticket| {
        let same_request =
            ticket.session_id == claim.session_id && ticket.requester_role == claim.requester_role;
        !(same_request && (ticket.pair_id != claim.pair_id || ticket.role == claim.role))
    });
    loop {
        let ticket = random_id();
        if !store.tickets.contains_key(&ticket) {
            store.tickets.insert(ticket.clone(), claim);
            return ticket;
        }
    }
}

async fn request_relay(
    State(state): State<AppState>,
    Json(req): Json<RelayRequestBody>,
) -> Result<impl IntoResponse, ApiError> {
    validate_identity(&req.role, &req.token, &req.peer_id, &req.lease_id)?;
    validate_partner(
        &req.expected_partner_peer_id,
        &req.expected_partner_lease_id,
    )?;
    if req.generation == 0 {
        return Err(request_error(
            StatusCode::BAD_REQUEST,
            "generation must be non-zero",
        ));
    }
    let relay_port = state
        .advertised_relay_port()
        .ok_or_else(|| request_error(StatusCode::SERVICE_UNAVAILABLE, "relay disabled"))?;
    let mut store = state.store.write().await;
    prune_store(&mut store);

    let claim = {
        let session = session_mut(&mut store, &req.token)?;
        let owner = validate_owner(session, &req.role, &req.peer_id, &req.lease_id)?.clone();
        let partner = validate_expected_partner(
            session,
            &req.role,
            &req.expected_partner_peer_id,
            &req.expected_partner_lease_id,
        )?
        .clone();
        let (requester_role, request) = match req.mode {
            RelayMode::Request => {
                let request = if let Some(previous) = session.relay_requests.get(&req.role) {
                    if req.generation < previous.generation {
                        return Err(request_error(
                            StatusCode::CONFLICT,
                            "request generation moved backwards within the lease",
                        ));
                    }
                    if req.generation == previous.generation {
                        if previous.owner_peer_id != owner.peer_id
                            || previous.owner_lease_id != owner.lease_id
                            || previous.partner_peer_id != partner.peer_id
                            || previous.partner_lease_id != partner.lease_id
                        {
                            return Err(request_error(
                                StatusCode::CONFLICT,
                                "relay request ownership changed",
                            ));
                        }
                        previous.clone()
                    } else {
                        make_signal_request(
                            &owner,
                            &partner,
                            req.expected_partner_peer_id,
                            req.generation,
                            Some(random_id()),
                        )
                    }
                } else {
                    if session
                        .relay_generation_high_water
                        .get(&req.role)
                        .is_some_and(|generation| req.generation <= *generation)
                    {
                        return Err(request_error(
                            StatusCode::CONFLICT,
                            "relay request generation was already consumed by this lease",
                        ));
                    }
                    make_signal_request(
                        &owner,
                        &partner,
                        req.expected_partner_peer_id,
                        req.generation,
                        Some(random_id()),
                    )
                };
                session
                    .relay_requests
                    .insert(req.role.clone(), request.clone());
                session
                    .relay_generation_high_water
                    .insert(req.role.clone(), req.generation);
                (req.role.clone(), request)
            }
            RelayMode::Join => {
                let requester_role = partner_role(&req.role).to_string();
                let request = session
                    .relay_requests
                    .get(&requester_role)
                    .ok_or_else(|| {
                        request_error(StatusCode::CONFLICT, "no live partner relay request")
                    })?
                    .clone();
                if request.generation != req.generation
                    || request.owner_peer_id != partner.peer_id
                    || request.owner_lease_id != partner.lease_id
                    || request.partner_peer_id != owner.peer_id
                    || request.partner_lease_id != owner.lease_id
                    || !request_matches_live_owners(session, &requester_role, &request)
                {
                    return Err(request_error(
                        StatusCode::CONFLICT,
                        "relay request generation or ownership changed",
                    ));
                }
                (requester_role, request)
            }
        };
        session
            .peers
            .get_mut(&req.role)
            .expect("owner validated")
            .last_seen = Instant::now();
        (
            RelayTicket {
                session_id: session.id.clone(),
                pair_id: request.pair_id.clone().expect("relay request has pair id"),
                role: req.role,
                peer_id: owner.peer_id,
                lease_id: owner.lease_id,
                partner_peer_id: partner.peer_id,
                partner_lease_id: partner.lease_id,
                requester_role,
                request_generation: request.generation,
                expires_at: Instant::now() + RELAY_TICKET_TTL,
            },
            request,
        )
    };
    let (claim, request) = claim;
    let session_id = claim.session_id.clone();
    let generation = claim.request_generation;
    let ticket = issue_ticket(&mut store, claim);
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(RelayResponse {
            status: "ok",
            ticket,
            expires_in_seconds: RELAY_TICKET_TTL.as_secs(),
            relay_port,
            session_id,
            mode: "relay",
            generation,
            owner_peer_id: request.owner_peer_id,
            owner_lease_id: request.owner_lease_id,
            partner_peer_id: request.partner_peer_id,
            partner_lease_id: request.partner_lease_id,
            context: request.context,
        }),
    ))
}

async fn session_status(
    State(state): State<AppState>,
    Json(req): Json<SessionStatusRequest>,
) -> Result<impl IntoResponse, ApiError> {
    validate_field("token", &req.token, MAX_TOKEN_LEN)?;
    let identity = match (
        &req.role,
        &req.peer_id,
        &req.lease_id,
        &req.expected_partner_peer_id,
        &req.expected_partner_lease_id,
    ) {
        (None, None, None, None, None) => None,
        (
            Some(role),
            Some(peer_id),
            Some(lease_id),
            Some(partner_peer_id),
            Some(partner_lease_id),
        ) => {
            validate_identity(role, &req.token, peer_id, lease_id)?;
            validate_partner(partner_peer_id, partner_lease_id)?;
            Some((
                role.as_str(),
                peer_id.as_str(),
                lease_id.as_str(),
                partner_peer_id.as_str(),
                partner_lease_id.as_str(),
            ))
        }
        _ => {
            return Err(request_error(
                StatusCode::BAD_REQUEST,
                "owner and expected partner identities must be supplied together",
            ));
        }
    };
    let mut store = state.store.write().await;
    prune_store(&mut store);
    let session = session_mut(&mut store, &req.token)?;
    if let Some((role, peer_id, lease_id, partner_peer_id, partner_lease_id)) = identity {
        validate_owner(session, role, peer_id, lease_id)?;
        validate_expected_partner(session, role, partner_peer_id, partner_lease_id)?;
        session
            .peers
            .get_mut(role)
            .expect("owner validated")
            .last_seen = Instant::now();
    }
    Ok(Json(SessionStatus {
        session_id: session.id.clone(),
        host: session.peers.get("host").map(peer_status),
        client: session.peers.get("client").map(peer_status),
        host_punch_request: session.punch_requests.get("host").map(request_status),
        client_punch_request: session.punch_requests.get("client").map(request_status),
        host_relay_request: session.relay_requests.get("host").map(request_status),
        client_relay_request: session.relay_requests.get("client").map(request_status),
        relay_port: state.advertised_relay_port(),
    }))
}

async fn unregister(
    State(state): State<AppState>,
    Json(req): Json<OwnedRequest>,
) -> Result<impl IntoResponse, ApiError> {
    validate_identity(&req.role, &req.token, &req.peer_id, &req.lease_id)?;
    let mut store = state.store.write().await;
    prune_store(&mut store);
    if let Some(session) = store.sessions.get_mut(&req.token) {
        if session.peers.contains_key(&req.role) {
            validate_owner(session, &req.role, &req.peer_id, &req.lease_id)?;
            session.peers.remove(&req.role);
            reset_pair_state(session);
            info!(role = %req.role, peer_id = %req.peer_id, "peer unregistered");
        }
        if session.peers.is_empty() {
            store.sessions.remove(&req.token);
        }
    }
    prune_store(&mut store);
    Ok(Json(serde_json::json!({"status": "ok"})))
}

async fn health(State(state): State<AppState>) -> Json<HealthStatus> {
    let relay_port = state.advertised_relay_port();
    Json(HealthStatus {
        status: "ok",
        relay_enabled: relay_port.is_some(),
        relay_port,
    })
}

async fn cleanup_loop(store: SharedStore) {
    loop {
        tokio::time::sleep(CLEANUP_INTERVAL).await;
        let mut store = store.write().await;
        let before = store.sessions.len();
        prune_store(&mut store);
        let removed = before.saturating_sub(store.sessions.len());
        if removed > 0 {
            info!(removed, remaining = store.sessions.len(), "cleanup sweep");
        }
    }
}

struct RelayWaiting {
    stream: tokio::net::TcpStream,
    since: Instant,
    _permit: OwnedSemaphorePermit,
}

type RelayWaitMap = Arc<tokio::sync::Mutex<HashMap<String, HashMap<String, RelayWaiting>>>>;

struct RelayReadyGuard(Arc<AtomicBool>);

impl Drop for RelayReadyGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

async fn read_relay_hello(stream: &mut tokio::net::TcpStream) -> Option<(String, String)> {
    use tokio::io::AsyncReadExt;
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        match tokio::time::timeout_at(deadline, stream.read(&mut byte)).await {
            Ok(Ok(1)) if byte[0] == b'\n' => break,
            Ok(Ok(1)) => {
                line.push(byte[0]);
                if line.len() > RELAY_HELLO_MAX {
                    return None;
                }
            }
            _ => return None,
        }
    }
    let line = String::from_utf8(line).ok()?;
    let mut parts = line.split_whitespace();
    if parts.next()? != "STRELAY2" {
        return None;
    }
    let role = parts.next()?.to_string();
    if !matches!(role.as_str(), "host" | "client") {
        return None;
    }
    let ticket = parts.next()?.to_string();
    if ticket.is_empty()
        || ticket.len() > MAX_RELAY_TICKET_LEN
        || parts.next().is_some()
        || !ticket
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return None;
    }
    Some((role, ticket))
}

fn consume_relay_ticket(store: &mut Store, role: &str, ticket: &str) -> Option<String> {
    let claim = store.tickets.remove(ticket)?;
    if claim.role != role || claim.expires_at <= Instant::now() {
        return None;
    }
    // Authenticate the opaque ticket in O(1) before paying for a global sweep.
    prune_store(store);
    let session = store
        .sessions
        .values()
        .find(|session| session.id == claim.session_id)?;
    let peer = session.peers.get(role)?;
    let partner = session.peers.get(partner_role(role))?;
    if peer.peer_id != claim.peer_id
        || peer.lease_id != claim.lease_id
        || partner.peer_id != claim.partner_peer_id
        || partner.lease_id != claim.partner_lease_id
    {
        return None;
    }
    let request = session.relay_requests.get(&claim.requester_role)?;
    if request.generation != claim.request_generation
        || request.pair_id.as_deref() != Some(claim.pair_id.as_str())
        || !request_matches_live_owners(session, &claim.requester_role, request)
    {
        return None;
    }
    Some(claim.pair_id)
}

async fn relay_pipe_dir(
    mut from: tokio::net::tcp::OwnedReadHalf,
    mut to: tokio::net::tcp::OwnedWriteHalf,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let size = match tokio::time::timeout(RELAY_IDLE_TIMEOUT, from.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(size)) => size,
        };
        if !matches!(
            tokio::time::timeout(RELAY_IDLE_TIMEOUT, to.write_all(&buf[..size])).await,
            Ok(Ok(()))
        ) {
            break;
        }
    }
    let _ = to.shutdown().await;
}

async fn run_relay_on(listener: tokio::net::TcpListener, state: AppState) {
    let _ready_guard = RelayReadyGuard(Arc::clone(&state.relay_ready));
    let waiting: RelayWaitMap = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    {
        let waiting = Arc::clone(&waiting);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(5)).await;
                let mut waiting = waiting.lock().await;
                for peers in waiting.values_mut() {
                    peers.retain(|_, peer| peer.since.elapsed() < RELAY_PAIR_TIMEOUT);
                }
                waiting.retain(|_, peers| !peers.is_empty());
            }
        });
    }

    loop {
        let (mut stream, peer_addr) = match listener.accept().await {
            Ok(connection) => connection,
            Err(error) => {
                tracing::warn!(%error, "relay accept error");
                continue;
            }
        };
        let Ok(preauth_permit) = Arc::clone(&state.relay_preauth_slots).try_acquire_owned() else {
            tracing::warn!(%peer_addr, "relay pre-auth capacity reached");
            continue;
        };
        let state = state.clone();
        let waiting = Arc::clone(&waiting);
        tokio::spawn(async move {
            let preauth_permit = preauth_permit;
            let _ = stream.set_nodelay(true);
            let Some((role, ticket)) = read_relay_hello(&mut stream).await else {
                return;
            };
            let pair_id = {
                let mut store = state.store.write().await;
                consume_relay_ticket(&mut store, &role, &ticket)
            };
            let Some(pair_id) = pair_id else {
                return;
            };
            drop(preauth_permit);

            let partner = {
                let mut waiting = waiting.lock().await;
                let peers = waiting.entry(pair_id.clone()).or_default();
                if let Some(partner) = peers.remove(partner_role(&role)) {
                    if peers.is_empty() {
                        waiting.remove(&pair_id);
                    }
                    Some(partner)
                } else {
                    if peers.contains_key(&role) {
                        return;
                    }
                    let Ok(permit) = Arc::clone(&state.relay_waiter_slots).try_acquire_owned()
                    else {
                        return;
                    };
                    peers.insert(
                        role.clone(),
                        RelayWaiting {
                            stream,
                            since: Instant::now(),
                            _permit: permit,
                        },
                    );
                    info!(%role, %peer_addr, "relay peer waiting for partner");
                    return;
                }
            };
            let Some(partner) = partner else {
                return;
            };
            let Ok(_relay_permit) = Arc::clone(&state.relay_slots).try_acquire_owned() else {
                tracing::warn!("relay at capacity; dropping session pair");
                return;
            };

            use tokio::io::AsyncWriteExt;
            let mut first = stream;
            let RelayWaiting {
                stream: mut second,
                _permit: waiting_permit,
                ..
            } = partner;
            drop(waiting_permit);
            if first.write_all(b"OK\n").await.is_err() || second.write_all(b"OK\n").await.is_err() {
                return;
            }
            info!(%role, %peer_addr, "relay session paired");
            let (first_read, first_write) = first.into_split();
            let (second_read, second_write) = second.into_split();
            let forward = tokio::spawn(relay_pipe_dir(first_read, second_write));
            let reverse = tokio::spawn(relay_pipe_dir(second_read, first_write));
            let _ = forward.await;
            let _ = reverse.await;
            info!("relay session ended");
        });
    }
}

async fn bind_relay_listener(bind: &str) -> Option<tokio::net::TcpListener> {
    if bind.eq_ignore_ascii_case("off") {
        return None;
    }
    match tokio::net::TcpListener::bind(bind).await {
        Ok(listener) => {
            info!(%bind, "relay listener started");
            Some(listener)
        }
        Err(error) => {
            tracing::error!(%bind, %error, "relay disabled: listener bind failed");
            None
        }
    }
}

fn configured_public_port(listener: &tokio::net::TcpListener) -> Result<u16, String> {
    match std::env::var("RELAY_PUBLIC_PORT") {
        Ok(value) => value
            .parse::<u16>()
            .ok()
            .filter(|port| *port != 0)
            .ok_or_else(|| "RELAY_PUBLIC_PORT must be an integer in 1..=65535".to_string()),
        Err(_) => listener
            .local_addr()
            .map(|address| address.port())
            .map_err(|error| format!("inspect relay listener: {error}"))
            .and_then(|port| {
                (port != 0)
                    .then_some(port)
                    .ok_or_else(|| "relay listener did not receive a public port".to_string())
            }),
    }
}

fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/api/register", post(register))
        .route("/api/unregister", post(unregister))
        .route("/api/key", post(key_exchange))
        .route("/api/candidates", post(candidates))
        .route("/api/punch", post(request_punch))
        .route("/api/relay", post(request_relay))
        .route("/api/session", post(session_status))
        .layer(CorsLayer::permissive())
        .with_state(state)
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "st_api_server=info,tower_http=info".into()),
        )
        .init();

    let relay_bind = std::env::var("RELAY_BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:3001".into());
    let mut relay_listener = bind_relay_listener(&relay_bind).await;
    let relay_port = match relay_listener.as_ref().map(configured_public_port) {
        Some(Ok(port)) => Some(port),
        Some(Err(error)) => {
            tracing::error!(%error, "relay disabled: invalid public port");
            relay_listener = None;
            None
        }
        None => None,
    };
    let relay_ready = Arc::new(AtomicBool::new(relay_listener.is_some()));
    let state = AppState {
        store: Arc::new(RwLock::new(Store::default())),
        relay_port,
        relay_ready,
        relay_slots: Arc::new(Semaphore::new(MAX_ACTIVE_RELAYS)),
        relay_waiter_slots: Arc::new(Semaphore::new(MAX_WAITING_RELAYS)),
        relay_preauth_slots: Arc::new(Semaphore::new(MAX_PREAUTH_RELAYS)),
    };
    tokio::spawn(cleanup_loop(Arc::clone(&state.store)));
    if let Some(listener) = relay_listener {
        tokio::spawn(run_relay_on(listener, state.clone()));
    }

    let bind = std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:3000".into());
    let address: SocketAddr = bind.parse().expect("invalid BIND_ADDR");
    let listener = tokio::net::TcpListener::bind(address).await.unwrap();
    info!(address = %listener.local_addr().unwrap_or(address), "starting API server");
    axum::serve(listener, build_router(state)).await.unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        http::Request,
    };
    use serde_json::{json, Value};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tower::ServiceExt;

    fn test_state(relay_port: Option<u16>, relay_capacity: usize) -> AppState {
        AppState {
            store: Arc::new(RwLock::new(Store::default())),
            relay_port,
            relay_ready: Arc::new(AtomicBool::new(relay_port.is_some())),
            relay_slots: Arc::new(Semaphore::new(relay_capacity)),
            relay_waiter_slots: Arc::new(Semaphore::new(MAX_WAITING_RELAYS)),
            relay_preauth_slots: Arc::new(Semaphore::new(MAX_PREAUTH_RELAYS)),
        }
    }

    async fn post(state: &AppState, path: &str, value: Value) -> (StatusCode, Value) {
        let request = Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .body(Body::from(value.to_string()))
            .unwrap();
        let response = build_router(state.clone()).oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, value)
    }

    async fn register_peer(
        state: &AppState,
        token: &str,
        role: &str,
        peer_id: &str,
        lease_id: &str,
    ) -> StatusCode {
        post(
            state,
            "/api/register",
            json!({
                "token": token,
                "role": role,
                "peer_id": peer_id,
                "lease_id": lease_id,
                "candidates": ["127.0.0.1:5000"]
            }),
        )
        .await
        .0
    }

    struct TicketSpec<'a> {
        token: &'a str,
        role: &'a str,
        peer_id: &'a str,
        lease_id: &'a str,
        partner_peer_id: &'a str,
        partner_lease_id: &'a str,
        generation: u64,
        mode: &'a str,
    }

    async fn ticket(state: &AppState, spec: TicketSpec<'_>) -> (StatusCode, Value) {
        post(
            state,
            "/api/relay",
            json!({
                "token": spec.token,
                "role": spec.role,
                "peer_id": spec.peer_id,
                "lease_id": spec.lease_id,
                "expected_partner_peer_id": spec.partner_peer_id,
                "expected_partner_lease_id": spec.partner_lease_id,
                "generation": spec.generation,
                "mode": spec.mode
            }),
        )
        .await
    }

    async fn relay_fixture(capacity: usize) -> (AppState, SocketAddr) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let state = test_state(Some(address.port()), capacity);
        tokio::spawn(run_relay_on(listener, state.clone()));
        (state, address)
    }

    async fn send_hello(stream: &mut tokio::net::TcpStream, role: &str, ticket: &str) {
        stream
            .write_all(format!("STRELAY2 {role} {ticket}\n").as_bytes())
            .await
            .unwrap();
    }

    async fn assert_closed(mut stream: tokio::net::TcpStream) {
        let mut byte = [0u8; 1];
        let size = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut byte))
            .await
            .expect("relay should answer or close")
            .unwrap();
        assert_eq!(size, 0);
    }

    async fn register_pair(state: &AppState, token: &str) {
        assert_eq!(
            register_peer(state, token, "host", "host-peer", "host-lease").await,
            StatusCode::OK
        );
        assert_eq!(
            register_peer(state, token, "client", "client-peer", "client-lease").await,
            StatusCode::OK
        );
    }

    async fn relay_ticket_pair(state: &AppState, token: &str, generation: u64) -> (String, String) {
        let (status, client) = ticket(
            state,
            TicketSpec {
                token,
                role: "client",
                peer_id: "client-peer",
                lease_id: "client-lease",
                partner_peer_id: "host-peer",
                partner_lease_id: "host-lease",
                generation,
                mode: "request",
            },
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{client}");
        let (status, host) = ticket(
            state,
            TicketSpec {
                token,
                role: "host",
                peer_id: "host-peer",
                lease_id: "host-lease",
                partner_peer_id: "client-peer",
                partner_lease_id: "client-lease",
                generation,
                mode: "join",
            },
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{host}");
        assert_eq!(client["context"], host["context"]);
        assert_eq!(client["session_id"], host["session_id"]);
        assert_eq!(client["owner_lease_id"], "client-lease");
        assert_eq!(host["partner_lease_id"], "host-lease");
        (
            host["ticket"].as_str().unwrap().to_string(),
            client["ticket"].as_str().unwrap().to_string(),
        )
    }

    #[tokio::test]
    async fn idle_discovery_is_read_only_and_does_not_claim_client_slot() {
        let state = test_state(None, 1);
        register_peer(&state, "token", "host", "host", "host-lease").await;
        let (status, session) = post(&state, "/api/session", json!({"token": "token"})).await;
        assert_eq!(status, StatusCode::OK);
        assert!(session["client"].is_null());
        assert!(!state.store.read().await.sessions["token"]
            .peers
            .contains_key("client"));
        assert_eq!(
            register_peer(&state, "token", "client", "active", "active-lease").await,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn leases_enforce_single_live_identity_and_reset_process_state() {
        let state = test_state(None, 1);
        register_pair(&state, "token").await;
        let key = BASE64.encode([3u8; 32]);
        let (status, _) = post(
            &state,
            "/api/key",
            json!({
                "token": "token", "role": "client", "peer_id": "client-peer",
                "lease_id": "client-lease", "expected_partner_peer_id": "host-peer",
                "expected_partner_lease_id": "host-lease",
                "public_key": key
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = post(
            &state,
            "/api/punch",
            json!({
                "token": "token", "role": "client", "peer_id": "client-peer",
                "lease_id": "client-lease", "expected_partner_peer_id": "host-peer",
                "expected_partner_lease_id": "host-lease",
                "generation": 7
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            register_peer(&state, "token", "client", "different-peer", "other-lease").await,
            StatusCode::CONFLICT
        );
        let (status, _) = post(
            &state,
            "/api/register",
            json!({
                "token": "token", "role": "client", "peer_id": "client-peer",
                "lease_id": "new-client-lease", "candidates": []
            }),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        {
            let mut store = state.store.write().await;
            store
                .sessions
                .get_mut("token")
                .unwrap()
                .peers
                .get_mut("client")
                .unwrap()
                .last_seen = Instant::now() - SESSION_TTL - Duration::from_secs(1);
        }
        assert_eq!(
            post(
                &state,
                "/api/register",
                json!({
                    "token": "token", "role": "client", "peer_id": "client-peer",
                    "lease_id": "new-client-lease", "candidates": []
                }),
            )
            .await
            .0,
            StatusCode::OK
        );
        {
            let store = state.store.read().await;
            let session = &store.sessions["token"];
            assert!(session.peers["client"].public_key.is_none());
            assert!(session.peers["client"].candidates.is_empty());
            assert!(session.punch_requests.is_empty());
        }

        let (status, _) = post(
            &state,
            "/api/unregister",
            json!({
                "token": "token", "role": "client", "peer_id": "client-peer",
                "lease_id": "client-lease"
            }),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(
            register_peer(&state, "token", "client", "client-peer", "client-lease").await,
            StatusCode::CONFLICT
        );
        let (status, _) = post(
            &state,
            "/api/key",
            json!({
                "token": "token", "role": "client", "peer_id": "client-peer",
                "lease_id": "client-lease", "expected_partner_peer_id": "host-peer",
                "expected_partner_lease_id": "host-lease",
                "public_key": BASE64.encode([9u8; 32])
            }),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(
            state.store.read().await.sessions["token"].peers["client"].lease_id,
            "new-client-lease"
        );
        assert!(state.store.read().await.sessions["token"].peers["client"]
            .public_key
            .is_none());
    }

    #[tokio::test]
    async fn request_generations_are_monotonic_and_absence_is_explicit() {
        let state = test_state(Some(3001), 1);
        register_pair(&state, "token").await;
        let punch = |generation| {
            json!({
                "token": "token", "role": "client", "peer_id": "client-peer",
                "lease_id": "client-lease", "expected_partner_peer_id": "host-peer",
                "expected_partner_lease_id": "host-lease", "generation": generation
            })
        };
        let (status, first) = post(&state, "/api/punch", punch(9)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            post(&state, "/api/punch", punch(8)).await.0,
            StatusCode::CONFLICT
        );
        {
            let mut store = state.store.write().await;
            store
                .sessions
                .get_mut("token")
                .unwrap()
                .punch_requests
                .get_mut("client")
                .unwrap()
                .created_at = Instant::now() - SIGNAL_REQUEST_TTL - Duration::from_secs(1);
        }
        let (_, session) = post(&state, "/api/session", json!({"token": "token"})).await;
        assert!(session["client_punch_request"].is_null());
        assert_eq!(
            post(&state, "/api/punch", punch(9)).await.0,
            StatusCode::CONFLICT
        );
        let (status, next) = post(&state, "/api/punch", punch(10)).await;
        assert_eq!(status, StatusCode::OK);
        assert_ne!(first["context"], next["context"]);

        let (status, _) = ticket(
            &state,
            TicketSpec {
                token: "token",
                role: "client",
                peer_id: "client-peer",
                lease_id: "client-lease",
                partner_peer_id: "host-peer",
                partner_lease_id: "host-lease",
                generation: 8,
                mode: "request",
            },
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "punch and relay high-water marks mixed"
        );
        {
            let mut store = state.store.write().await;
            store
                .sessions
                .get_mut("token")
                .unwrap()
                .relay_requests
                .get_mut("client")
                .unwrap()
                .created_at = Instant::now() - SIGNAL_REQUEST_TTL - Duration::from_secs(1);
        }
        let _ = post(&state, "/api/session", json!({"token": "token"})).await;
        let (status, _) = ticket(
            &state,
            TicketSpec {
                token: "token",
                role: "client",
                peer_id: "client-peer",
                lease_id: "client-lease",
                partner_peer_id: "host-peer",
                partner_lease_id: "host-lease",
                generation: 8,
                mode: "request",
            },
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(session["host_punch_request"].is_null());
        assert!(session["client_relay_request"].is_null());
    }

    #[tokio::test]
    async fn partner_identity_is_checked_atomically_for_results_and_requests() {
        let state = test_state(Some(3001), 1);
        register_pair(&state, "token").await;
        {
            let mut store = state.store.write().await;
            store
                .sessions
                .get_mut("token")
                .unwrap()
                .peers
                .get_mut("host")
                .unwrap()
                .last_seen = Instant::now() - SESSION_TTL - Duration::from_secs(1);
        }
        assert_eq!(
            register_peer(&state, "token", "host", "host-peer", "new-lease").await,
            StatusCode::OK
        );
        let (key_status, _) = post(
            &state,
            "/api/key",
            json!({
                "token": "token", "role": "client", "peer_id": "client-peer",
                "lease_id": "client-lease", "expected_partner_peer_id": "host-peer",
                "expected_partner_lease_id": "host-lease",
                "public_key": BASE64.encode([1u8; 32])
            }),
        )
        .await;
        let (candidate_status, _) = post(
            &state,
            "/api/candidates",
            json!({
                "token": "token", "role": "client", "peer_id": "client-peer",
                "lease_id": "client-lease", "expected_partner_peer_id": "host-peer",
                "expected_partner_lease_id": "host-lease",
                "candidates": []
            }),
        )
        .await;
        let (relay_status, _) = ticket(
            &state,
            TicketSpec {
                token: "token",
                role: "client",
                peer_id: "client-peer",
                lease_id: "client-lease",
                partner_peer_id: "host-peer",
                partner_lease_id: "host-lease",
                generation: 1,
                mode: "request",
            },
        )
        .await;
        let (session_status, _) = post(
            &state,
            "/api/session",
            json!({
                "token": "token", "role": "client", "peer_id": "client-peer",
                "lease_id": "client-lease", "expected_partner_peer_id": "host-peer",
                "expected_partner_lease_id": "host-lease"
            }),
        )
        .await;
        assert_eq!(key_status, StatusCode::CONFLICT);
        assert_eq!(candidate_status, StatusCode::CONFLICT);
        assert_eq!(relay_status, StatusCode::CONFLICT);
        assert_eq!(session_status, StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn lease_replacement_between_key_and_candidates_cannot_mix_partner_state() {
        let state = test_state(None, 1);
        register_pair(&state, "token").await;
        let (status, _) = post(
            &state,
            "/api/key",
            json!({
                "token": "token", "role": "host", "peer_id": "host-peer",
                "lease_id": "host-lease", "expected_partner_peer_id": "client-peer",
                "expected_partner_lease_id": "client-lease",
                "public_key": BASE64.encode([4u8; 32])
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, key) = post(
            &state,
            "/api/key",
            json!({
                "token": "token", "role": "client", "peer_id": "client-peer",
                "lease_id": "client-lease", "expected_partner_peer_id": "host-peer",
                "expected_partner_lease_id": "host-lease",
                "public_key": BASE64.encode([5u8; 32])
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(key["partner_lease_id"], "host-lease");

        {
            let mut store = state.store.write().await;
            store
                .sessions
                .get_mut("token")
                .unwrap()
                .peers
                .get_mut("host")
                .unwrap()
                .last_seen = Instant::now() - SESSION_TTL - Duration::from_secs(1);
        }
        assert_eq!(
            register_peer(&state, "token", "host", "host-peer", "new-host-lease").await,
            StatusCode::OK
        );
        let (status, _) = post(
            &state,
            "/api/candidates",
            json!({
                "token": "token", "role": "client", "peer_id": "client-peer",
                "lease_id": "client-lease", "expected_partner_peer_id": "host-peer",
                "expected_partner_lease_id": "host-lease", "candidates": []
            }),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn request_context_changes_for_repeated_and_a_b_a_pairs() {
        let state = test_state(None, 1);
        assert_eq!(
            register_peer(&state, "token", "host", "host-peer", "host-lease").await,
            StatusCode::OK
        );

        async fn punch_for(
            state: &AppState,
            peer_id: &str,
            lease_id: &str,
            generation: u64,
        ) -> Value {
            let (status, response) = post(
                state,
                "/api/punch",
                json!({
                    "token": "token", "role": "client", "peer_id": peer_id,
                    "lease_id": lease_id, "expected_partner_peer_id": "host-peer",
                    "expected_partner_lease_id": "host-lease", "generation": generation
                }),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{response}");
            response
        }

        register_peer(&state, "token", "client", "peer-a", "lease-a1").await;
        let a1 = punch_for(&state, "peer-a", "lease-a1", 1).await;
        let a2 = punch_for(&state, "peer-a", "lease-a1", 2).await;
        assert_ne!(a1["context"], a2["context"]);
        let (_, session) = post(&state, "/api/session", json!({"token": "token"})).await;
        assert_eq!(a2["context"], session["client_punch_request"]["context"]);

        async fn expire_client(state: &AppState, old_lease: &str) {
            let mut store = state.store.write().await;
            let peer = store
                .sessions
                .get_mut("token")
                .unwrap()
                .peers
                .get_mut("client")
                .unwrap();
            assert_eq!(peer.lease_id, old_lease);
            peer.last_seen = Instant::now() - SESSION_TTL - Duration::from_secs(1);
        }
        expire_client(&state, "lease-a1").await;
        assert_eq!(
            register_peer(&state, "token", "client", "peer-b", "lease-b").await,
            StatusCode::OK
        );
        let b = punch_for(&state, "peer-b", "lease-b", 1).await;
        expire_client(&state, "lease-b").await;
        assert_eq!(
            register_peer(&state, "token", "client", "peer-a", "lease-a2").await,
            StatusCode::OK
        );
        let a3 = punch_for(&state, "peer-a", "lease-a2", 1).await;
        assert_ne!(a1["context"], b["context"]);
        assert_ne!(b["context"], a3["context"]);
        assert_ne!(a1["context"], a3["context"]);
        assert_ne!(a2["context"], a3["context"]);
    }

    #[tokio::test]
    async fn relay_ticket_is_opaque_and_valid_pair_pipes_then_replay_fails() {
        let (state, address) = relay_fixture(2).await;
        let token = "secret-token-that-must-not-cross-relay";
        register_pair(&state, token).await;
        let (host_ticket, client_ticket) = relay_ticket_pair(&state, token, 1).await;
        assert!(!host_ticket.contains(token));
        assert!(!client_ticket.contains(token));

        let mut host = tokio::net::TcpStream::connect(address).await.unwrap();
        let mut client = tokio::net::TcpStream::connect(address).await.unwrap();
        send_hello(&mut host, "host", &host_ticket).await;
        send_hello(&mut client, "client", &client_ticket).await;
        let mut ok = [0u8; 3];
        host.read_exact(&mut ok).await.unwrap();
        assert_eq!(&ok, b"OK\n");
        client.read_exact(&mut ok).await.unwrap();
        assert_eq!(&ok, b"OK\n");
        host.write_all(b"host-data").await.unwrap();
        let mut data = [0u8; 9];
        client.read_exact(&mut data).await.unwrap();
        assert_eq!(&data, b"host-data");

        let mut replay = tokio::net::TcpStream::connect(address).await.unwrap();
        send_hello(&mut replay, "host", &host_ticket).await;
        assert_closed(replay).await;
    }

    #[tokio::test]
    async fn relay_rejects_wrong_role_expired_wrong_peer_and_unrequested_ticket() {
        let (state, address) = relay_fixture(2).await;
        register_pair(&state, "token").await;

        let (wrong_role, _) = relay_ticket_pair(&state, "token", 1).await;
        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        send_hello(&mut stream, "client", &wrong_role).await;
        assert_closed(stream).await;

        let (expired, _) = relay_ticket_pair(&state, "token", 2).await;
        state
            .store
            .write()
            .await
            .tickets
            .get_mut(&expired)
            .unwrap()
            .expires_at = Instant::now() - Duration::from_secs(1);
        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        send_hello(&mut stream, "host", &expired).await;
        assert_closed(stream).await;

        let (wrong_peer, _) = relay_ticket_pair(&state, "token", 3).await;
        {
            let mut store = state.store.write().await;
            store
                .sessions
                .get_mut("token")
                .unwrap()
                .peers
                .get_mut("host")
                .unwrap()
                .last_seen = Instant::now() - SESSION_TTL - Duration::from_secs(1);
        }
        register_peer(&state, "token", "host", "new-host", "new-host-lease").await;
        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        send_hello(&mut stream, "host", &wrong_peer).await;
        assert_closed(stream).await;

        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        send_hello(&mut stream, "client", &random_id()).await;
        assert_closed(stream).await;
    }

    #[tokio::test]
    async fn relay_join_requires_a_real_partner_request() {
        let state = test_state(Some(3001), 1);
        register_pair(&state, "token").await;
        let (status, _) = ticket(
            &state,
            TicketSpec {
                token: "token",
                role: "host",
                peer_id: "host-peer",
                lease_id: "host-lease",
                partner_peer_id: "client-peer",
                partner_lease_id: "client-lease",
                generation: 1,
                mode: "join",
            },
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn api_restart_invalidates_sessions_requests_and_tickets() {
        let first = test_state(Some(3001), 1);
        register_pair(&first, "token").await;
        let (ticket, _) = relay_ticket_pair(&first, "token", 1).await;
        let second = test_state(Some(3001), 1);
        let mut store = second.store.write().await;
        assert!(consume_relay_ticket(&mut store, "host", &ticket).is_none());
        drop(store);
        let (status, _) = post(&second, "/api/session", json!({"token": "token"})).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn relay_semaphore_holds_capacity_for_the_pipe_lifetime() {
        let (state, address) = relay_fixture(1).await;
        register_pair(&state, "token").await;
        let (host_ticket, client_ticket) = relay_ticket_pair(&state, "token", 1).await;
        let mut first_host = tokio::net::TcpStream::connect(address).await.unwrap();
        let mut first_client = tokio::net::TcpStream::connect(address).await.unwrap();
        send_hello(&mut first_host, "host", &host_ticket).await;
        send_hello(&mut first_client, "client", &client_ticket).await;
        let mut ok = [0u8; 3];
        first_host.read_exact(&mut ok).await.unwrap();
        first_client.read_exact(&mut ok).await.unwrap();

        let (host_ticket, client_ticket) = relay_ticket_pair(&state, "token", 2).await;
        let mut second_host = tokio::net::TcpStream::connect(address).await.unwrap();
        let mut second_client = tokio::net::TcpStream::connect(address).await.unwrap();
        send_hello(&mut second_host, "host", &host_ticket).await;
        send_hello(&mut second_client, "client", &client_ticket).await;
        assert_closed(second_host).await;
        assert_closed(second_client).await;

        drop(first_host);
        drop(first_client);
    }

    #[tokio::test]
    async fn relay_preauth_capacity_is_acquired_before_hello_read() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let mut state = test_state(Some(address.port()), 1);
        state.relay_preauth_slots = Arc::new(Semaphore::new(1));
        tokio::spawn(run_relay_on(listener, state.clone()));

        let stalled = tokio::net::TcpStream::connect(address).await.unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        while state.relay_preauth_slots.available_permits() != 0 {
            assert!(tokio::time::Instant::now() < deadline);
            tokio::task::yield_now().await;
        }
        let rejected = tokio::net::TcpStream::connect(address).await.unwrap();
        assert_closed(rejected).await;
        drop(stalled);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        while state.relay_preauth_slots.available_permits() != 1 {
            assert!(tokio::time::Instant::now() < deadline);
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test]
    async fn failed_relay_bind_keeps_health_truthful() {
        let occupied = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listener = bind_relay_listener(&occupied.local_addr().unwrap().to_string()).await;
        assert!(listener.is_none());
        let state = test_state(None, 1);
        let health = health(State(state)).await.0;
        assert!(!health.relay_enabled);
        assert_eq!(health.relay_port, None);
    }

    #[test]
    fn relay_public_port_zero_is_rejected() {
        assert!("0".parse::<u16>().ok().filter(|port| *port != 0).is_none());
    }
}
