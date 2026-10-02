use crate::http::{self, AppState, IncomingMessage};
use axum::{
    Json,
    http::HeaderMap,
    response::IntoResponse,
    routing::{get, post},
};
use loco_rs::{
    controller::{Routes, format},
    prelude::SharedStore,
};
use serde_json::json;

pub(crate) fn routes() -> Routes {
    Routes::new()
        .add("/health", get(health))
        .add("/.well-known/mesh-lighthouse", get(discovery))
        .add("/challenge", get(challenge))
        .add("/ingest", post(ingest))
        .add(
            "/telemetry",
            post(telemetry).layer(axum::extract::DefaultBodyLimit::max(65_536)),
        )
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct TelemetryBatch {
    session_id: String,
    events: Vec<match_lighthouse::telemetry::Event>,
}

async fn telemetry(
    SharedStore(state): SharedStore<AppState>,
    headers: HeaderMap,
    Json(mut input): Json<TelemetryBatch>,
) -> impl IntoResponse {
    use axum::http::StatusCode;
    if !headers
        .get("origin")
        .is_some_and(|origin| state.cors_settings().allows(origin))
    {
        return StatusCode::FORBIDDEN;
    }
    if input.events.is_empty()
        || input.events.len() > 100
        || input.session_id.is_empty()
        || input.session_id.len() > 80
        || !input
            .session_id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-')
    {
        return StatusCode::BAD_REQUEST;
    }
    for event in &mut input.events {
        event.source = "browser".into();
        event.session_id.clone_from(&input.session_id);
        if !event.valid() {
            return StatusCode::BAD_REQUEST;
        }
    }
    if !match_lighthouse::telemetry::enabled() {
        return StatusCode::SERVICE_UNAVAILABLE;
    }
    if !allow_telemetry_batch() {
        return StatusCode::TOO_MANY_REQUESTS;
    }
    for event in input.events {
        match_lighthouse::telemetry::emit(event);
    }
    StatusCode::ACCEPTED
}
async fn health() -> loco_rs::Result<axum::response::Response> {
    format::json(json!({"status":"ok"}))
}
async fn discovery(
    SharedStore(state): SharedStore<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    http::discover(state, headers).await
}
async fn challenge(SharedStore(state): SharedStore<AppState>) -> impl IntoResponse {
    http::challenge(state).await
}
async fn ingest(
    SharedStore(state): SharedStore<AppState>,
    Json(input): Json<IncomingMessage>,
) -> impl IntoResponse {
    http::ingest(state, input).await
}

// Bounded global intake protects diagnostics from consuming replication resources.
fn allow_telemetry_batch() -> bool {
    static LIMIT: std::sync::Mutex<(u64, u32)> = std::sync::Mutex::new((0, 0));
    let now = match_lighthouse::now_ms().unwrap_or(0).max(0) as u64 / 1000;
    let mut window = LIMIT.lock().unwrap_or_else(|error| error.into_inner());
    if window.0 != now {
        *window = (now, 0);
    }
    if window.1 >= 30 {
        return false;
    }
    window.1 += 1;
    true
}
