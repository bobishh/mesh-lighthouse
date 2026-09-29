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
