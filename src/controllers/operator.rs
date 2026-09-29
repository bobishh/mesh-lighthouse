use crate::{
    http::{self, AppState},
    pairing::LoginRequest,
};
use axum::{
    Json,
    extract::Path,
    http::HeaderMap,
    response::IntoResponse,
    routing::{get, post},
};
use loco_rs::{
    controller::{ErrorDetail, Routes, format},
    prelude::SharedStore,
};
use serde_json::Value;

pub(crate) fn routes() -> Routes {
    Routes::new()
        .prefix("/admin/api")
        .add("/session", get(session).post(login))
        .add("/pairings", get(pairings))
        .add("/overview", get(overview))
        .add("/pairings/{id}/decision", post(decision))
}

async fn login(
    SharedStore(state): SharedStore<AppState>,
    Json(input): Json<LoginRequest>,
) -> impl IntoResponse {
    http::admin_login(state, input).await
}
async fn pairings(
    SharedStore(state): SharedStore<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    http::admin_list(state, headers).await
}
async fn session(
    SharedStore(state): SharedStore<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    http::admin_session(state, headers).await
}
async fn decision(
    SharedStore(state): SharedStore<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<Value>,
) -> impl IntoResponse {
    http::admin_decision(state, id, headers, input).await
}
async fn overview(
    SharedStore(state): SharedStore<AppState>,
    headers: HeaderMap,
) -> loco_rs::Result<axum::response::Response> {
    let Json(value) = http::admin_overview(state, headers)
        .await
        .map_err(|error| {
            let error = error.0;
            loco_rs::Error::CustomError(
                error.status(),
                ErrorDetail::new(error.code(), error.message()),
            )
        })?;
    format::json(value)
}
