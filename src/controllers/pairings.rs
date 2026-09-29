use crate::{
    http::{self, AppState},
    pairing::ControllerRequest,
};
use axum::{Json, extract::Path, response::IntoResponse, routing::post};
use loco_rs::{controller::Routes, prelude::SharedStore};

pub(crate) fn routes() -> Routes {
    Routes::new()
        .prefix("/v1/pairings")
        .add("/", post(create))
        .add("/{id}/decision", post(decision))
        .add("/{id}/status", post(status))
        .add("/{id}/provision", post(provision))
}

async fn create(
    SharedStore(state): SharedStore<AppState>,
    Json(request): Json<ControllerRequest>,
) -> impl IntoResponse {
    http::create_pairing(state, request).await
}
async fn decision(
    SharedStore(state): SharedStore<AppState>,
    Path(id): Path<String>,
    Json(request): Json<ControllerRequest>,
) -> impl IntoResponse {
    http::pairing_decision(state, id, request).await
}
async fn status(
    SharedStore(state): SharedStore<AppState>,
    Path(id): Path<String>,
    Json(request): Json<ControllerRequest>,
) -> impl IntoResponse {
    http::pairing_status(state, id, request).await
}
async fn provision(
    SharedStore(state): SharedStore<AppState>,
    Path(id): Path<String>,
    Json(request): Json<ControllerRequest>,
) -> impl IntoResponse {
    http::pairing_provision(state, id, request).await
}
