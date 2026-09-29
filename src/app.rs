//! Loco owns the HTTP lifecycle. Durable mesh and pairing services remain
//! independent of the web framework and are injected through AppContext.
use std::{net::SocketAddr, path::PathBuf};

use async_trait::async_trait;
use axum::{
    Router,
    extract::Request,
    http::{HeaderValue, header},
    middleware::{self, Next},
    response::Response,
};
use loco_rs::{
    app::{AppContext, Hooks},
    bgworker::Queue,
    boot::{BootResult, ServeParams, StartMode, create_app},
    config::Config,
    controller::{
        AppRoutes,
        middleware::{
            MiddlewareLayer,
            static_assets::{FolderConfig, StaticAssets},
        },
    },
    environment::Environment,
    task::Tasks,
};
use serde_json::json;

use crate::{controllers, http::AppState};

pub(crate) struct LighthouseApp;

#[async_trait]
impl Hooks for LighthouseApp {
    fn app_name() -> &'static str {
        "mesh-lighthouse"
    }
    fn app_version() -> String {
        env!("CARGO_PKG_VERSION").into()
    }

    async fn boot(
        mode: StartMode,
        environment: &Environment,
        config: Config,
    ) -> loco_rs::Result<BootResult> {
        create_app::<Self>(mode, environment, config).await
    }

    fn routes(_ctx: &AppContext) -> AppRoutes {
        AppRoutes::empty()
            .add_route(controllers::public::routes())
            .add_route(controllers::pairings::routes())
            .add_route(controllers::operator::routes())
    }

    async fn after_routes(router: Router, _ctx: &AppContext) -> loco_rs::Result<Router> {
        Ok(router.layer(middleware::from_fn(asset_cache)))
    }

    fn middlewares(ctx: &AppContext) -> Vec<Box<dyn MiddlewareLayer>> {
        let mut stack = loco_rs::controller::middleware::default_middleware_stack(ctx);
        stack.push(Box::new(StaticAssets {
            enable: true,
            must_exist: false,
            folder: FolderConfig {
                uri: "/assets".into(),
                path: frontend_directory().join("assets"),
            },
            fallback: frontend_directory().join("not-found"),
            cache_control: Some("no-cache".into()),
            ..Default::default()
        }));
        stack
    }

    async fn connect_workers(_ctx: &AppContext, _queue: &Queue) -> loco_rs::Result<()> {
        Ok(())
    }
    fn register_tasks(_tasks: &mut Tasks) {}
}

pub(crate) fn frontend_directory() -> PathBuf {
    std::env::var_os("LIGHTHOUSE_FRONTEND_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("frontend/dist"))
}

async fn boot(
    state: AppState,
    address: SocketAddr,
    origins: Vec<HeaderValue>,
) -> loco_rs::Result<BootResult> {
    let assets = frontend_directory();
    // Existing runtime configuration stays in Config.json and LIGHTHOUSE_*.
    // No DB, mailer, queue, request timeout, or replacement auth subsystem.
    let config: Config = serde_json::from_value(json!({
        "logger": {"enable": false, "level": "info", "format": "compact"},
        "workers": {"mode": "ForegroundBlocking"},
        "server": {
            "binding": address.ip().to_string(), "port": address.port(),
            "host": format!("http://{}", address.ip()),
            "middlewares": {
                "limit_payload": {"body_limit": "16384"},
                "cors": {"enable": true, "allow_origins": origins.iter().map(|v| v.to_str().unwrap_or_default()).collect::<Vec<_>>(),
                    "allow_methods": ["GET", "POST"], "allow_headers": ["content-type"]},
                "logger": {"enable": false},
                "etag": {"enable": false},
                "static": {"enable": true, "must_exist": false,
                    "folder": {"uri": "/admin", "path": assets},
                    "fallback": assets.join("index.html"), "cache_control": "no-cache"}
            }
        }
    }))?;
    let result =
        LighthouseApp::boot(StartMode::ServerOnly, &Environment::Production, config).await?;
    result.app_context.shared_store.insert(state);
    Ok(result)
}

pub(crate) async fn serve(
    state: AppState,
    address: SocketAddr,
    origins: Vec<HeaderValue>,
) -> loco_rs::Result<()> {
    let result = boot(state, address, origins).await?;
    println!("Lighthouse HTTP listening on {address}");
    loco_rs::boot::start::<LighthouseApp>(
        result,
        ServeParams {
            binding: address.ip().to_string(),
            port: i32::from(address.port()),
        },
        true,
    )
    .await
}

#[cfg(test)]
pub(crate) async fn router(state: AppState, origins: Vec<HeaderValue>) -> loco_rs::Result<Router> {
    boot(state, "127.0.0.1:0".parse().unwrap(), origins)
        .await?
        .router
        .ok_or(loco_rs::Error::InternalServerError)
}

async fn asset_cache(request: Request, next: Next) -> Response {
    let fingerprinted = request.uri().path().starts_with("/admin/assets/");
    let mut response = next.run(request).await;
    if fingerprinted
        && response.status().is_success()
        && !response
            .headers()
            .get(header::CONTENT_TYPE)
            .is_some_and(|v| v.as_bytes().starts_with(b"text/html"))
    {
        response.headers_mut().insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("public, max-age=31536000, immutable"),
        );
    }
    response
}
