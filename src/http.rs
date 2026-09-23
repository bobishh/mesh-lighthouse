use std::{
    fs,
    io::Write,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::{Method, StatusCode, header},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tower_http::cors::CorsLayer;

const MAX_PENDING: usize = 1_000;

#[derive(Clone)]
struct Inbox {
    directory: Arc<PathBuf>,
    write_lock: Arc<Mutex<()>>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IncomingMessage {
    message: String,
    #[serde(default)]
    contact: String,
    #[serde(default)]
    company: String,
    #[serde(default)]
    role: String,
}

#[derive(Serialize)]
struct Receipt<'a> {
    id: &'a str,
    status: &'a str,
    message: &'a str,
}

pub async fn serve(
    directory: PathBuf,
    address: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let inbox = directory.join("inbox");
    fs::create_dir_all(&inbox)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&inbox, fs::Permissions::from_mode(0o700))?;
    }
    let app = Router::new()
        .route(
            "/health",
            get(|| async { Json(serde_json::json!({"status":"ok"})) }),
        )
        .route("/ingest", post(ingest))
        .layer(DefaultBodyLimit::max(16 * 1024))
        .layer(
            CorsLayer::new()
                .allow_origin("https://meta-uber-engineer.dev".parse::<axum::http::HeaderValue>()?)
                .allow_methods([Method::POST])
                .allow_headers([header::CONTENT_TYPE]),
        )
        .with_state(Inbox {
            directory: Arc::new(inbox),
            write_lock: Arc::new(Mutex::new(())),
        });
    let listener = tokio::net::TcpListener::bind(address).await?;
    println!("Lighthouse HTTP listening on {address}");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn ingest(
    State(inbox): State<Inbox>,
    Json(mut input): Json<IncomingMessage>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, &'static str)> {
    input.message = input.message.trim().to_owned();
    input.contact = input.contact.trim().to_owned();
    input.company = input.company.trim().to_owned();
    input.role = input.role.trim().to_owned();
    if input.message.is_empty()
        || input.message.len() > 8_000
        || input.contact.len() > 500
        || input.company.len() > 256
        || input.role.len() > 256
    {
        return Err((StatusCode::BAD_REQUEST, "Invalid message"));
    }
    let bytes =
        serde_json::to_vec(&input).map_err(|_| (StatusCode::BAD_REQUEST, "Invalid message"))?;
    let id = format!("{:x}", Sha256::digest(&bytes));
    let saved = tokio::task::spawn_blocking(move || save_inbox(&inbox, &id, &bytes).map(|_| id))
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Inbox unavailable"))?
        .map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "Inbox unavailable"))?;
    let receipt = Receipt {
        id: &saved,
        status: "pending",
        message: "Thanks. Your message was received.",
    };
    Ok((
        StatusCode::ACCEPTED,
        Json(serde_json::to_value(receipt).unwrap()),
    ))
}

fn save_inbox(inbox: &Inbox, id: &str, bytes: &[u8]) -> std::io::Result<()> {
    let _guard = inbox
        .write_lock
        .lock()
        .map_err(|_| std::io::Error::other("Inbox lock unavailable"))?;
    let directory = &inbox.directory;
    let path = directory.join(format!("{id}.json"));
    if path.exists() {
        return Ok(());
    }
    if fs::read_dir(directory.as_ref())?
        .filter_map(Result::ok)
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "json"))
        .count()
        >= MAX_PENDING
    {
        return Err(std::io::Error::other("Inbox is full"));
    }
    let temporary = directory.join(format!("{id}.tmp"));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(&temporary) {
        Ok(mut file) => {
            let result = (|| {
                file.write_all(bytes)?;
                file.sync_all()?;
                fs::hard_link(&temporary, &path)?;
                fs::File::open(directory.as_ref())?.sync_all()
            })();
            let _ = fs::remove_file(&temporary);
            result
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            Err(std::io::Error::other("Stale inbox write"))
        }
        Err(error) => Err(error),
    }
}
