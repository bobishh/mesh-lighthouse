use std::{fs, net::SocketAddr, path::PathBuf, str::FromStr, sync::Arc};

use iroh::EndpointId;
use match_lighthouse::{LeadDraft, MatchLighthouseState, now_ms};
use meta_mesh_core::{DEFAULT_SIGNATURE_DOMAIN, MeshHandshake, sign_json_envelope};
use meta_mesh_native::{
    FileScopeStore, NativeNode, NativeNodeOptions, NativeScopeService, serve_scope_request,
};
use serde::Deserialize;
use serde_json::Value;
use time::{OffsetDateTime, macros::format_description};
use tokio::sync::Mutex;

mod http;
mod join;
mod keeper;
mod pairing;
mod provisioning;
mod replication;

#[derive(Clone, Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Config {
    pub(crate) workspace_id: String,
    pub(crate) transport_secret: String,
    pub(crate) device_id: String,
    pub(crate) iroh_secret: Vec<u8>,
    pub(crate) owner_endpoint_id: String,
    pub(crate) local_handshake: MeshHandshake,
    pub(crate) genesis_person_id: String,
    pub(crate) state_path: PathBuf,
    pub(crate) initial_state: MatchLighthouseState,
    #[serde(default)]
    pub(crate) identity_seed: Vec<u8>,
    #[serde(default)]
    pub(crate) device_seed: Vec<u8>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) additional_scopes: Vec<Config>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) controller_person_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) provisioning_commits: Vec<ProvisioningCommit>,
}

#[derive(Clone, Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ProvisioningCommit {
    pub(crate) pairing_id: String,
    pub(crate) operation_id: String,
    pub(crate) transcript_hash: String,
    pub(crate) invitation_id: String,
    pub(crate) workspace_ids: Vec<String>,
    #[serde(default)]
    pub(crate) snapshot_hash: String,
    #[serde(default)]
    pub(crate) future_boards: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut args = std::env::args().skip(1);
    let path = args.next().ok_or(
        "Usage: match-lighthouse CONFIG.json | match-lighthouse join INVITE_URL STATE_DIR",
    )?;
    if path == "join" {
        let invite = args
            .next()
            .ok_or("Missing Match workspace invitation URL")?;
        let directory = args.next().ok_or("Missing lighthouse state directory")?;
        if args.next().is_some() {
            return Err("Too many join arguments".into());
        }
        join::join(&invite, PathBuf::from(directory)).await?;
        return Ok(());
    }
    if path == "serve-http" {
        let directory = PathBuf::from(args.next().ok_or("Missing lighthouse state directory")?);
        let address: SocketAddr = args
            .next()
            .unwrap_or_else(|| "0.0.0.0:8080".into())
            .parse()?;
        if args.next().is_some() {
            return Err("Too many serve-http arguments".into());
        }
        let discovery = load_discovery(&directory)?;
        return http::serve(directory, address, None, discovery).await;
    }
    if args.next().is_some() {
        return Err("Too many arguments".into());
    }
    let config: Config = serde_json::from_slice(&fs::read(&path)?)?;
    let discovery = match std::env::var("LIGHTHOUSE_PUBLIC_ORIGIN") {
        Ok(origin) => {
            let mut discovery = http::Discovery::from_peer(&config.local_handshake.peer, &origin)
                .map_err(std::io::Error::other)?;
            if let Ok(admin_secret) = std::env::var("LIGHTHOUSE_ADMIN_TOKEN") {
                let seed: [u8; 32] = config
                    .device_seed
                    .as_slice()
                    .try_into()
                    .map_err(|_| "Lighthouse device seed must contain 32 bytes")?;
                discovery = discovery.with_pairings(
                    pairing::PairingService::open(
                        config.state_path.with_file_name("pairings"),
                        &config.local_handshake.peer,
                        origin,
                        seed,
                        admin_secret,
                    )
                    .map_err(std::io::Error::other)?,
                );
            }
            Some(discovery)
        }
        Err(_) => None,
    };
    let device_seed: [u8; 32] = config
        .device_seed
        .as_slice()
        .try_into()
        .map_err(|_| "Lighthouse device seed must contain 32 bytes")?;
    let route_store = FileScopeStore::new(config.state_path.with_file_name("route-sequence"));
    let secret: [u8; 32] = config
        .iroh_secret
        .as_slice()
        .try_into()
        .map_err(|_| "Lighthouse Iroh secret must contain 32 bytes")?;
    let owner_id = EndpointId::from_str(&config.owner_endpoint_id)?;
    let node = Arc::new(
        NativeNode::start_with_options(NativeNodeOptions {
            secret: Some(secret),
            allowed_peers: vec![owner_id],
            accept_unlisted_browser_rpc: true,
            ..NativeNodeOptions::default()
        })
        .await?,
    );
    let host = keeper::KeeperHost::open(config.clone(), fs::canonicalize(&path)?)?;
    let discovery = discovery.map(|discovery| {
        discovery.with_provisioner(provisioning::ProvisioningService::new(
            host.clone(),
            Arc::clone(&node),
        ))
    });
    let service = Arc::new(Mutex::new(NativeScopeService::new(host.clone())));
    if let Ok(bind) = std::env::var("LIGHTHOUSE_HTTP_BIND") {
        let directory = config
            .state_path
            .parent()
            .ok_or("Invalid lighthouse state path")?
            .to_path_buf();
        let address: SocketAddr = bind.parse()?;
        let (lead_sender, mut lead_receiver) = tokio::sync::mpsc::channel::<http::LeadRequest>(16);
        let (mut lead_store, lead_peer) = host.primary_store()?;
        let lead_seed = device_seed;
        tokio::spawn(async move {
            while let Some(request) = lead_receiver.recv().await {
                let store = &mut lead_store;
                let result = store
                    .create_chat_message(
                        &lead_peer,
                        &lead_seed,
                        &request.lead_id,
                        &format!("New lead\n\n{}\n\n{}", request.body, request.verdict),
                    )
                    .and_then(|_| {
                        if request.create_card {
                            store
                                .create_lead(
                                    &lead_peer,
                                    &lead_seed,
                                    LeadDraft {
                                        id: &request.lead_id,
                                        company: &request.company,
                                        role: &request.role,
                                        job_url: &request.job_url,
                                        body: &request.body,
                                    },
                                )
                                .map(Some)
                        } else {
                            Ok(None)
                        }
                    });
                let _ = request.response.send(result);
            }
        });
        tokio::spawn(async move {
            if let Err(error) = http::serve(directory, address, Some(lead_sender), discovery).await
            {
                eprintln!("Lighthouse HTTP: {error}");
            }
        });
    }
    let incoming_node = Arc::clone(&node);
    let incoming_service = Arc::clone(&service);
    tokio::spawn(async move {
        loop {
            match serve_scope_request(&incoming_node, &incoming_service, now_ms().unwrap_or(0))
                .await
            {
                Ok(true) => {}
                Ok(false) => break,
                Err(error) => eprintln!("Lighthouse receive: {error}"),
            }
        }
    });
    println!(
        "Lighthouse {} listening for workspace {}",
        node.endpoint_id(),
        config.workspace_id
    );
    let previous = route_store
        .read()?
        .map(|bytes| {
            String::from_utf8(bytes)
                .map_err(|_| "Invalid lighthouse route sequence".to_string())?
                .parse::<u64>()
                .map_err(|_| "Invalid lighthouse route sequence".to_string())
        })
        .transpose()?
        .unwrap_or(0);
    let route_sequence = previous.saturating_add(1).max(now_ms()?.try_into()?);
    route_store.write_validated(route_sequence.to_string().as_bytes(), None, |_, _| Ok(()))?;
    host.refresh_routes(route_sequence)?;
    replication::run(node, service, host).await
}

fn load_discovery(
    directory: &std::path::Path,
) -> Result<Option<http::Discovery>, Box<dyn std::error::Error + Send + Sync>> {
    let Ok(public_origin) = std::env::var("LIGHTHOUSE_PUBLIC_ORIGIN") else {
        return Ok(None);
    };
    let config_path = directory.join("config.json");
    if !config_path.exists() {
        return Ok(None);
    }
    let config: Config = serde_json::from_slice(&fs::read(config_path)?)?;
    let mut discovery = http::Discovery::from_peer(&config.local_handshake.peer, &public_origin)
        .map_err(std::io::Error::other)?;
    if let Ok(admin_secret) = std::env::var("LIGHTHOUSE_ADMIN_TOKEN") {
        let seed: [u8; 32] = config
            .device_seed
            .as_slice()
            .try_into()
            .map_err(|_| "Lighthouse device seed must contain 32 bytes")?;
        discovery = discovery.with_pairings(
            pairing::PairingService::open(
                directory.join("pairings"),
                &config.local_handshake.peer,
                public_origin,
                seed,
                admin_secret,
            )
            .map_err(std::io::Error::other)?,
        );
    }
    Ok(Some(discovery))
}

fn refresh_route(
    handshake: &mut MeshHandshake,
    seed: &[u8; 32],
    sequence: u64,
) -> Result<(), String> {
    let mut payload = handshake
        .peer
        .pointer("/advertisement/payload")
        .cloned()
        .ok_or("Missing lighthouse route advertisement")?;
    let issued_at = OffsetDateTime::from_unix_timestamp_nanos(now_ms()? * 1_000_000)
        .map_err(|error| error.to_string())?
        .format(format_description!(
            "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z"
        ))
        .map_err(|error| error.to_string())?;
    payload["issuedAt"] = Value::String(issued_at);
    payload["routeSequence"] = Value::from(sequence);
    payload["deviceName"] = Value::String("Lighthouse".into());
    payload["userAgent"] =
        Value::String(concat!("mesh-lighthouse/", env!("CARGO_PKG_VERSION")).into());
    let signed = serde_json::to_value(sign_json_envelope(
        seed,
        payload.clone(),
        handshake
            .peer
            .pointer("/advertisement/payload/deviceId")
            .and_then(Value::as_str)
            .ok_or("Missing lighthouse device id")?,
        DEFAULT_SIGNATURE_DOMAIN,
    )?)
    .map_err(|error| error.to_string())?;
    let peer = handshake
        .peer
        .as_object_mut()
        .ok_or("Invalid lighthouse peer bundle")?;
    peer.insert("advertisement".into(), signed.clone());
    peer.insert("signed".into(), signed.clone());
    peer.insert("payload".into(), payload);
    peer.insert("signature".into(), signed["signature"].clone());
    peer.insert("signerKeyId".into(), signed["signerKeyId"].clone());
    Ok(())
}
