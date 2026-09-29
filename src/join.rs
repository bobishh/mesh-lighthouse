use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use iroh::{EndpointAddr, EndpointId};
use match_lighthouse::{MatchLighthouseState, MatchScopeStore, now_ms};
use meta_mesh_core::{
    DEFAULT_SIGNATURE_DOMAIN, DeviceCertificate, DeviceCertificatePayload, MeshHandshake,
    MeshScopeFrameEffect, MeshScopeRuntime, PublicIdentity, ScopedInvitation,
    VerifyWorkspaceMemberOptions, WorkspaceGrant, WorkspaceJoinHandshake, WorkspaceJoinInvitation,
    WorkspaceJoinResponse, WorkspaceRole, decode_workspace_set, encode_workspace_set,
    parse_invitation, public_key_from_seed, public_key_id, sign_device_certificate,
    sign_json_envelope, verify_workspace_grant, verify_workspace_member_bundle,
};
use meta_mesh_native::{NativeBrowserConnection, NativeNode, NativeNodeOptions, NativeScopeHost};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, macros::format_description};

use crate::{Config, ProvisioningCommit};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct JoinResponse {
    grants: Vec<WorkspaceGrant>,
    snapshot: String,
    mesh_workspaces: Vec<Value>,
}

pub async fn join(raw_invite: &str, directory: PathBuf) -> Result<(), BoxError> {
    let invite = match parse_invitation(raw_invite, now_ms()?.try_into()?)? {
        ScopedInvitation::WorkspaceJoin(invite) => invite,
        _ => return Err("Lighthouse requires a workspace invitation".into()),
    };
    let directory_existed = directory.exists();
    if directory_existed
        && (directory.join("config.json").exists() || directory.join("state.json").exists())
    {
        return Err("Lighthouse identity already exists in state directory".into());
    }

    let identity_seed: [u8; 32] = rand::random();
    let device_seed: [u8; 32] = rand::random();
    let iroh_secret: [u8; 32] = rand::random();
    let identity_public_key = public_key_from_seed(&identity_seed)?;
    let person_id = public_key_id(&identity_public_key)?;
    let device_public_key = public_key_from_seed(&device_seed)?;
    let device_id = public_key_id(&device_public_key)?;
    let certificate = sign_device_certificate(
        &identity_seed,
        DeviceCertificatePayload {
            kind: "device-certificate".into(),
            version: 1,
            person_id: person_id.clone(),
            device_id: device_id.clone(),
            device_public_key,
            issuer_certificate_hash: None,
            can_enroll_devices: false,
        },
        &person_id,
        DEFAULT_SIGNATURE_DOMAIN,
    )?;
    let owner_endpoint = EndpointId::from_str(&invite.issuer_endpoint)?;
    let node = NativeNode::start_with_options(NativeNodeOptions {
        secret: Some(iroh_secret),
        allowed_peers: vec![owner_endpoint],
        ..NativeNodeOptions::default()
    })
    .await?;
    let bundles = invite
        .workspaces
        .iter()
        .map(|workspace| {
            guest_bundle(
                &workspace.id,
                &person_id,
                &device_id,
                &identity_public_key,
                &certificate,
                &device_seed,
                &node.endpoint_id().to_string(),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let owner = EndpointAddr::new(owner_endpoint);
    let session = node.connect_browser(owner, Duration::from_secs(15)).await?;
    let mut created_scope_directories = Vec::new();
    let result = async {
        let mut machine = WorkspaceJoinHandshake::guest(&invite.secret)?;
        let request = serde_json::to_vec(&json!({
            "invitationId": invite.invitation_id,
            "personId": person_id,
            "displayName": "mesh-lighthouse",
            "meshPeers": bundles,
            "followOwner": true,
        }))?;
        let frame = machine.send_request(&request)?;
        let response = session.exchange(&frame, Duration::from_secs(600)).await?;
        let accepted = match machine.receive_response(&response)? {
            WorkspaceJoinResponse::Accepted(payload) => payload,
            WorkspaceJoinResponse::Rejected(reason) => {
                let ack = machine.acknowledge_rejection()?;
                let _ = session.exchange(&ack, Duration::from_secs(10)).await;
                return Err(reason.into());
            }
        };
        create_private_directory(&directory)?;
        let directory = fs::canonicalize(&directory)?;
        let received: JoinResponse = serde_json::from_slice(&accepted)?;
        let ids = invite.workspaces.iter().map(|workspace| workspace.id.clone()).collect::<Vec<_>>();
        if received.grants.len() != ids.len() || received.mesh_workspaces.len() != ids.len() {
            return Err("Workspace invitation must contain every selected grant and scope".into());
        }
        let entries = decode_workspace_set(&URL_SAFE_NO_PAD.decode(&received.snapshot)?, &ids)?;
        let mut configs = Vec::new();
        for (index, workspace) in invite.workspaces.iter().enumerate() {
            let mut scoped_invite = invite.clone();
            scoped_invite.workspace_id = workspace.id.clone();
            scoped_invite.workspaces = vec![workspace.clone()];
            let grant = received.grants.iter().find(|grant| grant.payload.workspace_id == workspace.id)
                .ok_or("Missing invited scope grant")?;
            let envelope = received.mesh_workspaces.iter().find(|envelope| envelope["workspaceId"] == workspace.id)
                .ok_or("Missing invited scope")?;
            let entry = entries.iter().find(|entry| entry.id == workspace.id).ok_or("Missing invited document")?;
            let scoped_response = serde_json::to_vec(&json!({ "grants": [grant],
                "meshWorkspaces": [envelope], "snapshot": URL_SAFE_NO_PAD.encode(serde_json::to_vec(&vec![entry])?) }))?;
            let path = if index == 0 { directory.clone() } else {
                let path = directory.join(format!("scope-{:032x}", rand::random::<u128>()));
                create_private_directory(&path)?;
                created_scope_directories.push(path.clone());
                path
            };
            configs.push(prepare_config(&scoped_invite, &scoped_response, &path, &person_id, &device_id,
                &bundles[index], identity_seed, &device_seed, iroh_secret)?);
        }
        let mut config = configs.remove(0);
        config.additional_scopes = configs;
        let owner_connection = serde_json::from_slice::<Value>(&accepted)?;
        config.controller_person_id = owner_connection.pointer("/ownerConnection/controllerPersonId")
            .and_then(Value::as_str).filter(|person| *person == invite.issuer_person_id).map(str::to_owned);
        save_config(&directory, &config)?;
        let ack = machine.acknowledge_success(
            &URL_SAFE_NO_PAD.decode(serde_json::from_slice::<JoinResponse>(&accepted)?.snapshot)?,
        )?;
        session.exchange(&ack, Duration::from_secs(20)).await?;
        Ok::<_, BoxError>(config)
    }
    .await;
    session.close();
    node.close().await?;
    if result.is_err() && !directory.join("config.json").exists() {
        for path in created_scope_directories {
            let _ = fs::remove_dir_all(path);
        }
        cleanup_failed_join(&directory, directory_existed);
    }
    let config = result?;
    println!(
        "Lighthouse joined {} as {}. Start: match-lighthouse {}",
        config.workspace_id,
        config.device_id,
        directory.join("config.json").display(),
    );
    Ok(())
}

/// Join approved owner scopes with the already running Lighthouse identity.
/// The activation callback must atomically publish all staged configs before
/// the handshake ACK is sent to Match.
pub async fn provision_existing_identity(
    invite: WorkspaceJoinInvitation,
    approved_scopes: &[String],
    pairing_id: &str,
    operation_id: &str,
    transcript_hash: &str,
    future_boards: bool,
    base: &Config,
    node: &NativeNode,
    service_directory: &Path,
    activate: impl FnOnce(Vec<Config>, ProvisioningCommit) -> Result<(), String>,
) -> Result<Vec<String>, BoxError> {
    let scope_ids = invite
        .workspaces
        .iter()
        .map(|workspace| workspace.id.clone())
        .collect::<Vec<_>>();
    if scope_ids.is_empty() || scope_ids != approved_scopes {
        return Err("Invitation scope set differs from dual-approved scopes".into());
    }
    if invite.role != "visitor" {
        return Err("Keeper replication requires visitor grants".into());
    }
    let identity_seed: [u8; 32] = base
        .identity_seed
        .as_slice()
        .try_into()
        .map_err(|_| "Keeper identity seed must contain 32 bytes")?;
    let device_seed: [u8; 32] = base
        .device_seed
        .as_slice()
        .try_into()
        .map_err(|_| "Keeper device seed must contain 32 bytes")?;
    let iroh_secret: [u8; 32] = base
        .iroh_secret
        .as_slice()
        .try_into()
        .map_err(|_| "Keeper Iroh seed must contain 32 bytes")?;
    let identity_public_key = public_key_from_seed(&identity_seed)?;
    let person_id = public_key_id(&identity_public_key)?;
    let device_id = public_key_id(&public_key_from_seed(&device_seed)?)?;
    if person_id
        != base
            .local_handshake
            .peer
            .pointer("/advertisement/payload/personId")
            .and_then(Value::as_str)
            .ok_or("Missing configured Lighthouse person identity")?
        || device_id != base.device_id
        || invite.issuer_person_id.is_empty()
    {
        return Err(
            "Configured Lighthouse identity material does not match its certificate".into(),
        );
    }
    let device_certificate = base
        .local_handshake
        .peer
        .get("certificates")
        .and_then(Value::as_array)
        .and_then(|certificates| certificates.first())
        .cloned()
        .ok_or("Missing configured Lighthouse device certificate")?;
    let device_certificate: DeviceCertificate = serde_json::from_value(device_certificate)?;
    let endpoint = base
        .local_handshake
        .peer
        .pointer("/advertisement/payload/endpoint")
        .and_then(Value::as_str)
        .ok_or("Missing configured Lighthouse endpoint")?;
    let bundles = invite
        .workspaces
        .iter()
        .map(|workspace| {
            guest_bundle(
                &workspace.id,
                &person_id,
                &device_id,
                &identity_public_key,
                &device_certificate,
                &device_seed,
                endpoint,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let owner_endpoint = EndpointId::from_str(&invite.issuer_endpoint)?;
    let session = node
        .connect_browser(EndpointAddr::new(owner_endpoint), Duration::from_secs(15))
        .await?;
    if pairing_id.is_empty()
        || !pairing_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        session.close();
        return Err("Invalid pairing identifier".into());
    }
    let stage_root = service_directory.join(format!(".provisioning-{pairing_id}"));
    if stage_root.exists() {
        fs::remove_dir_all(&stage_root)?;
    }
    create_private_directory(&stage_root)?;
    let mut committed = false;
    let result = async {
        let mut machine = WorkspaceJoinHandshake::guest(&invite.secret)?;
        let request = serde_json::to_vec(&json!({
            "invitationId": invite.invitation_id,
            "personId": person_id,
            "displayName": "mesh-lighthouse",
            "meshPeers": bundles,
            "followOwner": future_boards,
        }))?;
        let frame = machine.send_request(&request)?;
        let response = session.exchange(&frame, Duration::from_secs(600)).await?;
        let accepted = match machine.receive_response(&response)? {
            WorkspaceJoinResponse::Accepted(payload) => payload,
            WorkspaceJoinResponse::Rejected(reason) => {
                let ack = machine.acknowledge_rejection()?;
                let _ = session.exchange(&ack, Duration::from_secs(10)).await;
                return Err::<Vec<String>, BoxError>(reason.into());
            }
        };
        let accepted_payload: Value = serde_json::from_slice(&accepted)?;
        let original_snapshot_bytes = URL_SAFE_NO_PAD.decode(
            accepted_payload["snapshot"]
                .as_str()
                .ok_or("Workspace join response is missing snapshot")?,
        )?;
        let mut received: JoinResponse = serde_json::from_value(accepted_payload)?;
        if received.grants.len() != scope_ids.len()
            || received.mesh_workspaces.len() != scope_ids.len()
        {
            return Err("Workspace invitation must contain every selected grant and scope".into());
        }
        let snapshot_bytes = original_snapshot_bytes.clone();
        let mut entries = decode_workspace_set(&snapshot_bytes, &scope_ids)?;
        let proof_cache = stage_root.join("proof-pages");
        create_private_directory(&proof_cache)?;
        for entry in &mut entries {
            let authorization = entry
                .authorization
                .as_ref()
                .ok_or("Invitation scope is missing authorization evidence")?;
            if authorization.get("kind").and_then(Value::as_str)
                != Some("workspace-authorization-manifest")
            {
                continue;
            }
            let candidate = URL_SAFE_NO_PAD.decode(&entry.bytes)?;
            entry.authorization = Some(
                resolve_initial_authorization(
                    &entry.id,
                    &invite.secret,
                    &candidate,
                    authorization,
                    &proof_cache,
                    &session,
                )
                .await?,
            );
        }
        let snapshot = encode_workspace_set(&entries)?;
        received.snapshot = URL_SAFE_NO_PAD.encode(&snapshot);
        let mut staged = Vec::with_capacity(scope_ids.len());
        for (index, workspace) in invite.workspaces.iter().enumerate() {
            let mut scoped_invite = invite.clone();
            scoped_invite.workspace_id = workspace.id.clone();
            scoped_invite.workspaces = vec![workspace.clone()];
            let grant = received
                .grants
                .iter()
                .find(|grant| grant.payload.workspace_id == workspace.id)
                .ok_or("Missing invited scope grant")?;
            let envelope = received
                .mesh_workspaces
                .iter()
                .find(|envelope| envelope["workspaceId"] == workspace.id)
                .ok_or("Missing invited scope")?;
            let entry = entries
                .iter()
                .find(|entry| entry.id == workspace.id)
                .ok_or("Missing invited document")?;
            let scoped_snapshot = encode_workspace_set(std::slice::from_ref(entry))?;
            let scoped_response = serde_json::to_vec(&json!({
                "grants": [grant],
                "meshWorkspaces": [envelope],
                "snapshot": URL_SAFE_NO_PAD.encode(scoped_snapshot),
            }))?;
            let stage_directory = stage_root.join(format!("scope-{index}"));
            create_private_directory(&stage_directory)?;
            let mut scope = prepare_config(
                &scoped_invite,
                &scoped_response,
                &stage_directory,
                &person_id,
                &device_id,
                &bundles[index],
                identity_seed,
                &device_seed,
                iroh_secret,
            )?;
            scope.controller_person_id = future_boards.then(|| invite.issuer_person_id.clone());
            staged.push(scope);
        }
        let snapshot_hash = URL_SAFE_NO_PAD.encode(Sha256::digest(&original_snapshot_bytes));
        let receipt = serde_json::to_vec(&json!({
            "kind": "lighthouse-provision-commit",
            "version": 1,
            "workspaceIds": scope_ids,
            "snapshotHash": snapshot_hash,
        }))?;
        if receipt.len() > 4096 {
            return Err("Keeper commit receipt exceeds size limit".into());
        }
        let commit = ProvisioningCommit {
            pairing_id: pairing_id.to_owned(),
            operation_id: operation_id.to_owned(),
            transcript_hash: transcript_hash.to_owned(),
            invitation_id: invite.invitation_id.clone(),
            workspace_ids: scope_ids.clone(),
            snapshot_hash: URL_SAFE_NO_PAD.encode(Sha256::digest(&original_snapshot_bytes)),
            future_boards,
            controller_person_id: None,
        };
        if let Err(error) = activate(staged, commit) {
            return Err(error.into());
        }
        committed = true;
        let ack = machine.acknowledge_success(&receipt)?;
        let ack_result = session.exchange(&ack, Duration::from_secs(20)).await;
        // Cleanup is best-effort after the durable activation and ACK attempt.
        // A stale cache must never turn a committed join into a failed ACK.
        let _ = fs::remove_dir_all(&stage_root);
        ack_result?;
        Ok(scope_ids.clone())
    }
    .await;
    session.close();
    if result.is_err() && !committed {
        let _ = fs::remove_dir_all(&stage_root);
    }
    result
}

async fn resolve_initial_authorization(
    workspace_id: &str,
    secret: &str,
    candidate: &[u8],
    manifest: &Value,
    cache_directory: &Path,
    session: &NativeBrowserConnection,
) -> Result<Value, BoxError> {
    let mut runtime = MeshScopeRuntime::new(workspace_id, secret)?;
    let empty_document = automerge::AutoCommit::new().save();
    let mut effect =
        runtime.begin_authorization_transfer(candidate, &empty_document, manifest.clone())?;
    for _ in 0..4096 {
        effect = match effect {
            MeshScopeFrameEffect::ProofRequest { frame, cache_key } => {
                let safe_key = cache_key
                    .chars()
                    .map(|character| {
                        if character.is_ascii_alphanumeric() {
                            character
                        } else {
                            '-'
                        }
                    })
                    .collect::<String>();
                let path = cache_directory.join(format!("{safe_key}.page"));
                let reply = match fs::read(&path) {
                    Ok(cached) => runtime.accept_proof_page(&cached)?,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        let response = session.exchange(&frame, Duration::from_secs(20)).await?;
                        runtime
                            .receive_frame(&response)?
                            .ok_or("Lighthouse proof response was empty")?
                    }
                    Err(error) => return Err(error.into()),
                };
                reply
            }
            MeshScopeFrameEffect::ProofPageReceived { cache_key, payload } => {
                let safe_key = cache_key
                    .chars()
                    .map(|character| {
                        if character.is_ascii_alphanumeric() {
                            character
                        } else {
                            '-'
                        }
                    })
                    .collect::<String>();
                write_private_file(&cache_directory.join(format!("{safe_key}.page")), &payload)?;
                runtime.continue_proof_receive()?
            }
            MeshScopeFrameEffect::DocumentReceive {
                proof: Some(bundle),
                ..
            } => return Ok(bundle),
            _ => return Err("Lighthouse returned an invalid authorization-page sequence".into()),
        };
    }
    Err("Lighthouse authorization history exceeded 4096 pages".into())
}

pub(crate) fn guest_bundle(
    workspace_id: &str,
    person_id: &str,
    device_id: &str,
    public_key: &str,
    certificate: &DeviceCertificate,
    device_seed: &[u8; 32],
    endpoint: &str,
) -> Result<Value, BoxError> {
    let advertisement = sign_json_envelope(
        device_seed,
        json!({
            "kind": "peer-advertisement", "version": 1,
            "workspaceId": workspace_id, "personId": person_id,
            "deviceId": device_id, "endpoint": endpoint,
            "issuedAt": OffsetDateTime::from_unix_timestamp_nanos(now_ms()? * 1_000_000)?
                .format(format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z"))?,
            "deviceName": "Lighthouse",
            "userAgent": concat!("mesh-lighthouse/", env!("CARGO_PKG_VERSION")),
        }),
        device_id,
        DEFAULT_SIGNATURE_DOMAIN,
    )?;
    Ok(json!({
        "advertisement": advertisement,
        "signed": advertisement,
        "payload": advertisement.payload,
        "signerKeyId": advertisement.signer_key_id,
        "signature": advertisement.signature,
        "publicKey": public_key,
        "certificates": [certificate],
    }))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare_config(
    invite: &meta_mesh_core::WorkspaceJoinInvitation,
    response: &[u8],
    directory: &Path,
    person_id: &str,
    device_id: &str,
    bundle: &Value,
    identity_seed: [u8; 32],
    device_seed: &[u8; 32],
    iroh_secret: [u8; 32],
) -> Result<Config, BoxError> {
    let received: JoinResponse = serde_json::from_slice(response)?;
    if received.grants.len() != 1 || received.mesh_workspaces.len() != 1 {
        return Err("Workspace invitation must contain exactly one grant and mesh scope".into());
    }
    let envelope = &received.mesh_workspaces[0];
    let field = |name: &str| {
        envelope
            .get(name)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
    };
    if field("workspaceId") != Some(invite.workspace_id.as_str())
        || field("ownerPersonId") != Some(invite.issuer_person_id.as_str())
        || public_key_id(field("ownerPublicKey").ok_or("Missing owner public key")?)?
            != invite.issuer_person_id
    {
        return Err("Invitation owner or workspace mismatch".into());
    }
    let owner_public_key = field("ownerPublicKey").unwrap();
    let owner_certificates: Vec<DeviceCertificate> = serde_json::from_value(
        envelope
            .get("ownerCertificates")
            .cloned()
            .ok_or("Missing owner certificates")?,
    )?;
    let owner_identity = PublicIdentity {
        person_id: invite.issuer_person_id.clone(),
        public_key: owner_public_key.into(),
        display_name: String::new(),
    };
    let grant = &received.grants[0];
    let role = verify_workspace_grant(
        grant,
        &invite.workspace_id,
        person_id,
        &owner_identity,
        &owner_certificates,
    )?;
    if role != WorkspaceRole::Editor && role != WorkspaceRole::Visitor {
        return Err("Lighthouse invitation issued an invalid role".into());
    }
    let peers = envelope
        .get("peers")
        .and_then(Value::as_array)
        .ok_or("Missing owner peer")?;
    let issuer = peers
        .iter()
        .find(|peer| {
            peer.pointer("/advertisement/payload/deviceId")
                .and_then(Value::as_str)
                == Some(invite.issuer_device_id.as_str())
        })
        .ok_or("Invitation issuer absent from mesh peers")?;
    let verified_issuer = verify_workspace_member_bundle(
        issuer.clone(),
        VerifyWorkspaceMemberOptions {
            workspace_id: Some(invite.workspace_id.clone()),
            owner_person_id: Some(invite.issuer_person_id.clone()),
            owner_public_key: Some(owner_public_key.into()),
            owner_certificates: owner_certificates.clone(),
            ..Default::default()
        },
        now_ms()?,
    )?;
    if verified_issuer.role != WorkspaceRole::Owner
        || verified_issuer.device_public_key != invite.issuer_public_key
        || verified_issuer.payload.endpoint != invite.issuer_endpoint
    {
        return Err("Invitation issuer does not match signed owner route".into());
    }
    let workspace_set = URL_SAFE_NO_PAD.decode(received.snapshot)?;
    let entries = decode_workspace_set(&workspace_set, std::slice::from_ref(&invite.workspace_id))?;
    let entry = &entries[0];
    let mut state = MatchLighthouseState {
        document: URL_SAFE_NO_PAD.decode(&entry.bytes)?,
        authorization: entry
            .authorization
            .clone()
            .ok_or("Missing Match write authorization")?,
        chat: entry
            .chat
            .clone()
            .unwrap_or_else(|| json!({"version":1,"messages":[],"profiles":[],"typing":[]})),
        mesh: None,
    };
    let mut local_peer = bundle.clone();
    local_peer["grant"] = serde_json::to_value(grant)?;
    local_peer["ownerPublicKey"] = json!(owner_public_key);
    local_peer["ownerCertificates"] = serde_json::to_value(&owner_certificates)?;
    let verified_local = verify_workspace_member_bundle(
        local_peer.clone(),
        VerifyWorkspaceMemberOptions {
            workspace_id: Some(invite.workspace_id.clone()),
            owner_person_id: Some(invite.issuer_person_id.clone()),
            owner_public_key: Some(owner_public_key.into()),
            owner_certificates: owner_certificates.clone(),
            ..Default::default()
        },
        now_ms()?,
    )?;
    if verified_local.role != role {
        return Err("Lighthouse grant and advertisement disagree".into());
    }
    let mut store = MatchScopeStore::open(
        invite.workspace_id.clone(),
        invite.issuer_person_id.clone(),
        directory.join("state.json"),
        state.clone(),
    )?;
    let authority = store.authority()?;
    if authority.expected_current_owner.person_id != invite.issuer_person_id
        || authority.expected_current_owner.public_key != owner_public_key
    {
        return Err("Match document owner differs from invitation issuer".into());
    }
    let mut initial_peers = peers.clone();
    initial_peers.push(local_peer.clone());
    store.merge_mesh(&json!({"version": 1, "peers": initial_peers, "revocations": []}))?;
    state.mesh = store.snapshot()?.mesh;
    let handshake = MeshHandshake {
        workspace_id: invite.workspace_id.clone(),
        peer: local_peer,
        revocations: Vec::new(),
        device_revocations: Vec::new(),
        departures: Vec::new(),
        ownership_transfers: Vec::new(),
        succession_policy: None,
        succession_votes: Vec::new(),
        succession_claims: Vec::new(),
        owner_workspace_ids: None,
        capabilities: meta_mesh_core::MESH_CAPABILITIES
            .iter()
            .map(|item| (*item).into())
            .collect(),
    };
    Ok(Config {
        workspace_id: invite.workspace_id.clone(),
        transport_secret: field("transportSecret")
            .ok_or("Missing workspace transport secret")?
            .into(),
        device_id: device_id.into(),
        iroh_secret: iroh_secret.to_vec(),
        owner_endpoint_id: invite.issuer_endpoint.clone(),
        local_handshake: handshake,
        genesis_person_id: invite.issuer_person_id.clone(),
        state_path: directory.join("state.json"),
        initial_state: state,
        identity_seed: identity_seed.to_vec(),
        device_seed: device_seed.to_vec(),
        additional_scopes: Vec::new(),
        controller_person_id: None,
        provisioning_commits: Vec::new(),
    })
}

pub(crate) fn save_config(directory: &PathBuf, config: &Config) -> Result<(), BoxError> {
    let path = directory.join("config.json");
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(&serde_json::to_vec(config)?)?;
    file.sync_all()?;
    fs::File::open(directory)?.sync_all()?;
    Ok(())
}

pub(crate) fn create_private_directory(directory: &PathBuf) -> Result<(), BoxError> {
    match fs::create_dir(directory) {
        Ok(()) => (),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            if !fs::symlink_metadata(directory)?.file_type().is_dir() {
                return Err("Lighthouse state path is not a directory".into());
            }
        }
        Err(error) => return Err(error.into()),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn cleanup_failed_join(directory: &PathBuf, directory_existed: bool) {
    let _ = fs::remove_file(directory.join("state.json"));
    if !directory_existed {
        let _ = fs::remove_dir(directory);
    }
}

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), BoxError> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::File::open(path.parent().ok_or("Invalid proof cache path")?)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_join_preserves_existing_http_inbox() {
        let directory =
            std::env::temp_dir().join(format!("lighthouse-join-{}", rand::random::<u128>()));
        fs::create_dir(&directory).unwrap();
        let inbox = directory.join("inbox");
        fs::create_dir(&inbox).unwrap();
        fs::write(inbox.join("pending.json"), b"pending").unwrap();
        create_private_directory(&directory).unwrap();
        fs::write(directory.join("state.json"), b"incomplete").unwrap();
        cleanup_failed_join(&directory, true);
        assert!(!directory.join("state.json").exists());
        assert_eq!(fs::read(inbox.join("pending.json")).unwrap(), b"pending");
        fs::remove_dir_all(directory).unwrap();
    }
}
