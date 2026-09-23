use std::{fs, io::Write, path::PathBuf, str::FromStr, time::Duration};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use iroh::{EndpointAddr, EndpointId};
use match_lighthouse::{MatchLighthouseState, MatchScopeStore, now_ms};
use meta_mesh_core::{
    DEFAULT_SIGNATURE_DOMAIN, DeviceCertificate, DeviceCertificatePayload, MeshHandshake,
    PublicIdentity, ScopedInvitation, VerifyWorkspaceMemberOptions, WorkspaceGrant,
    WorkspaceJoinHandshake, WorkspaceJoinResponse, WorkspaceRole, decode_workspace_set,
    parse_invitation, public_key_from_seed, public_key_id, sign_device_certificate,
    sign_json_envelope, verify_workspace_grant, verify_workspace_member_bundle,
};
use meta_mesh_native::{NativeNode, NativeNodeOptions};
use serde::Deserialize;
use serde_json::{Value, json};
use time::{OffsetDateTime, macros::format_description};

use crate::Config;

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
    if invite.workspaces.len() != 1 {
        return Err("Lighthouse accepts one workspace per invitation".into());
    }
    if directory.exists() {
        return Err("Lighthouse state directory already exists".into());
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
    let bundle = guest_bundle(
        &invite.workspace_id,
        &person_id,
        &device_id,
        &identity_public_key,
        &certificate,
        &device_seed,
        &node.endpoint_id().to_string(),
    )?;
    let owner = EndpointAddr::new(owner_endpoint);
    let session = node.connect_browser(owner, Duration::from_secs(15)).await?;
    let result = async {
        let mut machine = WorkspaceJoinHandshake::guest(&invite.secret)?;
        let request = serde_json::to_vec(&json!({
            "invitationId": invite.invitation_id,
            "personId": person_id,
            "displayName": "mesh-lighthouse",
            "meshPeers": [bundle],
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
        let config = prepare_config(
            &invite,
            &accepted,
            &directory,
            &person_id,
            &device_id,
            &bundle,
            identity_seed,
            &device_seed,
            iroh_secret,
        )?;
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
        let _ = fs::remove_dir_all(&directory);
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

fn guest_bundle(
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
            "deviceName": "mesh-lighthouse",
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
fn prepare_config(
    invite: &meta_mesh_core::WorkspaceJoinInvitation,
    response: &[u8],
    directory: &PathBuf,
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
    let entries = decode_workspace_set(&workspace_set, &[invite.workspace_id.clone()])?;
    let entry = &entries[0];
    let state = MatchLighthouseState {
        document: URL_SAFE_NO_PAD.decode(&entry.bytes)?,
        authorization: entry
            .authorization
            .clone()
            .ok_or("Missing Match write authorization")?,
        chat: entry
            .chat
            .clone()
            .unwrap_or_else(|| json!({"version":1,"messages":[],"profiles":[],"typing":[]})),
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
    let store = MatchScopeStore::open(
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
    })
}

fn save_config(directory: &PathBuf, config: &Config) -> Result<(), BoxError> {
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

fn create_private_directory(directory: &PathBuf) -> Result<(), BoxError> {
    fs::create_dir(directory)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}
