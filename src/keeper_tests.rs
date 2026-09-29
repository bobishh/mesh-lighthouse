use std::{fs, path::PathBuf};

use automerge::{AutoCommit, ROOT, transaction::Transactable};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use match_lighthouse::MatchLighthouseState;
use meta_mesh_core::{
    DEFAULT_SIGNATURE_DOMAIN, DeviceCertificate, DeviceCertificatePayload, MeshHandshake,
    MeshPeerAdmission, WorkspaceAuthority, WorkspaceChangeAuthorizationPayload,
    WorkspaceGrantPayload, WorkspaceItem, WorkspaceJoinInvitation, WorkspaceRole,
    WorkspaceSetEntry, public_key_from_seed, public_key_id, sign_device_certificate,
    sign_json_envelope,
};
use meta_mesh_native::{NativeScopeHost, NativeScopeServiceHost};
use serde_json::{Value, json};

use super::KeeperHost;
use crate::{Config, ProvisioningCommit, join};

struct Identity {
    identity_seed: [u8; 32],
    device_seed: [u8; 32],
    person_id: String,
    device_id: String,
    public_key: String,
    endpoint_secret: [u8; 32],
    endpoint: String,
    certificate: DeviceCertificate,
}

impl Identity {
    fn new(identity_seed: u8, device_seed: u8, endpoint_seed: u8) -> Self {
        let identity_seed = [identity_seed; 32];
        let device_seed = [device_seed; 32];
        let public_key = public_key_from_seed(&identity_seed).unwrap();
        let person_id = public_key_id(&public_key).unwrap();
        let device_public_key = public_key_from_seed(&device_seed).unwrap();
        let device_id = public_key_id(&device_public_key).unwrap();
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
        )
        .unwrap();
        let endpoint_secret = [endpoint_seed; 32];
        Self {
            identity_seed,
            device_seed,
            person_id,
            device_id,
            public_key,
            endpoint_secret,
            endpoint: iroh::SecretKey::from(endpoint_secret).public().to_string(),
            certificate,
        }
    }

    fn bundle(&self, workspace_id: &str) -> Value {
        join::guest_bundle(
            workspace_id,
            &self.person_id,
            &self.device_id,
            &self.public_key,
            &self.certificate,
            &self.device_seed,
            &self.endpoint,
        )
        .unwrap()
    }

    fn authority(&self) -> WorkspaceAuthority {
        WorkspaceAuthority {
            person_id: self.person_id.clone(),
            public_key: self.public_key.clone(),
            certificates: vec![self.certificate.clone()],
        }
    }
}

struct ScopeFixture {
    invitation: WorkspaceJoinInvitation,
    response: Vec<u8>,
    grant: Value,
    envelope: Value,
    entry: Value,
}

fn signed_grant(owner: &Identity, person_id: &str, workspace_id: &str) -> Value {
    serde_json::to_value(
        sign_json_envelope(
            &owner.identity_seed,
            json!(WorkspaceGrantPayload {
                kind: "workspace-grant".into(),
                version: 1,
                grant_id: format!("grant-{workspace_id}-{person_id}"),
                workspace_id: workspace_id.into(),
                person_id: person_id.into(),
                role: WorkspaceRole::Editor,
                access_epoch: None,
            }),
            &owner.person_id,
            DEFAULT_SIGNATURE_DOMAIN,
        )
        .unwrap(),
    )
    .unwrap()
}

fn signed_state(owner: &Identity, workspace_id: &str) -> MatchLighthouseState {
    let mut document = AutoCommit::new();
    document.put(ROOT, "id", workspace_id).unwrap();
    document
        .put(ROOT, "ownerPersonId", owner.person_id.clone())
        .unwrap();
    // Automerge JS 3 uses Text objects for ordinary string properties.
    let title = document
        .put_object(ROOT, "title", automerge::ObjType::Text)
        .unwrap();
    document.splice_text(&title, 0, 0, workspace_id).unwrap();
    let bytes = document.save();
    let hashes = document
        .get_changes(&[])
        .iter()
        .map(|change| change.hash().to_string())
        .collect::<Vec<_>>();
    let signed = sign_json_envelope(
        &owner.device_seed,
        json!(WorkspaceChangeAuthorizationPayload {
            kind: "workspace-changes".into(),
            version: 1,
            workspace_id: workspace_id.into(),
            hashes,
            person_id: owner.person_id.clone(),
            device_id: owner.device_id.clone(),
        }),
        &owner.device_id,
        DEFAULT_SIGNATURE_DOMAIN,
    )
    .unwrap();
    MatchLighthouseState {
        document: bytes,
        authorization: json!({
            "version": 1,
            "records": [{
                "signed": signed,
                "publicKey": owner.public_key,
                "certificates": [owner.certificate],
            }],
            "authority": {
                "genesisOwner": owner.authority(),
                "genesisEpoch": 1,
                "currentOwner": owner.authority(),
                "currentEpoch": 1,
                "ownershipTransfers": [],
                "successionClaims": [],
                "revocations": [],
                "deviceRevocations": [],
                "departures": [],
            }
        }),
        chat: json!({"version":1,"messages":[],"profiles":[],"typing":[]}),
        mesh: None,
    }
}

fn fixture(owner: &Identity, keeper: &Identity, workspace_id: &str) -> ScopeFixture {
    let state = signed_state(owner, workspace_id);
    let grant = signed_grant(owner, &keeper.person_id, workspace_id);
    let owner_bundle = owner.bundle(workspace_id);
    let owner_peer = {
        let mut peer = owner_bundle.clone();
        peer["ownerPublicKey"] = json!(owner.public_key);
        peer["ownerCertificates"] = json!([owner.certificate]);
        peer
    };
    let envelope = json!({
        "workspaceId": workspace_id,
        "ownerPersonId": owner.person_id,
        "ownerPublicKey": owner.public_key,
        "ownerCertificates": [owner.certificate],
        "transportSecret": format!("transport-secret-{workspace_id}"),
        "peers": [owner_peer],
    });
    let entry = json!(WorkspaceSetEntry {
        id: workspace_id.into(),
        bytes: URL_SAFE_NO_PAD.encode(&state.document),
        authorization: Some(state.authorization.clone()),
        chat: Some(state.chat.clone()),
        mesh: None,
    });
    let response = serde_json::to_vec(&json!({
        "grants": [grant],
        "meshWorkspaces": [envelope],
        "snapshot": URL_SAFE_NO_PAD.encode(serde_json::to_vec(std::slice::from_ref(&entry)).unwrap()),
    }))
    .unwrap();
    let invitation = WorkspaceJoinInvitation {
        version: 1,
        kind: "workspace-join".into(),
        invitation_id: format!("invite-{workspace_id}"),
        issuer_person_id: owner.person_id.clone(),
        issuer_device_id: owner.device_id.clone(),
        issuer_public_key: public_key_from_seed(&owner.device_seed).unwrap(),
        issuer_endpoint: owner.endpoint.clone(),
        workspace_id: workspace_id.into(),
        workspace_title: workspace_id.into(),
        workspaces: vec![WorkspaceItem {
            id: workspace_id.into(),
            title: workspace_id.into(),
        }],
        role: "editor".into(),
        created_at: String::new(),
        expires_at: String::new(),
        secret: "invite-secret".into(),
    };
    ScopeFixture {
        invitation,
        response,
        grant,
        envelope,
        entry,
    }
}

struct TestKeeper {
    host: KeeperHost,
    owner: Identity,
    keeper: Identity,
    config_path: PathBuf,
    directory: PathBuf,
}

impl TestKeeper {
    fn new() -> Self {
        let owner = Identity::new(11, 12, 13);
        let keeper = Identity::new(21, 22, 23);
        let primary = fixture(&owner, &keeper, "primary-board");
        let directory = std::env::temp_dir().join(format!(
            "keeper-native-test-{}-{}",
            std::process::id(),
            rand::random::<u128>()
        ));
        fs::create_dir_all(&directory).unwrap();
        let config = join::prepare_config(
            &primary.invitation,
            &primary.response,
            &directory,
            &keeper.person_id,
            &keeper.device_id,
            &keeper.bundle("primary-board"),
            keeper.identity_seed,
            &keeper.device_seed,
            keeper.endpoint_secret,
        )
        .unwrap();
        let mut config = config;
        config.controller_person_id = Some(owner.person_id.clone());
        let config_path = directory.join("config.json");
        fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
        let host = KeeperHost::open(config, config_path.clone()).unwrap();
        Self {
            host,
            owner,
            keeper,
            config_path,
            directory,
        }
    }

    fn peer(&self, identity: &Identity, workspace_id: &str) -> MeshPeerAdmission {
        MeshPeerAdmission {
            workspace_id: workspace_id.into(),
            person_id: identity.person_id.clone(),
            device_id: identity.device_id.clone(),
            endpoint: identity.endpoint.clone(),
            instance_id: None,
            role: WorkspaceRole::Owner,
        }
    }

    fn offer(&self, fixture: &ScopeFixture) -> Value {
        json!({
            "version": 1,
            "controllerPersonId": self.owner.person_id,
            "workspaceId": fixture.invitation.workspace_id,
            "grant": fixture.grant,
            "envelope": fixture.envelope,
            "workspace": fixture.entry,
        })
    }

    fn merge_offer(&self, peer: MeshPeerAdmission, offer: &Value) -> Result<(), String> {
        let mut host = self.host.clone();
        let mut scope = host.open_scope(&peer)?;
        scope.merge_owner_offer(offer.to_string().as_bytes())
    }

    fn staged_scope(&self, workspace_id: &str) -> Config {
        let fixture = fixture(&self.owner, &self.keeper, workspace_id);
        let directory = self.directory.join(format!(".provisioning-{workspace_id}"));
        let mut config = join::prepare_config(
            &fixture.invitation,
            &fixture.response,
            &directory,
            &self.keeper.person_id,
            &self.keeper.device_id,
            &self.keeper.bundle(workspace_id),
            self.keeper.identity_seed,
            &self.keeper.device_seed,
            self.keeper.endpoint_secret,
        )
        .unwrap();
        config.controller_person_id = Some(self.owner.person_id.clone());
        config
    }
}

impl Drop for TestKeeper {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

#[tokio::test]
async fn loco_overview_authenticates_operator_and_reports_existing_boards_and_jev_without_invites()
{
    use crate::{http, pairing::PairingService};
    use axum::http::{StatusCode, header};
    let keeper = TestKeeper::new();
    let staged = keeper.staged_scope("second-board");
    keeper
        .host
        .activate_provisioned_scopes(
            vec![staged],
            ProvisioningCommit {
                pairing_id: "overview-pairing".into(),
                operation_id: "overview-operation".into(),
                transcript_hash: "overview-transcript".into(),
                invitation_id: "overview-invitation".into(),
                workspace_ids: vec!["second-board".into()],
                snapshot_hash: "overview-snapshot".into(),
                future_boards: false,
            },
        )
        .unwrap();
    let config = keeper.host.configuration().unwrap();
    let admin_secret = "test-operator-token-that-is-long-enough";
    let pairings = PairingService::open(
        keeper.directory.join("pairings"),
        &config.local_handshake.peer,
        "http://127.0.0.1:4283".into(),
        keeper.keeper.device_seed,
        admin_secret.into(),
    )
    .unwrap();
    let discovery =
        http::Discovery::from_peer(&config.local_handshake.peer, "http://127.0.0.1:4283")
            .unwrap()
            .with_pairings(pairings);
    let app = http::operator_test_router(&keeper.directory, discovery, keeper.host.clone()).await;
    fs::write(
        keeper.directory.join("inbox/pending.json"),
        "private incoming lead content",
    )
    .unwrap();
    for (index, status) in ["awaiting_mesh", "chat_queued", "card_created_v2"]
        .iter()
        .enumerate()
    {
        fs::write(keeper.directory.join(format!("results/{index}.json")), json!({
            "assessment": {"choice":"qualified", "confidence":0.9,"probabilities":{}, "model":"test-model"},
            "status":status,"company":"private employer", "role":"private lead role",
        }).to_string()).unwrap();
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = reqwest::Client::new();
    let url = format!("{origin}/admin/api/overview");
    assert_eq!(
        client.get(&url).send().await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    let login = client
        .post(format!("{origin}/admin/api/session"))
        .json(&json!({"secret":admin_secret}))
        .send()
        .await
        .unwrap();
    assert_eq!(login.status(), StatusCode::OK);
    let cookie = login.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let response = client
        .get(&url)
        .header(header::COOKIE, &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let overview = response.json::<Value>().await.unwrap();
    let boards = overview["keeper"]["boards"].as_array().unwrap();
    assert_eq!(boards.len(), 2);
    assert_eq!(boards[0]["workspaceId"], "primary-board");
    assert_eq!(boards[0]["title"], "primary-board");
    assert_eq!(boards[0]["isPrimary"], true);
    assert_eq!(boards[1]["workspaceId"], "second-board");
    assert!(
        boards
            .iter()
            .all(|board| !board["heads"].as_array().unwrap().is_empty())
    );
    assert_eq!(overview["keeper"]["personId"], keeper.keeper.person_id);
    assert_eq!(overview["keeper"]["deviceId"], keeper.keeper.device_id);
    assert_eq!(overview["replication"]["state"], "idle");
    assert_eq!(overview["replication"]["activePeers"], 0);
    assert_eq!(
        overview["triggers"][0]["targetWorkspaceId"],
        "primary-board"
    );
    assert_eq!(overview["triggers"][0]["pendingCount"], 1);
    assert!(overview["triggers"][0]["lastResultAt"].as_u64().is_some());
    assert_eq!(
        overview["triggers"][0]["outcomes"],
        json!({"awaitingMesh":1,"chatQueued":1,"cardCreated":1})
    );
    let body = overview.to_string();
    for private in [
        admin_secret,
        "private incoming lead content",
        "private employer",
        "transport-secret",
        "identitySeed",
        "deviceSeed",
        "irohSecret",
    ] {
        assert!(!body.contains(private));
    }
    // Missing durable result storage is a sanitized failure, never an empty
    // success that hides lost intake data or leaked filesystem diagnostics.
    fs::remove_dir_all(keeper.directory.join("results")).unwrap();
    let failed = client
        .get(&url)
        .header(header::COOKIE, &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(failed.status(), StatusCode::SERVICE_UNAVAILABLE);
    let failure = failed.text().await.unwrap();
    assert!(!failure.contains(keeper.directory.to_str().unwrap()));
    assert!(!failure.contains("private employer"));
    server.abort();
}

#[test]
fn approved_owner_offer_activates_and_persists_scope_with_shared_service_identity() {
    let keeper = TestKeeper::new();
    let scope_fixture = fixture(&keeper.owner, &keeper.keeper, "second-board");
    let offer = keeper.offer(&scope_fixture);

    keeper
        .merge_offer(keeper.peer(&keeper.owner, "primary-board"), &offer)
        .unwrap();

    let scopes = keeper.host.scopes().unwrap();
    assert_eq!(scopes.len(), 2);
    assert!(scopes.iter().any(|(id, _, _)| id == "second-board"));
    let persisted: Config =
        serde_json::from_slice(&fs::read(&keeper.config_path).unwrap()).unwrap();
    let added = persisted
        .additional_scopes
        .iter()
        .find(|scope| scope.workspace_id == "second-board")
        .unwrap();
    assert_eq!(added.device_id, keeper.keeper.device_id);
    assert_eq!(added.iroh_secret, keeper.keeper.endpoint_secret);
    assert_eq!(added.identity_seed, keeper.keeper.identity_seed);
    assert_eq!(added.device_seed, keeper.keeper.device_seed);
}

#[test]
fn offer_from_wrong_remote_or_claimed_controller_cannot_activate_scope() {
    let keeper = TestKeeper::new();
    let other = Identity::new(31, 32, 33);
    let scope_fixture = fixture(&keeper.owner, &keeper.keeper, "second-board");
    let offer = keeper.offer(&scope_fixture);

    assert!(
        keeper
            .merge_offer(keeper.peer(&other, "primary-board"), &offer)
            .is_err()
    );
    assert_eq!(keeper.host.scopes().unwrap().len(), 1);

    let mut forged_claim = offer;
    forged_claim["controllerPersonId"] = json!(other.person_id);
    assert!(
        keeper
            .merge_offer(keeper.peer(&keeper.owner, "primary-board"), &forged_claim)
            .is_err()
    );
    assert_eq!(keeper.host.scopes().unwrap().len(), 1);
}

#[test]
fn invalid_grant_or_document_never_activates_offered_scope() {
    let keeper = TestKeeper::new();
    let scope_fixture = fixture(&keeper.owner, &keeper.keeper, "second-board");
    let peer = keeper.peer(&keeper.owner, "primary-board");

    let mut tampered_grant = keeper.offer(&scope_fixture);
    tampered_grant["grant"]["payload"]["role"] = json!("owner");
    assert!(keeper.merge_offer(peer.clone(), &tampered_grant).is_err());
    assert_eq!(keeper.host.scopes().unwrap().len(), 1);

    let mut tampered_document = keeper.offer(&scope_fixture);
    tampered_document["workspace"]["bytes"] =
        json!(URL_SAFE_NO_PAD.encode(b"not an automerge document"));
    assert!(keeper.merge_offer(peer, &tampered_document).is_err());
    assert_eq!(keeper.host.scopes().unwrap().len(), 1);
}

#[test]
fn repeated_offer_is_idempotent_but_revalidates_signed_grant() {
    let keeper = TestKeeper::new();
    let scope_fixture = fixture(&keeper.owner, &keeper.keeper, "second-board");
    let peer = keeper.peer(&keeper.owner, "primary-board");
    let offer = keeper.offer(&scope_fixture);

    keeper.merge_offer(peer.clone(), &offer).unwrap();
    let before = keeper.host.scopes().unwrap();
    keeper.merge_offer(peer.clone(), &offer).unwrap();
    assert_eq!(keeper.host.scopes().unwrap(), before);

    let mut tampered = offer;
    tampered["grant"]["signature"] = json!("forged-signature");
    assert!(keeper.merge_offer(peer, &tampered).is_err());
    assert_eq!(keeper.host.scopes().unwrap(), before);
}

#[test]
fn owner_scope_inventory_is_withheld_from_unrelated_peer() {
    let keeper = TestKeeper::new();
    let scope_fixture = fixture(&keeper.owner, &keeper.keeper, "second-board");
    keeper
        .merge_offer(
            keeper.peer(&keeper.owner, "primary-board"),
            &keeper.offer(&scope_fixture),
        )
        .unwrap();

    let request: MeshHandshake = serde_json::from_value(json!({
        "workspaceId": "primary-board",
        "peer": {"advertisement": {"payload": {"personId": "unrelated-person"}}},
        "revocations": [],
        "deviceRevocations": [],
        "departures": [],
        "ownershipTransfers": [],
        "successionVotes": [],
        "successionClaims": [],
        "capabilities": [],
    }))
    .unwrap();
    let mut host = keeper.host.clone();
    let (_, response) = host.prepare_handshake("primary-board", &request).unwrap();
    assert!(response.get("ownerWorkspaceIds").is_none());

    let request: MeshHandshake = serde_json::from_value(json!({
        "workspaceId": "primary-board",
        "peer": keeper.owner.bundle("primary-board"),
        "revocations": [],
        "deviceRevocations": [],
        "departures": [],
        "ownershipTransfers": [],
        "successionVotes": [],
        "successionClaims": [],
        "capabilities": [],
    }))
    .unwrap();
    let (_, response) = host.prepare_handshake("primary-board", &request).unwrap();
    assert_eq!(
        response["ownerWorkspaceIds"],
        json!(["primary-board", "second-board"])
    );
}

#[test]
fn registry_write_failure_does_not_activate_or_leave_new_scope_storage() {
    let keeper = TestKeeper::new();
    let offered = fixture(&keeper.owner, &keeper.keeper, "second-board");
    fs::remove_file(&keeper.config_path).unwrap();
    fs::create_dir(&keeper.config_path).unwrap();
    assert!(
        keeper
            .merge_offer(
                keeper.peer(&keeper.owner, "primary-board"),
                &keeper.offer(&offered)
            )
            .is_err()
    );
    assert_eq!(keeper.host.scopes().unwrap().len(), 1);
    assert!(!fs::read_dir(&keeper.directory).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("scope-")
    }));
}

#[test]
fn provisioned_scopes_activate_atomically_and_retry_by_durable_marker() {
    let keeper = TestKeeper::new();
    let commit = ProvisioningCommit {
        pairing_id: "pairing-test".into(),
        operation_id: "operation-test".into(),
        transcript_hash: "transcript-test".into(),
        invitation_id: "invitation-test".into(),
        workspace_ids: vec!["selected-board-a".into(), "selected-board-b".into()],
        snapshot_hash: "snapshot-test".into(),
        future_boards: false,
    };
    let mut orphaned = vec![keeper.staged_scope("selected-board-a")];
    super::relocate_provisioned_scope_dirs(&keeper.directory, &mut orphaned, &commit).unwrap();
    let staged = vec![
        keeper.staged_scope("selected-board-a"),
        keeper.staged_scope("selected-board-b"),
    ];

    keeper
        .host
        .activate_provisioned_scopes(staged.clone(), commit.clone())
        .unwrap();
    assert_eq!(
        keeper
            .host
            .scopes()
            .unwrap()
            .iter()
            .map(|(id, _, _)| id.clone())
            .collect::<Vec<_>>(),
        vec![
            "primary-board".to_string(),
            "selected-board-a".to_string(),
            "selected-board-b".to_string()
        ]
    );
    keeper
        .host
        .activate_provisioned_scopes(staged, commit.clone())
        .unwrap();
    assert!(keeper.host.configuration().unwrap().provisioning_commits == vec![commit]);
    let mut changed = keeper.host.configuration().unwrap().provisioning_commits[0].clone();
    changed.snapshot_hash = "different-snapshot".into();
    assert!(
        keeper
            .host
            .activate_provisioned_scopes(vec![], changed)
            .is_err()
    );
    let persisted = keeper.host.configuration().unwrap();
    let added = persisted
        .additional_scopes
        .iter()
        .find(|scope| scope.workspace_id == "selected-board-a")
        .unwrap();
    assert!(added.state_path.exists());
    assert!(
        !added
            .state_path
            .starts_with(keeper.directory.join(".provisioning-"))
    );
    for workspace_id in ["selected-board-a", "selected-board-b"] {
        let _ = fs::remove_dir_all(
            keeper
                .directory
                .join(format!(".provisioning-{workspace_id}")),
        );
    }
    let reopened = KeeperHost::open(persisted, keeper.config_path.clone()).unwrap();
    assert_eq!(reopened.scopes().unwrap().len(), 3);
    assert!(reopened.primary_store().unwrap().0.snapshot().is_ok());
}

#[test]
fn failed_scope_validation_never_activates_a_subset_of_provisioned_scopes() {
    let keeper = TestKeeper::new();
    let first = keeper.staged_scope("selected-board-a");
    let mut second = keeper.staged_scope("selected-board-b");
    second.controller_person_id = Some("wrong-controller".into());
    let commit = ProvisioningCommit {
        pairing_id: "pairing-test".into(),
        operation_id: "operation-test".into(),
        transcript_hash: "transcript-test".into(),
        invitation_id: "invitation-test".into(),
        workspace_ids: vec!["selected-board-a".into(), "selected-board-b".into()],
        snapshot_hash: "snapshot-test".into(),
        future_boards: false,
    };

    assert!(
        keeper
            .host
            .activate_provisioned_scopes(vec![first, second], commit)
            .is_err()
    );
    assert_eq!(keeper.host.scopes().unwrap().len(), 1);
    assert!(
        keeper
            .host
            .configuration()
            .unwrap()
            .additional_scopes
            .is_empty()
    );
    assert!(
        keeper
            .host
            .configuration()
            .unwrap()
            .provisioning_commits
            .is_empty()
    );
}

#[test]
fn outbound_inventory_uses_signed_route_person_field_and_only_targets_owner() {
    let keeper = TestKeeper::new();
    let mut host = keeper.host.clone();
    let handshake = host.outgoing_handshake("primary-board").unwrap();
    let frame = meta_mesh_core::encode_mesh_handshake(
        "mesh-handshake-request",
        "transport-secret-primary-board",
        handshake,
    )
    .unwrap();
    let owner_frame = host
        .attach_owner_inventory(
            "primary-board",
            &keeper.owner.endpoint,
            "transport-secret-primary-board",
            frame.clone(),
        )
        .unwrap();
    let decoded = meta_mesh_core::decode_mesh_handshake(
        &owner_frame,
        "mesh-handshake-request",
        "transport-secret-primary-board",
        "primary-board",
    )
    .unwrap();
    assert_eq!(
        decoded.owner_workspace_ids,
        Some(vec!["primary-board".into()])
    );
    let other = Identity::new(31, 32, 33);
    let other_frame = host
        .attach_owner_inventory(
            "primary-board",
            &other.endpoint,
            "transport-secret-primary-board",
            frame,
        )
        .unwrap();
    let decoded = meta_mesh_core::decode_mesh_handshake(
        &other_frame,
        "mesh-handshake-request",
        "transport-secret-primary-board",
        "primary-board",
    )
    .unwrap();
    assert!(decoded.owner_workspace_ids.is_none());
}
