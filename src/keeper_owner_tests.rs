use super::*;
use crate::keeper::future_policy_matches_owner;

fn provision_commit(
    owner: &Identity,
    workspace_ids: &[&str],
    future_boards: bool,
) -> ProvisioningCommit {
    ProvisioningCommit {
        pairing_id: format!("pairing-{}", owner.person_id),
        operation_id: format!("operation-{}", owner.person_id),
        transcript_hash: "transcript".into(),
        invitation_id: "invitation".into(),
        workspace_ids: workspace_ids.iter().map(|id| (*id).into()).collect(),
        snapshot_hash: "snapshot".into(),
        future_boards,
        controller_person_id: Some(owner.person_id.clone()),
    }
}

fn owner_offer(owner: &Identity, workspace_id: &str) -> Value {
    json!({
        "version": 1,
        "controllerPersonId": owner.person_id,
        "workspaceId": workspace_id,
        "envelope": {
            "workspaceId": workspace_id,
            "ownerPersonId": owner.person_id,
            "ownerPublicKey": owner.public_key,
            "ownerCertificates": [owner.certificate],
            "peers": [],
        },
        "workspace": {"id": workspace_id},
    })
}

fn two_owner_keeper(owner_b_future_boards: bool) -> (TestKeeper, Identity) {
    let mut keeper = TestKeeper::new();
    let owner_b = Identity::new(41, 42, 43);
    let fixture_b = fixture(&owner_b, &keeper.keeper, "b-board");
    let staged_path = keeper.directory.join(".provisioning-b-board");
    let staged_b = join::prepare_config(
        &fixture_b.invitation,
        &fixture_b.response,
        &staged_path,
        &keeper.keeper.person_id,
        &keeper.keeper.device_id,
        &keeper.keeper.bundle("b-board"),
        keeper.keeper.identity_seed,
        &keeper.keeper.device_seed,
        keeper.keeper.endpoint_secret,
    )
    .unwrap();
    let mut config = keeper.host.configuration().unwrap();
    let mut legacy_commit = provision_commit(&keeper.owner, &["primary-board"], true);
    legacy_commit.controller_person_id = None;
    config.provisioning_commits.push(legacy_commit);
    fs::write(&keeper.config_path, serde_json::to_vec(&config).unwrap()).unwrap();
    keeper.host = KeeperHost::open(config, keeper.config_path.clone()).unwrap();
    keeper
        .host
        .activate_provisioned_scopes(
            vec![staged_b],
            provision_commit(&owner_b, &["b-board"], owner_b_future_boards),
        )
        .unwrap();
    let persisted = keeper.host.configuration().unwrap();
    assert_eq!(
        persisted.controller_person_id.as_deref(),
        Some(keeper.owner.person_id.as_str())
    );
    assert_eq!(
        persisted.provisioning_commits[0]
            .controller_person_id
            .as_deref(),
        Some(keeper.owner.person_id.as_str())
    );
    let persisted_b = persisted
        .additional_scopes
        .iter()
        .find(|scope| scope.workspace_id == "b-board")
        .unwrap();
    assert_eq!(
        persisted_b.controller_person_id.as_deref(),
        Some(owner_b.person_id.as_str())
    );
    (keeper, owner_b)
}

#[test]
fn owner_views_and_handshakes_only_include_current_owners_boards() {
    let (keeper, owner_b) = two_owner_keeper(false);
    let ids = |overview: Value| {
        overview["keeper"]["boards"]
            .as_array()
            .unwrap()
            .iter()
            .map(|board| board["workspaceId"].as_str().unwrap().to_owned())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        ids(keeper.host.owner_overview(&keeper.owner.person_id).unwrap()),
        ["primary-board"]
    );
    assert_eq!(
        ids(keeper.host.owner_overview(&owner_b.person_id).unwrap()),
        ["b-board"]
    );
    let mut host = keeper.host.clone();
    let request_a: MeshHandshake = serde_json::from_value(json!({
        "workspaceId":"primary-board", "peer":keeper.owner.bundle("primary-board"),
        "revocations":[], "deviceRevocations":[], "departures":[],
        "ownershipTransfers":[], "successionVotes":[], "successionClaims":[], "capabilities":[],
    }))
    .unwrap();
    let (_, response_a) = host.prepare_handshake("primary-board", &request_a).unwrap();
    assert_eq!(response_a["ownerWorkspaceIds"], json!(["primary-board"]));

    let request_b: MeshHandshake = serde_json::from_value(json!({
        "workspaceId":"b-board", "peer":owner_b.bundle("b-board"),
        "revocations":[], "deviceRevocations":[], "departures":[],
        "ownershipTransfers":[], "successionVotes":[], "successionClaims":[], "capabilities":[],
    }))
    .unwrap();
    let (_, response_b) = host.prepare_handshake("b-board", &request_b).unwrap();
    assert_eq!(response_b["ownerWorkspaceIds"], json!(["b-board"]));

    let secrets = keeper.host.scopes().unwrap();
    let secret_a = secrets
        .iter()
        .find(|(id, _, _)| id == "primary-board")
        .unwrap()
        .1
        .clone();
    let secret_b = secrets
        .iter()
        .find(|(id, _, _)| id == "b-board")
        .unwrap()
        .1
        .clone();
    let handshake_a = host.outgoing_handshake("primary-board").unwrap();
    let frame_a =
        meta_mesh_core::encode_mesh_handshake("mesh-handshake-request", &secret_a, handshake_a)
            .unwrap();
    let frame_a = keeper
        .host
        .attach_owner_inventory("primary-board", &keeper.owner.endpoint, &secret_a, frame_a)
        .unwrap();
    let inventory_a = meta_mesh_core::decode_mesh_handshake(
        &frame_a,
        "mesh-handshake-request",
        &secret_a,
        "primary-board",
    )
    .unwrap()
    .owner_workspace_ids;
    assert_eq!(inventory_a, Some(vec!["primary-board".into()]));

    let handshake = host.outgoing_handshake("b-board").unwrap();
    let frame =
        meta_mesh_core::encode_mesh_handshake("mesh-handshake-request", &secret_b, handshake)
            .unwrap();
    let frame = keeper
        .host
        .attach_owner_inventory("b-board", &owner_b.endpoint, &secret_b, frame)
        .unwrap();
    let inventory = meta_mesh_core::decode_mesh_handshake(
        &frame,
        "mesh-handshake-request",
        &secret_b,
        "b-board",
    )
    .unwrap()
    .owner_workspace_ids;
    assert_eq!(inventory, Some(vec!["b-board".into()]));
}

#[test]
fn native_owner_offers_cannot_cross_board_ownership_or_inherit_future_policy() {
    let (keeper, owner_b) = two_owner_keeper(true);
    let mut host = keeper.host.clone();
    let peer_a = keeper.peer(&keeper.owner, "primary-board");
    let peer_b = keeper.peer(&owner_b, "b-board");

    let mut scope_a = host.open_scope(&peer_a).unwrap();
    let offer_to_b = owner_offer(&keeper.owner, "b-board");
    assert!(
        scope_a
            .prepare_owner_offer(offer_to_b.to_string().as_bytes())
            .err()
            .unwrap()
            .contains("not authorized")
    );
    assert!(
        scope_a
            .merge_owner_offer(offer_to_b.to_string().as_bytes())
            .unwrap_err()
            .contains("another owner's scope")
    );

    let mut scope_b = host.open_scope(&peer_b).unwrap();
    let offer_to_a = owner_offer(&owner_b, "primary-board");
    assert!(
        scope_b
            .prepare_owner_offer(offer_to_a.to_string().as_bytes())
            .err()
            .unwrap()
            .contains("not authorized")
    );
    assert!(
        scope_b
            .merge_owner_offer(offer_to_a.to_string().as_bytes())
            .unwrap_err()
            .contains("another owner's scope")
    );
    // Both accepted commits retain independent future-board access after reopen.
    let future_b = owner_offer(&owner_b, "b-future");
    assert!(
        scope_b
            .prepare_owner_offer(future_b.to_string().as_bytes())
            .err()
            .unwrap()
            .contains("omits its authenticated owner device")
    );

    // A's accepted future policy passes authorization; validation then reaches its issuer check.
    let future_a = owner_offer(&keeper.owner, "a-future");
    assert!(
        scope_a
            .prepare_owner_offer(future_a.to_string().as_bytes())
            .err()
            .unwrap()
            .contains("omits its authenticated owner device")
    );

    let reopened = KeeperHost::open(
        keeper.host.configuration().unwrap(),
        keeper.config_path.clone(),
    )
    .unwrap();
    let mut reopened_host = reopened.clone();
    let mut reopened_b = reopened_host.open_scope(&peer_b).unwrap();
    assert!(
        reopened_b
            .prepare_owner_offer(future_b.to_string().as_bytes())
            .err()
            .unwrap()
            .contains("omits its authenticated owner device")
    );
}

#[test]
fn future_policy_off_isolated_to_owner_b() {
    let (keeper, owner_b) = two_owner_keeper(false);
    let mut host = keeper.host.clone();
    let peer_b = keeper.peer(&owner_b, "b-board");
    let mut scope_b = host.open_scope(&peer_b).unwrap();
    let future_b = owner_offer(&owner_b, "b-future");
    assert!(
        scope_b
            .prepare_owner_offer(future_b.to_string().as_bytes())
            .err()
            .unwrap()
            .contains("not authorized")
    );
}

#[test]
fn mixed_owner_activation_is_rejected_without_config_or_scope_changes() {
    let keeper = TestKeeper::new();
    let owner_b = Identity::new(41, 42, 43);
    let staged_a = keeper.staged_scope("a-staged");
    let fixture_b = fixture(&owner_b, &keeper.keeper, "b-staged");
    let staged_path = keeper.directory.join(".provisioning-b-staged");
    let staged_b = join::prepare_config(
        &fixture_b.invitation,
        &fixture_b.response,
        &staged_path,
        &keeper.keeper.person_id,
        &keeper.keeper.device_id,
        &keeper.keeper.bundle("b-staged"),
        keeper.keeper.identity_seed,
        &keeper.keeper.device_seed,
        keeper.keeper.endpoint_secret,
    )
    .unwrap();
    let before = keeper.host.configuration().unwrap();
    let commit = ProvisioningCommit {
        pairing_id: "mixed-owner-pairing".into(),
        operation_id: "mixed-owner-operation".into(),
        transcript_hash: "mixed-owner-transcript".into(),
        invitation_id: "mixed-owner-invitation".into(),
        workspace_ids: vec!["a-staged".into(), "b-staged".into()],
        snapshot_hash: "mixed-owner-snapshot".into(),
        future_boards: true,
        controller_person_id: Some(keeper.owner.person_id.clone()),
    };
    assert!(
        keeper
            .host
            .activate_provisioned_scopes(vec![staged_a, staged_b], commit)
            .unwrap_err()
            .contains("cannot mix owners")
    );
    let after = keeper.host.configuration().unwrap();
    assert_eq!(
        after.additional_scopes.len(),
        before.additional_scopes.len()
    );
    assert!(after.provisioning_commits == before.provisioning_commits);
    assert_eq!(keeper.host.scopes().unwrap().len(), 1);
}

#[test]
fn transferred_board_does_not_transfer_future_policy_to_new_owner() {
    let commits = vec![provision_commit_from_ids(&["a-one", "a-two"], true)];
    assert!(!future_policy_matches_owner("owner-b", true, &commits));
    assert!(future_policy_matches_owner("owner-a", true, &commits));
    assert!(!future_policy_matches_owner("owner-a", false, &commits));
}

fn match_certificate(identity: &Identity) -> DeviceCertificate {
    sign_device_certificate(
        &identity.identity_seed,
        DeviceCertificatePayload {
            kind: "device-certificate".into(),
            version: 1,
            person_id: identity.person_id.clone(),
            device_id: identity.device_id.clone(),
            device_public_key: public_key_from_seed(&identity.device_seed).unwrap(),
            issuer_certificate_hash: None,
            can_enroll_devices: true,
        },
        &identity.person_id,
        "MATCH/1",
    )
    .unwrap()
}

fn login_as(pairings: &crate::pairing::PairingService, identity: &Identity) -> (String, String) {
    let (intent, challenge) = pairings.begin_login("https://match.example").unwrap();
    let envelope = pairings.login_challenge(&challenge.challenge_id).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let proof = json!({
        "kind":"lighthouse-login-proof","version":1,"protocolVersion":1,
        "challengeId":challenge.challenge_id,"challengeNonce":envelope.payload["nonce"],
        "servicePersonId":pairings_service_person(pairings),"serviceOrigin":"http://127.0.0.1:23991",
        "controllerPersonId":identity.person_id,"controllerDeviceId":identity.device_id,
        "operationId":base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()),
        "issuedAt":now,"expiresAt":challenge.expires_at,
    });
    let certificate = match_certificate(identity);
    let request = crate::pairing::ControllerRequest {
        identity: meta_mesh_core::PublicIdentity {
            person_id: identity.person_id.clone(),
            public_key: identity.public_key.clone(),
            display_name: format!("Owner {}", identity.person_id),
        },
        device_id: identity.device_id.clone(),
        certificates: vec![certificate],
        signed: meta_mesh_core::sign_json_envelope(
            &identity.device_seed,
            proof,
            &identity.device_id,
            crate::pairing::CONTROL_DOMAIN,
        )
        .unwrap(),
    };
    let result = pairings
        .prove_login(request, &challenge.challenge_id)
        .unwrap();
    let (cookie, session) = pairings.exchange_login(&result.code, &intent).unwrap();
    (cookie, session.csrf_token)
}

fn pairings_service_person(_pairings: &crate::pairing::PairingService) -> String {
    // The test fixture's peer person id is deterministic from its service identity seed.
    meta_mesh_core::public_key_id(&meta_mesh_core::public_key_from_seed(&[76; 32]).unwrap())
        .unwrap()
}

fn create_owner_pairing(
    pairings: &crate::pairing::PairingService,
    identity: &Identity,
    workspace_id: &str,
) -> crate::pairing::PairingRecord {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let certificate = match_certificate(identity);
    let controller = meta_mesh_core::PublicIdentity {
        person_id: identity.person_id.clone(),
        public_key: identity.public_key.clone(),
        display_name: format!("Owner {}", identity.person_id),
    };
    let payload = json!({
        "kind":"lighthouse-pairing-offer","version":1,"protocolVersion":1,
        "servicePersonId":pairings_service_person(pairings),"serviceOrigin":"http://127.0.0.1:23991",
        "controllerPersonId":identity.person_id,"controllerDeviceId":identity.device_id,
        "operationId":base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()),
        "issuedAt":now,"expiresAt":now+600,
        "body":{"scopes":[{"workspaceId":workspace_id,"title":workspace_id,"genesisAnchor":"test-anchor","mode":"replicate"}],"policy":{"futureBoards":false}}
    });
    pairings
        .create(crate::pairing::ControllerRequest {
            identity: controller,
            device_id: identity.device_id.clone(),
            certificates: vec![certificate],
            signed: meta_mesh_core::sign_json_envelope(
                &identity.device_seed,
                payload,
                &identity.device_id,
                crate::pairing::CONTROL_DOMAIN,
            )
            .unwrap(),
        })
        .unwrap()
}

#[tokio::test]
async fn real_http_owner_sessions_filter_pairings_boards_replication_and_triggers() {
    let (keeper, owner_b) = two_owner_keeper(false);
    let service = Identity::new(76, 77, 78);
    let service_certificate = match_certificate(&service);
    let service_peer = json!({
        "advertisement":{"payload":{"personId":service.person_id,"deviceId":service.device_id,"deviceName":"Lighthouse"}},
        "publicKey":service.public_key,"certificates":[service_certificate]
    });
    let origin = "http://127.0.0.1:23991";
    let pairing_service = crate::pairing::PairingService::open(
        keeper.directory.join("pairings"),
        &service_peer,
        origin.into(),
        service.device_seed,
        "test-operator-token-that-is-long-enough".into(),
    )
    .unwrap();
    let record_a = create_owner_pairing(&pairing_service, &keeper.owner, "primary-board");
    let record_b = create_owner_pairing(&pairing_service, &owner_b, "b-board");
    let (cookie_a, csrf_a) = login_as(&pairing_service, &keeper.owner);
    let (cookie_b, csrf_b) = login_as(&pairing_service, &owner_b);

    let discovery = crate::http::Discovery::from_peer(&service_peer, origin)
        .unwrap()
        .with_pairings(pairing_service.clone());
    let runtime = crate::replication::RuntimeOverview::default();
    runtime.update("primary-board", "route-a", |status| {
        status.state = "connected".into();
        status.last_error_category = Some("owner-a-only".into());
    });
    runtime.update("b-board", "route-b", |status| {
        status.state = "connected".into();
        status.last_error_category = Some("owner-b-only".into());
    });
    let router = crate::http::operator_test_router_with_runtime(
        &keeper.directory,
        discovery,
        keeper.host.clone(),
        runtime,
    )
    .await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let base = format!("http://{address}/admin/api");
    let client = reqwest::Client::new();

    let owner_view = |cookie: &str| {
        client
            .get(format!("{base}/overview"))
            .header("cookie", format!("mesh_lighthouse_admin={cookie}"))
    };
    let response_a = owner_view(&cookie_a).send().await.unwrap();
    assert_eq!(response_a.status(), reqwest::StatusCode::OK);
    assert_eq!(
        response_a.headers().get("cache-control").unwrap(),
        "no-store"
    );
    let overview_a: Value = response_a.json().await.unwrap();
    assert_eq!(overview_a["keeper"]["boards"].as_array().unwrap().len(), 1);
    assert_eq!(
        overview_a["keeper"]["boards"][0]["workspaceId"],
        "primary-board"
    );
    assert_eq!(overview_a["replication"]["activePeers"], 1);
    assert_eq!(
        overview_a["replication"]["lastErrorCategory"],
        "owner-a-only"
    );
    assert_eq!(overview_a["triggers"].as_array().unwrap().len(), 1);

    let response_b = owner_view(&cookie_b).send().await.unwrap();
    let overview_b: Value = response_b.json().await.unwrap();
    assert_eq!(overview_b["keeper"]["boards"].as_array().unwrap().len(), 1);
    assert_eq!(overview_b["keeper"]["boards"][0]["workspaceId"], "b-board");
    assert_eq!(overview_b["replication"]["activePeers"], 1);
    assert_eq!(
        overview_b["replication"]["lastErrorCategory"],
        "owner-b-only"
    );
    assert_eq!(overview_b["triggers"], json!([]));

    for (cookie, expected_id, forbidden_id) in [
        (&cookie_a, &record_a.id, &record_b.id),
        (&cookie_b, &record_b.id, &record_a.id),
    ] {
        let listed = client
            .get(format!("{base}/pairings"))
            .header("cookie", format!("mesh_lighthouse_admin={cookie}"))
            .send()
            .await
            .unwrap();
        assert_eq!(listed.headers().get("cache-control").unwrap(), "no-store");
        let listed: Value = listed.json().await.unwrap();
        assert_eq!(listed["pairings"].as_array().unwrap().len(), 1);
        assert_eq!(listed["pairings"][0]["id"], expected_id.as_str());
        assert!(!listed.to_string().contains(forbidden_id));
    }
    let denied = client
        .post(format!("{base}/pairings/{}/decision", record_b.id))
        .header("cookie", format!("mesh_lighthouse_admin={cookie_a}"))
        .header("x-csrf-token", &csrf_a)
        .json(&json!({"decision":"approve"}))
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), reqwest::StatusCode::FORBIDDEN);

    let missing_intent = client
        .post(format!("{base}/login/exchange"))
        .header("origin", origin)
        .json(&json!({"code":"not-a-real-code"}))
        .send()
        .await
        .unwrap();
    assert_eq!(missing_intent.status(), reqwest::StatusCode::FORBIDDEN);
    let logout_missing_csrf = client
        .post(format!("{base}/logout"))
        .header("origin", origin)
        .header("cookie", format!("mesh_lighthouse_admin={cookie_a}"))
        .send()
        .await
        .unwrap();
    assert_eq!(logout_missing_csrf.status(), reqwest::StatusCode::FORBIDDEN);
    assert_eq!(
        client
            .get(format!("{base}/session"))
            .header("cookie", format!("mesh_lighthouse_admin={cookie_a}"))
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::OK
    );
    let logout = client
        .post(format!("{base}/logout"))
        .header("origin", origin)
        .header("cookie", format!("mesh_lighthouse_admin={cookie_a}"))
        .header("x-csrf-token", &csrf_a)
        .send()
        .await
        .unwrap();
    assert_eq!(logout.status(), reqwest::StatusCode::NO_CONTENT);
    assert_eq!(
        client
            .get(format!("{base}/session"))
            .header("cookie", format!("mesh_lighthouse_admin={cookie_a}"))
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::FORBIDDEN
    );

    server.abort();
    let _ = csrf_b;
}

fn provision_commit_from_ids(workspace_ids: &[&str], future_boards: bool) -> ProvisioningCommit {
    ProvisioningCommit {
        pairing_id: "pairing-owner-a".into(),
        operation_id: "operation-owner-a".into(),
        transcript_hash: "transcript".into(),
        invitation_id: "invitation".into(),
        workspace_ids: workspace_ids.iter().map(|id| (*id).into()).collect(),
        snapshot_hash: "snapshot".into(),
        future_boards,
        controller_person_id: Some("owner-a".into()),
    }
}
