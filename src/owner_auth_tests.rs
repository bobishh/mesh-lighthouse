use super::*;
use meta_mesh_core::{DeviceCertificatePayload, public_key_from_seed, sign_device_certificate};
use serde_json::json;

const OPERATOR_SECRET: &str = "owner-auth-test-operator-token-long-enough";

fn test_peer(
    name: &str,
    identity_seed: [u8; 32],
    device_seed: [u8; 32],
) -> (Value, PublicIdentity, String, Vec<DeviceCertificate>) {
    let identity_key = public_key_from_seed(&identity_seed).unwrap();
    let person_id = public_key_id(&identity_key).unwrap();
    let device_key = public_key_from_seed(&device_seed).unwrap();
    let device_id = public_key_id(&device_key).unwrap();
    let identity = PublicIdentity {
        person_id: person_id.clone(),
        public_key: identity_key.clone(),
        display_name: name.into(),
    };
    let cert = sign_device_certificate(
        &identity_seed,
        DeviceCertificatePayload {
            kind: "device-certificate".into(),
            version: 1,
            person_id,
            device_id: device_id.clone(),
            device_public_key: device_key,
            issuer_certificate_hash: None,
            can_enroll_devices: true,
        },
        &identity.person_id,
        "MATCH/1",
    )
    .unwrap();
    let peer = json!({
        "advertisement":{"payload":{"personId":identity.person_id,"deviceId":device_id,"deviceName":name}},
        "publicKey":identity.public_key,"certificates":[cert]
    });
    (peer, identity, device_id, vec![cert])
}

fn pairings() -> PairingService {
    let service_seed = [7; 32];
    let (peer, _, _, _) = test_peer("Lighthouse", [6; 32], service_seed);
    let directory =
        std::env::temp_dir().join(format!("lighthouse-owner-auth-{}", random_token(12)));
    let service = PairingService::open(
        directory,
        &peer,
        "https://keeper.example".into(),
        service_seed,
        OPERATOR_SECRET.into(),
    )
    .unwrap();
    service
}

fn proof(
    seed: &[u8; 32],
    identity: &PublicIdentity,
    device_id: &str,
    certificates: &[DeviceCertificate],
    challenge_id: &str,
    nonce: &str,
    issued_at: u64,
    expires_at: u64,
) -> ControllerRequest {
    let payload = json!({
        "kind":"lighthouse-login-proof","version":1,"protocolVersion":1,
        "challengeId":challenge_id,"challengeNonce":nonce,
        "servicePersonId": "placeholder", "serviceOrigin":"https://keeper.example",
        "controllerPersonId":identity.person_id,"controllerDeviceId":device_id,
        "operationId":URL_SAFE_NO_PAD.encode(random_token(24)),
        "issuedAt":issued_at,"expiresAt":expires_at,
    });
    ControllerRequest {
        identity: identity.clone(),
        device_id: device_id.into(),
        certificates: certificates.into(),
        signed: sign_json_envelope(seed, payload, device_id, CONTROL_DOMAIN).unwrap(),
    }
}

fn signed_proof(
    pairings: &PairingService,
    seed: &[u8; 32],
    identity: &PublicIdentity,
    device_id: &str,
    certificates: &[DeviceCertificate],
    challenge_id: &str,
    nonce: &str,
) -> ControllerRequest {
    let expires_at = pairings
        .state
        .lock()
        .unwrap()
        .login_challenges
        .get(challenge_id)
        .unwrap()
        .expires_at;
    let mut request = proof(
        seed,
        identity,
        device_id,
        certificates,
        challenge_id,
        nonce,
        now_seconds(),
        expires_at,
    );
    request.signed.payload["servicePersonId"] = json!(pairings.service_identity.person_id);
    request.signed =
        sign_json_envelope(seed, request.signed.payload, device_id, CONTROL_DOMAIN).unwrap();
    request
}

fn challenge_parts(pairings: &PairingService, id: &str) -> (String, String) {
    let envelope = pairings.login_challenge(id).unwrap();
    assert_eq!(envelope.payload["kind"], "lighthouse-login-challenge");
    (
        envelope.payload["challengeId"].as_str().unwrap().into(),
        envelope.payload["nonce"].as_str().unwrap().into(),
    )
}

#[test]
fn valid_identity_login_is_bound_to_intent_and_consumed_once_without_operator_rights() {
    let service = pairings();
    let owner_seed = [9; 32];
    let (match_peer, owner, device_id, certificates) = test_peer("Owner A", [8; 32], [9; 32]);
    let _ = match_peer;
    let (intent, challenge) = service.begin_login("https://match.example").unwrap();
    let (challenge_id, nonce) = challenge_parts(&service, &challenge.challenge_id);
    let proof = signed_proof(
        &service,
        &owner_seed,
        &owner,
        &device_id,
        &certificates,
        &challenge_id,
        &nonce,
    );
    let replay = proof.clone();
    let result = service.prove_login(proof, &challenge_id).unwrap();
    assert!(
        result
            .redirect_url
            .starts_with("https://keeper.example/admin/#login=")
    );
    assert!(service.prove_login(replay, &challenge_id).is_err());
    assert!(
        service
            .exchange_login(&result.code, "wrong-intent")
            .is_err()
    );
    let (cookie, session) = service.exchange_login(&result.code, &intent).unwrap();
    assert_eq!(session.person_id.as_deref(), Some(owner.person_id.as_str()));
    assert_eq!(session.display_name, "Owner A");
    assert!(!session.operator);
    assert!(
        service
            .require_operator(&cookie, Some(&session.csrf_token))
            .is_err()
    );
    assert!(service.exchange_login(&result.code, &intent).is_err());
}

#[test]
fn invalid_signature_nonce_and_expiry_do_not_consume_login_challenge() {
    let service = pairings();
    let owner_seed = [11; 32];
    let (_, owner, device_id, certificates) = test_peer("Owner B", [10; 32], [11; 32]);
    let (intent, challenge) = service.begin_login("https://match.example").unwrap();
    let (challenge_id, nonce) = challenge_parts(&service, &challenge.challenge_id);

    let mut forged = signed_proof(
        &service,
        &owner_seed,
        &owner,
        &device_id,
        &certificates,
        &challenge_id,
        &nonce,
    );
    forged.signed.signature = random_token(48);
    assert!(service.prove_login(forged, &challenge_id).is_err());

    let wrong_nonce = signed_proof(
        &service,
        &owner_seed,
        &owner,
        &device_id,
        &certificates,
        &challenge_id,
        "wrong-nonce",
    );
    assert!(service.prove_login(wrong_nonce, &challenge_id).is_err());

    let expired = proof(
        &owner_seed,
        &owner,
        &device_id,
        &certificates,
        &challenge_id,
        &nonce,
        now_seconds() - LOGIN_TTL_SECONDS - 1,
        now_seconds() - 1,
    );
    let mut expired = expired;
    expired.signed.payload["servicePersonId"] = json!(service.service_identity.person_id);
    expired.signed = sign_json_envelope(
        &owner_seed,
        expired.signed.payload,
        &device_id,
        CONTROL_DOMAIN,
    )
    .unwrap();
    assert!(matches!(
        service.prove_login(expired, &challenge_id),
        Err(PairingError::Expired)
    ));

    let valid = signed_proof(
        &service,
        &owner_seed,
        &owner,
        &device_id,
        &certificates,
        &challenge_id,
        &nonce,
    );
    let accepted = service.prove_login(valid, &challenge_id).unwrap();
    assert!(service.exchange_login(&accepted.code, &intent).is_ok());
}

#[test]
fn token_login_remains_operator_session() {
    let service = pairings();
    let (cookie, _) = service.login(OPERATOR_SECRET).unwrap();
    let session = service.admin_session(&cookie).unwrap();
    assert!(session.person_id.is_none());
    assert!(session.operator);
    assert!(
        service
            .require_operator(&cookie, Some(&session.csrf_token))
            .is_ok()
    );
}

#[test]
fn logout_requires_csrf_and_revokes_only_valid_session() {
    let service = pairings();
    let (cookie, csrf) = service.login(OPERATOR_SECRET).unwrap();
    assert!(service.logout(&cookie, "wrong-csrf").is_err());
    assert!(service.admin_session(&cookie).is_ok());
    service.logout(&cookie, &csrf).unwrap();
    assert!(service.admin_session(&cookie).is_err());
}

#[test]
fn expired_challenges_and_codes_cannot_be_used() {
    let service = pairings();
    let (_, owner, device_id, certificates) = test_peer("Owner C", [12; 32], [13; 32]);
    let (intent, challenge) = service.begin_login("https://match.example").unwrap();
    service
        .state
        .lock()
        .unwrap()
        .login_challenges
        .get_mut(&challenge.challenge_id)
        .unwrap()
        .expires_at = now_seconds() - 1;
    assert!(matches!(
        service.login_challenge(&challenge.challenge_id),
        Err(PairingError::NotFound)
    ));
    let mut expired_proof = proof(
        &[13; 32],
        &owner,
        &device_id,
        &certificates,
        &challenge.challenge_id,
        "expired",
        now_seconds(),
        now_seconds() + LOGIN_TTL_SECONDS,
    );
    expired_proof.signed.payload["servicePersonId"] = json!(service.service_identity.person_id);
    expired_proof.signed = sign_json_envelope(
        &[13; 32],
        expired_proof.signed.payload,
        &device_id,
        CONTROL_DOMAIN,
    )
    .unwrap();
    assert!(
        service
            .prove_login(expired_proof, &challenge.challenge_id)
            .is_err()
    );
    assert!(!intent.is_empty());

    let (intent, challenge) = service.begin_login("https://match.example").unwrap();
    let (_, nonce) = challenge_parts(&service, &challenge.challenge_id);
    let proof = signed_proof(
        &service,
        &[13; 32],
        &owner,
        &device_id,
        &certificates,
        &challenge.challenge_id,
        &nonce,
    );
    let accepted = service.prove_login(proof, &challenge.challenge_id).unwrap();
    service
        .state
        .lock()
        .unwrap()
        .login_codes
        .get_mut(&accepted.code)
        .unwrap()
        .expires_at = now_seconds() - 1;
    assert!(service.exchange_login(&accepted.code, &intent).is_err());
}

#[test]
fn proof_rejects_wrong_service_audience_and_spoofed_controller_identity_without_consuming_challenge()
 {
    let service = pairings();
    let (_, owner, device_id, certificates) = test_peer("Owner D", [14; 32], [15; 32]);
    let (_, challenge) = service.begin_login("https://match.example").unwrap();
    let (_, nonce) = challenge_parts(&service, &challenge.challenge_id);

    let mut audience = signed_proof(
        &service,
        &[15; 32],
        &owner,
        &device_id,
        &certificates,
        &challenge.challenge_id,
        &nonce,
    );
    audience.signed.payload["serviceOrigin"] = json!("https://attacker.example");
    audience.signed = sign_json_envelope(
        &[15; 32],
        audience.signed.payload,
        &device_id,
        CONTROL_DOMAIN,
    )
    .unwrap();
    assert!(
        service
            .prove_login(audience, &challenge.challenge_id)
            .is_err()
    );

    let mut spoofed = signed_proof(
        &service,
        &[15; 32],
        &owner,
        &device_id,
        &certificates,
        &challenge.challenge_id,
        &nonce,
    );
    spoofed.signed.payload["controllerPersonId"] = json!("other-person");
    spoofed.signed = sign_json_envelope(
        &[15; 32],
        spoofed.signed.payload,
        &device_id,
        CONTROL_DOMAIN,
    )
    .unwrap();
    assert!(
        service
            .prove_login(spoofed, &challenge.challenge_id)
            .is_err()
    );

    let overlong_expiry = service
        .state
        .lock()
        .unwrap()
        .login_challenges
        .get(&challenge.challenge_id)
        .unwrap()
        .expires_at
        + 1;
    let mut overlong = proof(
        &[15; 32],
        &owner,
        &device_id,
        &certificates,
        &challenge.challenge_id,
        &nonce,
        now_seconds(),
        overlong_expiry,
    );
    overlong.signed.payload["servicePersonId"] = json!(service.service_identity.person_id);
    overlong.signed = sign_json_envelope(
        &[15; 32],
        overlong.signed.payload,
        &device_id,
        CONTROL_DOMAIN,
    )
    .unwrap();
    assert!(matches!(
        service.prove_login(overlong, &challenge.challenge_id),
        Err(PairingError::Expired)
    ));

    assert!(
        service
            .prove_login(
                signed_proof(
                    &service,
                    &[15; 32],
                    &owner,
                    &device_id,
                    &certificates,
                    &challenge.challenge_id,
                    &nonce
                ),
                &challenge.challenge_id
            )
            .is_ok()
    );
}
