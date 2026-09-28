use std::{
    collections::HashMap,
    fs,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use meta_mesh_core::{
    DeviceCertificate, PublicIdentity, SignedEnvelope, canonicalize_json, public_key_id,
    sign_json_envelope, verify_device_certificate_chain, verify_signed_envelope,
};
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub const CONTROL_DOMAIN: &str = "MESH-LIGHTHOUSE/1";
const MAX_AGE_SECONDS: u64 = 600;
const MAX_SCOPES: usize = 16;

#[derive(Clone)]
pub struct PairingService {
    state: Arc<Mutex<PairingState>>,
    directory: Arc<PathBuf>,
    service_identity: PublicIdentity,
    service_device_id: String,
    service_seed: Arc<[u8; 32]>,
    origin: String,
    admin_secret: Arc<String>,
}

#[derive(Default, Serialize, Deserialize)]
struct PairingState {
    records: HashMap<String, PairingRecord>,
    #[serde(skip)]
    sessions: HashMap<String, AdminSession>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingRecord {
    pub id: String,
    pub expires_at: u64,
    pub created_at: u64,
    pub transcript_hash: String,
    pub comparison_code: String,
    pub operator_approved: Option<bool>,
    pub controller_approved: Option<bool>,
    pub controller_decision_operation: Option<String>,
    pub controller_decision_hash: Option<String>,
    pub controller: PublicIdentity,
    pub controller_device_id: String,
    pub controller_certificates: Vec<DeviceCertificate>,
    pub offer: Value,
    pub challenge: SignedEnvelope<Value>,
    pub last_operation_id: String,
}

#[derive(Clone)]
struct AdminSession {
    csrf: String,
    expires_at: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ControllerRequest {
    pub identity: PublicIdentity,
    pub device_id: String,
    pub certificates: Vec<DeviceCertificate>,
    pub signed: SignedEnvelope<Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginRequest {
    pub secret: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionResponse {
    pub csrf_token: String,
}

impl PairingService {
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        directory: PathBuf,
        peer: &Value,
        origin: String,
        service_seed: [u8; 32],
        admin_secret: String,
    ) -> Result<Self, String> {
        if admin_secret.len() < 24 {
            return Err("LIGHTHOUSE_ADMIN_TOKEN must contain at least 24 characters".into());
        }
        let payload = peer
            .pointer("/advertisement/payload")
            .or_else(|| peer.pointer("/payload"))
            .ok_or("Missing service identity")?;
        let identity = PublicIdentity {
            person_id: payload["personId"]
                .as_str()
                .ok_or("Missing personId")?
                .into(),
            public_key: peer["publicKey"]
                .as_str()
                .ok_or("Missing service public key")?
                .into(),
            display_name: payload["displayName"]
                .as_str()
                .unwrap_or("Lighthouse")
                .into(),
        };
        let device_id = payload["deviceId"]
            .as_str()
            .ok_or("Missing service deviceId")?
            .to_owned();
        let certificates: Vec<DeviceCertificate> =
            serde_json::from_value(peer["certificates"].clone())
                .map_err(|_| "Invalid service certificate chain")?;
        let device_public_key =
            verify_device_certificate_chain(&identity, &device_id, &certificates, "MATCH/1")?;
        if public_key_id(&device_public_key)? != device_id {
            return Err("Service signing seed does not match its device certificate".into());
        }
        fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
                .map_err(|error| error.to_string())?;
        }
        let store_path = directory.join("pairings.json");
        let state = if store_path.exists() {
            serde_json::from_slice(&fs::read(store_path).map_err(|error| error.to_string())?)
                .map_err(|_| "Invalid durable pairing state")?
        } else {
            PairingState::default()
        };
        Ok(Self {
            state: Arc::new(Mutex::new(state)),
            directory: Arc::new(directory),
            service_identity: identity,
            service_device_id: device_id,
            service_seed: Arc::new(service_seed),
            origin,
            admin_secret: Arc::new(admin_secret),
        })
    }

    pub fn create(&self, request: ControllerRequest) -> Result<PairingRecord, PairingError> {
        let now = now_seconds();
        self.verify_controller(&request)?;
        let payload = &request.signed.payload;
        validate_common(
            payload,
            "lighthouse-pairing-offer",
            &request,
            &self.service_identity,
            &self.origin,
            now,
        )?;
        let operation_id = string_field(payload, "operationId")?;
        let body = payload
            .get("body")
            .ok_or(PairingError::Invalid("Missing offer body"))?;
        if body
            .pointer("/policy/futureBoards")
            .and_then(Value::as_bool)
            != Some(false)
        {
            return Err(PairingError::Invalid(
                "Future-board authorization is not available",
            ));
        }
        let scopes = body
            .get("scopes")
            .and_then(Value::as_array)
            .ok_or(PairingError::Invalid("Missing scope list"))?;
        if scopes.is_empty() || scopes.len() > MAX_SCOPES {
            return Err(PairingError::Invalid("Select between 1 and 16 boards"));
        }
        let mut seen = std::collections::HashSet::new();
        for scope in scopes {
            let id = scope
                .get("workspaceId")
                .and_then(Value::as_str)
                .ok_or(PairingError::Invalid("Scope is missing workspaceId"))?;
            let title = scope
                .get("title")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let anchor = scope
                .get("genesisAnchor")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if id.is_empty()
                || id.len() > 256
                || title.trim().is_empty()
                || title.len() > 256
                || anchor.is_empty()
                || anchor.len() > 4096
                || !seen.insert(id)
                || scope.get("mode").and_then(Value::as_str) != Some("replicate")
            {
                return Err(PairingError::Invalid(
                    "Scopes must have unique IDs, genesis anchors and replicate mode",
                ));
            }
        }
        let canonical = canonicalize_json(payload)
            .map_err(|_| PairingError::Invalid("Invalid signed offer"))?;
        let transcript_hash = URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()));
        let mut state = self.state.lock().map_err(|_| PairingError::Unavailable)?;
        // Keep operation replay records through expiry plus the bounded clock skew.
        state
            .records
            .retain(|_, record| record.expires_at.saturating_add(30) > now);
        if let Some(existing) = state
            .records
            .values()
            .find(|record| record.last_operation_id == operation_id)
        {
            return if existing.transcript_hash == transcript_hash {
                Ok(existing.clone())
            } else {
                Err(PairingError::Conflict)
            };
        }
        if state
            .records
            .values()
            .filter(|record| record.expires_at > now)
            .count()
            >= 100
        {
            return Err(PairingError::Unavailable);
        }
        let id = random_token(16);
        let nonce = random_token(32);
        let expires_at = now.saturating_add(MAX_AGE_SECONDS);
        let challenge_payload = json!({
            "kind": "lighthouse-pairing-challenge", "version": 1,
            "pairingId": id, "transcriptHash": transcript_hash,
            "servicePersonId": self.service_identity.person_id,
            "serviceDeviceId": self.service_device_id,
            "serviceOrigin": self.origin, "nonce": nonce,
            "integrationId": random_token(16), "issuedAt": now, "expiresAt": expires_at,
        });
        let challenge = sign_json_envelope(
            &self.service_seed,
            challenge_payload,
            &self.service_device_id,
            CONTROL_DOMAIN,
        )
        .map_err(|_| PairingError::Unavailable)?;
        let comparison_code = comparison_code(
            &payload.clone(),
            &serde_json::to_value(&challenge).unwrap_or(Value::Null),
        );
        let record = PairingRecord {
            id,
            expires_at,
            created_at: now,
            transcript_hash,
            comparison_code,
            operator_approved: None,
            controller_approved: None,
            controller_decision_operation: None,
            controller_decision_hash: None,
            controller: request.identity,
            controller_device_id: request.device_id,
            controller_certificates: request.certificates,
            offer: payload.clone(),
            challenge,
            last_operation_id: operation_id.to_owned(),
        };
        state.records.insert(record.id.clone(), record.clone());
        self.persist(&state)?;
        Ok(record)
    }

    pub fn controller_decision(
        &self,
        id: &str,
        request: ControllerRequest,
    ) -> Result<PairingRecord, PairingError> {
        let _ = self.verify_controller(&request)?;
        let now = now_seconds();
        let mut state = self.state.lock().map_err(|_| PairingError::Unavailable)?;
        let record = state.records.get_mut(id).ok_or(PairingError::NotFound)?;
        if record.expires_at <= now {
            return Err(PairingError::Expired);
        }
        if request.identity.person_id != record.controller.person_id
            || request.device_id != record.controller_device_id
        {
            return Err(PairingError::Forbidden);
        }
        let payload = &request.signed.payload;
        validate_common(
            payload,
            "lighthouse-pairing-decision",
            &request,
            &self.service_identity,
            &self.origin,
            now,
        )?;
        if payload["kind"] != "lighthouse-pairing-decision"
            || payload["pairingId"] != id
            || payload["transcriptHash"] != record.transcript_hash
            || payload["challengeNonce"] != record.challenge.payload["nonce"]
            || !matches!(payload["decision"].as_str(), Some("approve" | "decline"))
            || payload["issuedAt"]
                .as_u64()
                .is_none_or(|v| v > now + 30 || now.saturating_sub(v) > MAX_AGE_SECONDS)
        {
            return Err(PairingError::Invalid(
                "Decision is not bound to this pairing transcript",
            ));
        }
        let approved = payload["decision"] == "approve";
        let operation_id = string_field(payload, "operationId")?;
        let decision_hash = URL_SAFE_NO_PAD.encode(Sha256::digest(
            canonicalize_json(payload)
                .map_err(|_| PairingError::Invalid("Invalid decision payload"))?
                .as_bytes(),
        ));
        if record.controller_decision_operation.as_deref() == Some(operation_id) {
            return if record.controller_decision_hash.as_deref() == Some(&decision_hash) {
                Ok(record.clone())
            } else {
                Err(PairingError::Conflict)
            };
        }
        if record.controller_decision_operation.is_some() {
            return Err(PairingError::Conflict);
        }
        if record
            .controller_approved
            .is_some_and(|previous| previous != approved)
        {
            return Err(PairingError::Conflict);
        }
        record.controller_approved = Some(approved);
        record.controller_decision_operation = Some(operation_id.to_owned());
        record.controller_decision_hash = Some(decision_hash);
        if !approved {
            record.operator_approved = Some(false);
        }
        let result = record.clone();
        self.persist(&state)?;
        Ok(result)
    }

    pub fn status(
        &self,
        id: &str,
        request: ControllerRequest,
    ) -> Result<SignedEnvelope<Value>, PairingError> {
        let _ = self.verify_controller(&request)?;
        let now = now_seconds();
        let mut state = self.state.lock().map_err(|_| PairingError::Unavailable)?;
        let record = state.records.get_mut(id).ok_or(PairingError::NotFound)?;
        if record.expires_at <= now {
            self.persist(&state)?;
            return Err(PairingError::Expired);
        }
        validate_common(
            &request.signed.payload,
            "lighthouse-pairing-status",
            &request,
            &self.service_identity,
            &self.origin,
            now,
        )?;
        if request.identity.person_id != record.controller.person_id
            || request.device_id != record.controller_device_id
        {
            return Err(PairingError::Forbidden);
        }
        if request.signed.payload["kind"] != "lighthouse-pairing-status"
            || request.signed.payload["pairingId"] != id
            || request.signed.payload["transcriptHash"] != record.transcript_hash
        {
            return Err(PairingError::Invalid(
                "Status request does not match pairing",
            ));
        }
        let status = if record.controller_approved == Some(false)
            || record.operator_approved == Some(false)
        {
            "rejected"
        } else if record.controller_approved == Some(true) && record.operator_approved == Some(true)
        {
            "approved"
        } else {
            "pending"
        };
        sign_json_envelope(&self.service_seed, json!({
            "kind":"lighthouse-pairing-status", "version":1, "pairingId":id,
            "transcriptHash":record.transcript_hash, "servicePersonId":self.service_identity.person_id,
            "serviceDeviceId":self.service_device_id, "serviceOrigin":self.origin,
            "expiresAt":record.expires_at, "operatorApproved":record.operator_approved,
            "controllerApproved":record.controller_approved, "status":status,
            "provisioning":false, "issuedAt":now,
        }), &self.service_device_id, CONTROL_DOMAIN).map_err(|_| PairingError::Unavailable)
    }

    pub fn login(&self, secret: &str) -> Result<(String, String), PairingError> {
        if !constant_time_eq(secret.as_bytes(), self.admin_secret.as_bytes()) {
            return Err(PairingError::Forbidden);
        }
        let cookie = random_token(32);
        let csrf = random_token(32);
        let mut state = self.state.lock().map_err(|_| PairingError::Unavailable)?;
        state.sessions.insert(
            cookie.clone(),
            AdminSession {
                csrf: csrf.clone(),
                expires_at: now_seconds() + 8 * 60 * 60,
            },
        );
        Ok((cookie, csrf))
    }

    pub fn service_fingerprint(&self) -> String {
        public_key_fingerprint(&self.service_identity.public_key)
    }

    pub fn fingerprint(public_key: &str) -> String {
        public_key_fingerprint(public_key)
    }

    pub fn admin_list(&self, cookie: &str) -> Result<Vec<PairingRecord>, PairingError> {
        let mut state = self.state.lock().map_err(|_| PairingError::Unavailable)?;
        self.require_session(&mut state, cookie, None)?;
        Ok(state
            .records
            .values()
            .filter(|record| record.expires_at > now_seconds())
            .cloned()
            .collect())
    }

    pub fn admin_decision(
        &self,
        id: &str,
        cookie: &str,
        csrf: &str,
        decision: bool,
    ) -> Result<PairingRecord, PairingError> {
        let mut state = self.state.lock().map_err(|_| PairingError::Unavailable)?;
        self.require_session(&mut state, cookie, Some(csrf))?;
        let record = state.records.get_mut(id).ok_or(PairingError::NotFound)?;
        if record.expires_at <= now_seconds() {
            return Err(PairingError::Expired);
        }
        if record.controller_approved == Some(false) {
            return Err(PairingError::Conflict);
        }
        if record
            .operator_approved
            .is_some_and(|previous| previous != decision)
        {
            return Err(PairingError::Conflict);
        }
        record.operator_approved = Some(decision);
        if !decision {
            record.controller_approved = Some(false);
        }
        let result = record.clone();
        self.persist(&state)?;
        Ok(result)
    }

    pub fn status_json(&self, id: &str) -> Result<Value, PairingError> {
        let state = self.state.lock().map_err(|_| PairingError::Unavailable)?;
        let record = state.records.get(id).ok_or(PairingError::NotFound)?;
        let status = if record.expires_at <= now_seconds() {
            "expired"
        } else if record.controller_approved == Some(false)
            || record.operator_approved == Some(false)
        {
            "rejected"
        } else if record.controller_approved == Some(true) && record.operator_approved == Some(true)
        {
            "approved"
        } else {
            "pending"
        };
        Ok(
            json!({ "id":record.id, "status":status, "expiresAt":record.expires_at, "controllerApproved":record.controller_approved, "operatorApproved":record.operator_approved }),
        )
    }

    fn verify_controller(&self, request: &ControllerRequest) -> Result<String, PairingError> {
        if request.certificates.len() > 32 {
            return Err(PairingError::Invalid("Invalid certificate chain"));
        }
        let key = verify_device_certificate_chain(
            &request.identity,
            &request.device_id,
            &request.certificates,
            "MATCH/1",
        )
        .map_err(|_| PairingError::Forbidden)?;
        if request.signed.signer_key_id != request.device_id
            || !verify_signed_envelope(&request.signed, &key, CONTROL_DOMAIN)
                .map_err(|_| PairingError::Forbidden)?
        {
            return Err(PairingError::Forbidden);
        }
        Ok(key)
    }

    fn require_session(
        &self,
        state: &mut PairingState,
        cookie: &str,
        csrf: Option<&str>,
    ) -> Result<(), PairingError> {
        let now = now_seconds();
        state.sessions.retain(|_, session| session.expires_at > now);
        let session = state.sessions.get(cookie).ok_or(PairingError::Forbidden)?;
        if let Some(csrf) = csrf {
            if !constant_time_eq(csrf.as_bytes(), session.csrf.as_bytes()) {
                return Err(PairingError::Forbidden);
            }
        }
        Ok(())
    }

    fn persist(&self, state: &PairingState) -> Result<(), PairingError> {
        let path = self.directory.join("pairings.json");
        let temporary = self.directory.join("pairings.json.tmp");
        let bytes = serde_json::to_vec(state).map_err(|_| PairingError::Unavailable)?;
        use std::io::Write;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&temporary)
            .map_err(|_| PairingError::Unavailable)?;
        file.write_all(&bytes)
            .map_err(|_| PairingError::Unavailable)?;
        file.sync_all().map_err(|_| PairingError::Unavailable)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))
                .map_err(|_| PairingError::Unavailable)?;
        }
        fs::rename(temporary, path).map_err(|_| PairingError::Unavailable)?;
        fs::File::open(self.directory.as_ref())
            .and_then(|directory| directory.sync_all())
            .map_err(|_| PairingError::Unavailable)
    }
}

fn validate_common(
    payload: &Value,
    kind: &str,
    request: &ControllerRequest,
    service: &PublicIdentity,
    origin: &str,
    now: u64,
) -> Result<(), PairingError> {
    if payload["kind"] != kind
        || payload["version"] != 1
        || payload["protocolVersion"] != 1
        || payload["servicePersonId"] != service.person_id
        || payload["serviceOrigin"] != origin
        || payload["controllerPersonId"] != request.identity.person_id
        || payload["controllerDeviceId"] != request.device_id
    {
        return Err(PairingError::Invalid(
            "Signed request identity or origin mismatch",
        ));
    }
    let issued = payload["issuedAt"]
        .as_u64()
        .ok_or(PairingError::Invalid("Missing issuedAt"))?;
    let expires = payload["expiresAt"]
        .as_u64()
        .ok_or(PairingError::Invalid("Missing expiresAt"))?;
    if issued > now + 30
        || now.saturating_sub(issued) > MAX_AGE_SECONDS
        || expires <= now
        || expires > issued + MAX_AGE_SECONDS
    {
        return Err(PairingError::Expired);
    }
    let operation = string_field(payload, "operationId")?;
    if operation.len() > 128
        || URL_SAFE_NO_PAD
            .decode(operation)
            .map_or(true, |bytes| bytes.len() < 16)
    {
        return Err(PairingError::Invalid(
            "operationId must contain at least 128 bits of randomness",
        ));
    }
    Ok(())
}

fn string_field<'a>(payload: &'a Value, field: &str) -> Result<&'a str, PairingError> {
    payload[field]
        .as_str()
        .filter(|value| !value.is_empty())
        .ok_or(PairingError::Invalid("Missing required field"))
}

fn comparison_code(offer: &Value, challenge: &Value) -> String {
    let transcript = canonicalize_json(
        &json!({"domain":"MESH-LIGHTHOUSE-COMPARISON/1", "offer":offer, "challenge":challenge}),
    )
    .unwrap_or_default();
    let bytes = Sha256::digest(transcript.as_bytes());
    let value = u32::from_be_bytes(bytes[..4].try_into().unwrap_or([0; 4])) % 1_000_000;
    format!("{value:06}")
}

fn public_key_fingerprint(public_key: &str) -> String {
    Sha256::digest(public_key.as_bytes())[..12]
        .chunks(2)
        .map(|bytes| format!("{:02x}{:02x}", bytes[0], bytes[1]))
        .collect::<Vec<_>>()
        .join(":")
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn random_token(length: usize) -> String {
    let mut bytes = vec![0; length];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0_u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[derive(Debug, Clone, Copy)]
pub enum PairingError {
    Invalid(&'static str),
    Forbidden,
    NotFound,
    Expired,
    Conflict,
    Unavailable,
}

impl PairingError {
    pub fn code(self) -> &'static str {
        match self {
            Self::Invalid(_) => "invalid_request",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not_found",
            Self::Expired => "expired",
            Self::Conflict => "operation_conflict",
            Self::Unavailable => "unavailable",
        }
    }
    pub fn message(self) -> &'static str {
        match self {
            Self::Invalid(message) => message,
            Self::Forbidden => "Approval is not authorized",
            Self::NotFound => "Pairing was not found",
            Self::Expired => "Pairing has expired",
            Self::Conflict => "Pairing state or operation conflicts with a prior request",
            Self::Unavailable => "Pairing service is temporarily unavailable",
        }
    }
    pub fn status(self) -> axum::http::StatusCode {
        match self {
            Self::Invalid(_) => axum::http::StatusCode::BAD_REQUEST,
            Self::Forbidden => axum::http::StatusCode::FORBIDDEN,
            Self::NotFound => axum::http::StatusCode::NOT_FOUND,
            Self::Expired => axum::http::StatusCode::GONE,
            Self::Conflict => axum::http::StatusCode::CONFLICT,
            Self::Unavailable => axum::http::StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}
