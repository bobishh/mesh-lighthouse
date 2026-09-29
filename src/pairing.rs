use std::{
    collections::HashMap,
    fs,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use meta_mesh_core::{
    DeviceCertificate, PublicIdentity, SignedEnvelope, WorkspaceJoinInvitation, canonicalize_json,
    public_key_id, sign_json_envelope, verify_device_certificate_chain, verify_signed_envelope,
};
use meta_mesh_native::FileScopeStore;
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[cfg(test)]
#[path = "owner_auth_tests.rs"]
mod owner_auth_tests;

use crate::ProvisioningCommit;

pub const CONTROL_DOMAIN: &str = "MESH-LIGHTHOUSE/1";
const MAX_AGE_SECONDS: u64 = 600;
const LOGIN_TTL_SECONDS: u64 = 5 * 60;
const MAX_PENDING_LOGINS: usize = 128;
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
    provisioning_runs: Arc<Mutex<std::collections::HashSet<String>>>,
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct PairingState {
    records: HashMap<String, PairingRecord>,
    #[serde(skip)]
    sessions: HashMap<String, AdminSession>,
    #[serde(skip)]
    login_challenges: HashMap<String, LoginChallenge>,
    #[serde(skip)]
    login_codes: HashMap<String, LoginCode>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provisioning: Option<ProvisioningRecord>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProvisioningRecord {
    pub operation_id: String,
    pub request_hash: String,
    pub status: String,
    pub scopes: Vec<ProvisionedScope>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProvisionedScope {
    pub workspace_id: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub struct ProvisionRequest {
    pub invitation: WorkspaceJoinInvitation,
    pub scopes: Vec<String>,
    pub operation_id: String,
    pub transcript_hash: String,
    pub future_boards: bool,
    pub should_run: bool,
}

#[derive(Clone)]
struct AdminSession {
    csrf: String,
    expires_at: u64,
    person_id: Option<String>,
    display_name: String,
    operator: bool,
}

#[derive(Clone)]
struct LoginChallenge {
    nonce: String,
    intent_cookie: String,
    expires_at: u64,
}

#[derive(Clone)]
struct LoginCode {
    person_id: String,
    display_name: String,
    intent_cookie: String,
    expires_at: u64,
}

#[derive(Clone, Deserialize)]
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginExchangeRequest {
    pub code: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionResponse {
    pub csrf_token: String,
    pub person_id: Option<String>,
    pub display_name: String,
    pub operator: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginChallengeResponse {
    pub challenge_id: String,
    pub match_url: String,
    pub expires_at: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginProofResponse {
    pub code: String,
    pub redirect_url: String,
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
            provisioning_runs: Arc::new(Mutex::new(std::collections::HashSet::new())),
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
            .is_none()
        {
            return Err(PairingError::Invalid("Missing future-board policy"));
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
            provisioning: None,
        };
        let mut next = state.clone();
        next.records.insert(record.id.clone(), record.clone());
        self.persist(&next)?;
        *state = next;
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
        let record = state.records.get(id).ok_or(PairingError::NotFound)?;
        if record.expires_at <= now
            && record
                .provisioning
                .as_ref()
                .map(|provisioning| provisioning.status.as_str())
                != Some("active")
        {
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
        let mut next = state.clone();
        let record = next.records.get_mut(id).ok_or(PairingError::NotFound)?;
        record.controller_approved = Some(approved);
        record.controller_decision_operation = Some(operation_id.to_owned());
        record.controller_decision_hash = Some(decision_hash);
        if !approved {
            record.operator_approved = Some(false);
        }
        let result = record.clone();
        self.persist(&next)?;
        *state = next;
        Ok(result)
    }

    /// Admit only an ordinary workspace invitation for the exact dual-approved
    /// service identity and scope set. The invitation secret stays out of every
    /// durable pairing record and status response.
    pub fn begin_provision(
        &self,
        id: &str,
        request: ControllerRequest,
    ) -> Result<ProvisionRequest, PairingError> {
        let device_key = self.verify_controller(&request)?;
        let now = now_seconds();
        let payload = &request.signed.payload;
        validate_common(
            payload,
            "lighthouse-pairing-provision",
            &request,
            &self.service_identity,
            &self.origin,
            now,
        )?;
        let operation_id = string_field(payload, "operationId")?.to_owned();
        let body = payload
            .get("body")
            .and_then(Value::as_object)
            .ok_or(PairingError::Invalid("Missing provisioning body"))?;
        let future_boards = body
            .get("futureBoards")
            .and_then(Value::as_bool)
            .ok_or(PairingError::Invalid("Missing future-board policy"))?;
        if body.get("pairingId").and_then(Value::as_str) != Some(id)
            || body.get("transcriptHash").and_then(Value::as_str).is_none()
            || body.get("servicePersonId").and_then(Value::as_str)
                != Some(self.service_identity.person_id.as_str())
        {
            return Err(PairingError::Invalid(
                "Provision request is not bound to this service and pairing",
            ));
        }
        let approved = body
            .get("approvedScopes")
            .and_then(Value::as_array)
            .ok_or(PairingError::Invalid("Missing approved scope list"))?;
        let request_hash = URL_SAFE_NO_PAD.encode(Sha256::digest(
            canonicalize_json(payload)
                .map_err(|_| PairingError::Invalid("Invalid provisioning request"))?
                .as_bytes(),
        ));

        let mut state = self.state.lock().map_err(|_| PairingError::Unavailable)?;
        let record = state.records.get(id).ok_or(PairingError::NotFound)?;
        if record.expires_at <= now {
            return Err(PairingError::Expired);
        }
        if request.identity.person_id != record.controller.person_id
            || request.device_id != record.controller_device_id
            || body.get("transcriptHash").and_then(Value::as_str)
                != Some(record.transcript_hash.as_str())
        {
            return Err(PairingError::Forbidden);
        }
        if record.controller_approved != Some(true) || record.operator_approved != Some(true) {
            return Err(PairingError::Forbidden);
        }
        if record
            .offer
            .pointer("/body/policy/futureBoards")
            .and_then(Value::as_bool)
            != Some(future_boards)
        {
            return Err(PairingError::Invalid(
                "Provision future-board policy differs from signed offer",
            ));
        }
        let transcript_hash = record.transcript_hash.clone();
        let invitation: WorkspaceJoinInvitation = serde_json::from_value(
            body.get("invitation")
                .cloned()
                .ok_or(PairingError::Invalid("Missing workspace invitation"))?,
        )
        .map_err(|_| PairingError::Invalid("Invalid workspace invitation"))?;
        let offered = record.offer["body"]["scopes"]
            .as_array()
            .ok_or(PairingError::Invalid("Pairing has no approved scopes"))?;
        let mut scope_ids = Vec::with_capacity(offered.len());
        for (index, scope) in offered.iter().enumerate() {
            let workspace_id = scope["workspaceId"]
                .as_str()
                .filter(|value| !value.is_empty())
                .ok_or(PairingError::Invalid("Invalid approved scope"))?;
            if scope["mode"] != "replicate"
                || approved.get(index).is_none_or(|entry| {
                    entry["workspaceId"] != workspace_id || entry["mode"] != "replicate"
                })
            {
                return Err(PairingError::Invalid(
                    "Provision scopes differ from the approved transcript",
                ));
            }
            scope_ids.push(workspace_id.to_owned());
        }
        if approved.len() != scope_ids.len()
            || invitation.kind != "workspace-join"
            || invitation.version != 1
            || invitation.issuer_person_id != request.identity.person_id
            || invitation.issuer_device_id != request.device_id
            || invitation.issuer_public_key != device_key
            || invitation.role != "visitor"
            || invitation.secret.len() < 32
            || invitation
                .workspaces
                .iter()
                .map(|scope| scope.id.clone())
                .collect::<Vec<_>>()
                != scope_ids
            || invitation.workspace_id != scope_ids.first().cloned().unwrap_or_default()
            || invitation.invitation_id.is_empty()
            || invitation.issuer_endpoint.is_empty()
            || invitation.expires_at.is_empty()
        {
            return Err(PairingError::Invalid(
                "Invitation does not match the approved owner and scopes",
            ));
        }
        let created_at = time::OffsetDateTime::parse(
            &invitation.created_at,
            &time::format_description::well_known::Rfc3339,
        )
        .map_err(|_| PairingError::Invalid("Invalid invitation creation time"))?;
        let expires_at = time::OffsetDateTime::parse(
            &invitation.expires_at,
            &time::format_description::well_known::Rfc3339,
        )
        .map_err(|_| PairingError::Invalid("Invalid invitation expiry"))?;
        let now = time::OffsetDateTime::now_utc();
        if created_at > now + time::Duration::seconds(30)
            || expires_at <= now
            || expires_at <= created_at
            || expires_at - created_at > time::Duration::minutes(10)
        {
            return Err(PairingError::Invalid(
                "Invitation must be valid and expire within 10 minutes",
            ));
        }
        if let Some(previous) = &record.provisioning {
            if previous.operation_id != operation_id || previous.request_hash != request_hash {
                return Err(PairingError::Conflict);
            }
            if previous.status == "active" {
                return Ok(ProvisionRequest {
                    invitation,
                    scopes: scope_ids,
                    operation_id,
                    transcript_hash,
                    future_boards,
                    should_run: false,
                });
            }
        } else {
            let mut next = state.clone();
            next.records
                .get_mut(id)
                .ok_or(PairingError::NotFound)?
                .provisioning = Some(ProvisioningRecord {
                operation_id: operation_id.clone(),
                request_hash: request_hash.clone(),
                status: "provisioning".into(),
                scopes: scope_ids
                    .iter()
                    .map(|workspace_id| ProvisionedScope {
                        workspace_id: workspace_id.clone(),
                        status: "pending".into(),
                        error: None,
                    })
                    .collect(),
            });
            self.persist(&next)?;
            *state = next;
        }
        drop(state);
        let mut running = self
            .provisioning_runs
            .lock()
            .map_err(|_| PairingError::Unavailable)?;
        let should_run = running.insert(id.to_owned());
        Ok(ProvisionRequest {
            invitation,
            scopes: scope_ids,
            operation_id,
            transcript_hash,
            future_boards,
            should_run,
        })
    }

    pub fn complete_provision(
        &self,
        id: &str,
        scopes: Vec<ProvisionedScope>,
        active: bool,
    ) -> Result<(), PairingError> {
        let mut state = self.state.lock().map_err(|_| PairingError::Unavailable)?;
        let mut next = state.clone();
        let provisioning = next
            .records
            .get_mut(id)
            .ok_or(PairingError::NotFound)?
            .provisioning
            .as_mut()
            .ok_or(PairingError::Conflict)?;
        if scopes.len() != provisioning.scopes.len()
            || scopes
                .iter()
                .zip(&provisioning.scopes)
                .any(|(actual, expected)| actual.workspace_id != expected.workspace_id)
            || (active
                && scopes
                    .iter()
                    .any(|scope| scope.status != "active" || scope.error.is_some()))
        {
            return Err(PairingError::Conflict);
        }
        provisioning.scopes = scopes;
        provisioning.status = if active { "active" } else { "provisioning" }.into();
        if let Err(error) = self.persist(&next) {
            self.provisioning_runs
                .lock()
                .map_err(|_| PairingError::Unavailable)?
                .remove(id);
            return Err(error);
        }
        *state = next;
        self.provisioning_runs
            .lock()
            .map_err(|_| PairingError::Unavailable)?
            .remove(id);
        Ok(())
    }

    pub fn complete_from_durable_activation(
        &self,
        id: &str,
        commit: &ProvisioningCommit,
    ) -> Result<(), PairingError> {
        let mut state = self.state.lock().map_err(|_| PairingError::Unavailable)?;
        let mut next = state.clone();
        let record = next.records.get_mut(id).ok_or(PairingError::NotFound)?;
        let provisioning = record.provisioning.as_mut().ok_or(PairingError::Conflict)?;
        let approved_future_boards = record
            .offer
            .pointer("/body/policy/futureBoards")
            .and_then(Value::as_bool);
        if commit.pairing_id != id
            || commit.operation_id != provisioning.operation_id
            || commit.transcript_hash != record.transcript_hash
            || commit.future_boards != approved_future_boards.unwrap_or(false)
            || commit.snapshot_hash.is_empty()
            || commit.workspace_ids
                != provisioning
                    .scopes
                    .iter()
                    .map(|scope| scope.workspace_id.clone())
                    .collect::<Vec<_>>()
        {
            return Err(PairingError::Conflict);
        }
        provisioning.status = "active".into();
        for scope in &mut provisioning.scopes {
            scope.status = "active".into();
            scope.error = None;
        }
        self.persist(&next)?;
        *state = next;
        Ok(())
    }

    pub fn status(
        &self,
        id: &str,
        request: ControllerRequest,
    ) -> Result<SignedEnvelope<Value>, PairingError> {
        let _ = self.verify_controller(&request)?;
        let now = now_seconds();
        let state = self.state.lock().map_err(|_| PairingError::Unavailable)?;
        let record = state.records.get(id).ok_or(PairingError::NotFound)?;
        if record.expires_at <= now {
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
        self.sign_status_record(record)
    }

    pub fn signed_provision_status(&self, id: &str) -> Result<SignedEnvelope<Value>, PairingError> {
        let state = self.state.lock().map_err(|_| PairingError::Unavailable)?;
        let record = state.records.get(id).ok_or(PairingError::NotFound)?;
        self.sign_status_record(record)
    }

    fn sign_status_record(
        &self,
        record: &PairingRecord,
    ) -> Result<SignedEnvelope<Value>, PairingError> {
        let now = now_seconds();
        let approval_status = if record.controller_approved == Some(false)
            || record.operator_approved == Some(false)
        {
            "rejected"
        } else if record.controller_approved == Some(true) && record.operator_approved == Some(true)
        {
            "approved"
        } else {
            "pending"
        };
        let status = record
            .provisioning
            .as_ref()
            .map(|provisioning| provisioning.status.as_str())
            .unwrap_or(approval_status);
        let provisioning = record
            .provisioning
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(|_| PairingError::Unavailable)?
            .unwrap_or(Value::Bool(false));
        sign_json_envelope(&self.service_seed, json!({
            "kind":"lighthouse-pairing-status", "version":1, "pairingId":record.id,
            "transcriptHash":record.transcript_hash, "servicePersonId":self.service_identity.person_id,
            "serviceDeviceId":self.service_device_id, "serviceOrigin":self.origin,
            "expiresAt":record.expires_at, "operatorApproved":record.operator_approved,
            "controllerApproved":record.controller_approved, "status":status,
            "provisioning":provisioning, "issuedAt":now,
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
                person_id: None,
                display_name: "Operator".into(),
                operator: true,
            },
        );
        Ok((cookie, csrf))
    }

    pub fn begin_login(
        &self,
        match_origin: &str,
    ) -> Result<(String, LoginChallengeResponse), PairingError> {
        let now = now_seconds();
        let challenge_id = random_token(24);
        let nonce = random_token(32);
        let intent_cookie = random_token(32);
        let expires_at = now + LOGIN_TTL_SECONDS;
        let mut url = reqwest::Url::parse(match_origin)
            .map_err(|_| PairingError::Invalid("Invalid Match origin"))?;
        if url.origin().ascii_serialization() != match_origin
            || !matches!(url.scheme(), "https" | "http")
        {
            return Err(PairingError::Invalid("Invalid Match origin"));
        }
        url.set_path("/login");
        url.set_query(None);
        url.set_fragment(None);
        url.query_pairs_mut()
            .append_pair("keeper", &self.origin)
            .append_pair("challenge", &challenge_id);
        let mut state = self.state.lock().map_err(|_| PairingError::Unavailable)?;
        prune_login_state(&mut state, now);
        if state.login_challenges.len() + state.login_codes.len() >= MAX_PENDING_LOGINS {
            return Err(PairingError::Unavailable);
        }
        state.login_challenges.insert(
            challenge_id.clone(),
            LoginChallenge {
                nonce,
                intent_cookie: intent_cookie.clone(),
                expires_at,
            },
        );
        Ok((
            intent_cookie,
            LoginChallengeResponse {
                challenge_id,
                match_url: url.to_string(),
                expires_at,
            },
        ))
    }

    pub fn login_challenge(&self, id: &str) -> Result<SignedEnvelope<Value>, PairingError> {
        let mut state = self.state.lock().map_err(|_| PairingError::Unavailable)?;
        prune_login_state(&mut state, now_seconds());
        let challenge = state
            .login_challenges
            .get(id)
            .ok_or(PairingError::NotFound)?;
        let now = now_seconds();
        let expires_at = challenge.expires_at;
        let nonce = challenge.nonce.clone();
        sign_json_envelope(
            &self.service_seed,
            json!({
                "kind":"lighthouse-login-challenge", "version":1,
                "challengeId":id, "nonce":nonce,
                "servicePersonId":self.service_identity.person_id,
                "serviceDeviceId":self.service_device_id, "serviceOrigin":self.origin,
                "issuedAt":now, "expiresAt":expires_at,
            }),
            &self.service_device_id,
            CONTROL_DOMAIN,
        )
        .map_err(|_| PairingError::Unavailable)
    }

    pub fn prove_login(
        &self,
        request: ControllerRequest,
        id: &str,
    ) -> Result<LoginProofResponse, PairingError> {
        let now = now_seconds();
        self.verify_controller(&request)?;
        let payload = &request.signed.payload;
        if payload["kind"] != "lighthouse-login-proof"
            || payload["version"] != 1
            || payload["protocolVersion"] != 1
            || payload["challengeId"] != id
            || payload["servicePersonId"] != self.service_identity.person_id
            || payload["serviceOrigin"] != self.origin
            || payload["controllerPersonId"] != request.identity.person_id
            || payload["controllerDeviceId"] != request.device_id
        {
            return Err(PairingError::Invalid(
                "Signed login proof identity or challenge mismatch",
            ));
        }
        let issued = payload["issuedAt"]
            .as_u64()
            .ok_or(PairingError::Invalid("Missing issuedAt"))?;
        let expires = payload["expiresAt"]
            .as_u64()
            .ok_or(PairingError::Invalid("Missing expiresAt"))?;
        let operation = string_field(payload, "operationId")?;
        if issued > now + 30
            || now.saturating_sub(issued) > LOGIN_TTL_SECONDS
            || expires <= now
            || expires > issued + LOGIN_TTL_SECONDS
            || operation.len() > 128
            || URL_SAFE_NO_PAD
                .decode(operation)
                .map_or(true, |bytes| bytes.len() < 16)
        {
            return Err(PairingError::Expired);
        }
        let mut state = self.state.lock().map_err(|_| PairingError::Unavailable)?;
        prune_login_state(&mut state, now);
        let challenge = state
            .login_challenges
            .get(id)
            .ok_or(PairingError::NotFound)?;
        if challenge.expires_at <= now
            || expires > challenge.expires_at
            || payload["challengeNonce"] != challenge.nonce
        {
            return Err(PairingError::Expired);
        }
        let intent_cookie = challenge.intent_cookie.clone();
        state.login_challenges.remove(id);
        let code = random_token(32);
        state.login_codes.insert(
            code.clone(),
            LoginCode {
                person_id: request.identity.person_id,
                display_name: request.identity.display_name,
                intent_cookie,
                expires_at: now + LOGIN_TTL_SECONDS,
            },
        );
        Ok(LoginProofResponse {
            code: code.clone(),
            redirect_url: format!("{}/admin/#login={code}", self.origin),
        })
    }

    pub fn exchange_login(
        &self,
        code: &str,
        intent_cookie: &str,
    ) -> Result<(String, SessionResponse), PairingError> {
        let now = now_seconds();
        let mut state = self.state.lock().map_err(|_| PairingError::Unavailable)?;
        prune_login_state(&mut state, now);
        let login = state.login_codes.get(code).ok_or(PairingError::Forbidden)?;
        if login.expires_at <= now
            || !constant_time_eq(login.intent_cookie.as_bytes(), intent_cookie.as_bytes())
        {
            return Err(PairingError::Forbidden);
        }
        let login = state
            .login_codes
            .remove(code)
            .ok_or(PairingError::Forbidden)?;
        let cookie = random_token(32);
        let csrf = random_token(32);
        let session = SessionResponse {
            csrf_token: csrf.clone(),
            person_id: Some(login.person_id.clone()),
            display_name: login.display_name.clone(),
            operator: false,
        };
        state.sessions.insert(
            cookie.clone(),
            AdminSession {
                csrf,
                expires_at: now + 8 * 60 * 60,
                person_id: Some(login.person_id),
                display_name: login.display_name,
                operator: false,
            },
        );
        Ok((cookie, session))
    }

    pub fn service_fingerprint(&self) -> String {
        public_key_fingerprint(&self.service_identity.public_key)
    }

    pub fn admin_session(&self, cookie: &str) -> Result<SessionResponse, PairingError> {
        let mut state = self.state.lock().map_err(|_| PairingError::Unavailable)?;
        self.require_session(&mut state, cookie, None)?;
        let session = state.sessions.get(cookie).ok_or(PairingError::Forbidden)?;
        Ok(SessionResponse {
            csrf_token: session.csrf.clone(),
            person_id: session.person_id.clone(),
            display_name: session.display_name.clone(),
            operator: session.operator,
        })
    }

    pub fn session_person_id(&self, cookie: &str) -> Result<Option<String>, PairingError> {
        let mut state = self.state.lock().map_err(|_| PairingError::Unavailable)?;
        self.require_session(&mut state, cookie, None)?;
        Ok(state
            .sessions
            .get(cookie)
            .and_then(|session| session.person_id.clone()))
    }

    pub fn logout(&self, cookie: &str, csrf: &str) -> Result<(), PairingError> {
        let mut state = self.state.lock().map_err(|_| PairingError::Unavailable)?;
        self.require_session(&mut state, cookie, Some(csrf))?;
        state.sessions.remove(cookie);
        Ok(())
    }

    pub fn require_operator(&self, cookie: &str, csrf: Option<&str>) -> Result<(), PairingError> {
        let mut state = self.state.lock().map_err(|_| PairingError::Unavailable)?;
        self.require_session(&mut state, cookie, csrf)?;
        if !state
            .sessions
            .get(cookie)
            .is_some_and(|session| session.operator)
        {
            return Err(PairingError::Forbidden);
        }
        Ok(())
    }

    pub fn fingerprint(public_key: &str) -> String {
        public_key_fingerprint(public_key)
    }

    pub fn admin_list(&self, cookie: &str) -> Result<Vec<PairingRecord>, PairingError> {
        let mut state = self.state.lock().map_err(|_| PairingError::Unavailable)?;
        self.require_session(&mut state, cookie, None)?;
        let owner = state
            .sessions
            .get(cookie)
            .and_then(|session| session.person_id.as_deref());
        Ok(state
            .records
            .values()
            .filter(|record| {
                owner.is_none_or(|person_id| record.controller.person_id == person_id)
                    && (record.expires_at > now_seconds()
                        || record
                            .provisioning
                            .as_ref()
                            .is_some_and(|provisioning| provisioning.status == "active"))
            })
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
        if !state
            .sessions
            .get(cookie)
            .is_some_and(|session| session.operator)
        {
            return Err(PairingError::Forbidden);
        }
        let record = state.records.get(id).ok_or(PairingError::NotFound)?;
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
        let mut next = state.clone();
        let record = next.records.get_mut(id).ok_or(PairingError::NotFound)?;
        record.operator_approved = Some(decision);
        if !decision {
            record.controller_approved = Some(false);
        }
        let result = record.clone();
        self.persist(&next)?;
        *state = next;
        Ok(result)
    }

    pub fn status_json(&self, id: &str) -> Result<Value, PairingError> {
        let state = self.state.lock().map_err(|_| PairingError::Unavailable)?;
        let record = state.records.get(id).ok_or(PairingError::NotFound)?;
        let approval_status = if record.expires_at <= now_seconds() {
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
        let status = record
            .provisioning
            .as_ref()
            .map(|provisioning| provisioning.status.as_str())
            .unwrap_or(approval_status);
        Ok(
            json!({ "id":record.id, "status":status, "expiresAt":record.expires_at, "controllerApproved":record.controller_approved, "operatorApproved":record.operator_approved, "provisioning":record.provisioning }),
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
        let bytes = serde_json::to_vec(state).map_err(|_| PairingError::Unavailable)?;
        FileScopeStore::new(self.directory.join("pairings.json"))
            .write_validated(&bytes, None, |_, _| Ok(()))
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
fn prune_login_state(state: &mut PairingState, now: u64) {
    state
        .login_challenges
        .retain(|_, challenge| challenge.expires_at > now);
    state.login_codes.retain(|_, code| code.expires_at > now);
    state.sessions.retain(|_, session| session.expires_at > now);
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
