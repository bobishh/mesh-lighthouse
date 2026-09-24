use std::{
    collections::BTreeSet,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use automerge::{
    ActorId, AutoCommit, AutoSerde, ObjId, ObjType, ROOT, ReadDoc,
    transaction::{CommitOptions, Transactable},
};
use match_authority::{admit_match_candidate, prepare_match_write_authority};
use meta_mesh_core::{
    DEFAULT_SIGNATURE_DOMAIN, MeshHandshake, MeshPeerAdmission, VerifyWorkspaceMemberOptions,
    WorkspaceChangeAuthorizationPayload, WorkspaceWriteAuthorizationSnapshot,
    merge_verified_peer_catalog, sign_json_envelope, validate_mesh_catalog,
    verify_workspace_member_bundle,
};
use meta_mesh_native::{
    FileScopeStore, NativeScopeCredential, NativeScopeHost, NativeScopeServiceHost,
    NativeScopeSnapshot,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MatchLighthouseState {
    pub document: Vec<u8>,
    pub authorization: Value,
    #[serde(default = "empty_chat")]
    pub chat: Value,
    #[serde(default)]
    pub mesh: Option<Value>,
}

fn empty_chat() -> Value {
    json!({"version": 1, "messages": [], "profiles": [], "typing": []})
}

struct Inner {
    state: MatchLighthouseState,
    file: FileScopeStore,
}

#[derive(Clone)]
pub struct MatchScopeStore {
    workspace_id: String,
    genesis_person_id: String,
    inner: Arc<Mutex<Inner>>,
}

pub struct LeadDraft<'a> {
    pub id: &'a str,
    pub company: &'a str,
    pub role: &'a str,
    pub job_url: &'a str,
    pub body: &'a str,
}

impl MatchScopeStore {
    pub fn open(
        workspace_id: String,
        genesis_person_id: String,
        path: PathBuf,
        initial: MatchLighthouseState,
    ) -> Result<Self, String> {
        let file = FileScopeStore::new(path);
        let state = match file.read()? {
            Some(bytes) => serde_json::from_slice::<MatchLighthouseState>(&bytes)
                .map_err(|error| format!("Invalid lighthouse state: {error}"))?,
            None => initial,
        };
        let store = Self {
            workspace_id,
            genesis_person_id,
            inner: Arc::new(Mutex::new(Inner { state, file })),
        };
        {
            let guard = store
                .inner
                .lock()
                .map_err(|_| "Lighthouse state lock poisoned")?;
            store.authority_for(&guard.state)?;
            let mut current = AutoCommit::load(&guard.state.document)
                .map_err(|error| format!("Invalid lighthouse document: {error}"))?;
            let hashes = current
                .get_changes(&[])
                .iter()
                .map(|change| change.hash().to_string())
                .collect::<Vec<_>>();
            let (snapshot, _) = store.authority_for(&guard.state)?;
            admit_match_candidate(
                None,
                &guard.state.document,
                &hashes,
                Some(&guard.state.authorization),
                snapshot,
                now_ms()?,
            )?;
            if guard.file.read()?.is_none() {
                write_state(&guard.file, &guard.state)?;
            }
        }
        Ok(store)
    }

    pub fn authority(&self) -> Result<WorkspaceWriteAuthorizationSnapshot, String> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| "Lighthouse state lock poisoned")?;
        self.authority_for(&guard.state)
            .map(|(snapshot, _)| snapshot)
    }

    pub fn authorized_peer_endpoints(&self) -> Result<Vec<String>, String> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| "Lighthouse state lock poisoned")?;
        let mesh = verified_mesh_for(self, &guard.state)?;
        Ok(mesh
            .get("peers")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|peer| peer.pointer("/advertisement/payload/endpoint"))
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect())
    }

    /// Author one Match lead with the lighthouse's own editor credential.
    /// Call while the service is stopped; the running process owns its in-memory state.
    pub fn create_lead(
        &mut self,
        peer: &Value,
        device_seed: &[u8; 32],
        draft: LeadDraft<'_>,
    ) -> Result<String, String> {
        let lead_id = draft.id;
        let company = draft.company.trim();
        let role = draft.role.trim();
        let job_url = draft.job_url.trim();
        let body = draft.body;
        if company.is_empty()
            || role.is_empty()
            || job_url.is_empty()
            || company.len() > 256
            || role.len() > 256
            || job_url.len() > 2_048
            || body.len() > 8_500
            || !lead_id.starts_with("item-")
            || lead_id.len() > 80
        {
            return Err("Lead needs company, role, and job URL".into());
        }
        let authority = self.authority()?;
        let member = verify_workspace_member_bundle(
            peer.clone(),
            VerifyWorkspaceMemberOptions {
                workspace_id: Some(self.workspace_id.clone()),
                owner_person_id: Some(authority.expected_current_owner.person_id.clone()),
                owner_public_key: Some(authority.expected_current_owner.public_key.clone()),
                owner_certificates: authority.expected_current_owner.certificates.clone(),
                owner_history: vec![authority.genesis_owner.clone()],
                ..Default::default()
            },
            now_ms()?,
        )?;
        if member.role != meta_mesh_core::WorkspaceRole::Editor {
            return Err("Lighthouse needs an editor grant to create leads".into());
        }
        let state = self.snapshot()?;
        let mut document = AutoCommit::load(&state.document)
            .map_err(|error| format!("Invalid Match document: {error}"))?;
        document.set_actor(ActorId::from(member.payload.device_id.as_bytes().to_vec()));
        let view =
            serde_json::to_value(AutoSerde::from(&document)).map_err(|error| error.to_string())?;
        let entities = view
            .get("entities")
            .and_then(Value::as_object)
            .ok_or("Invalid Match entities")?;
        if entities.contains_key(lead_id) {
            return Ok(lead_id.to_owned());
        }
        let board = entities
            .values()
            .find(|entity| {
                entity.get("kind").and_then(Value::as_str) == Some("board")
                    && entity.pointer("/preset/key").and_then(Value::as_str) == Some("job-search")
            })
            .ok_or("No job-search board in workspace")?;
        let bindings = board
            .pointer("/preset/bindings")
            .and_then(Value::as_object)
            .ok_or("Missing job-search bindings")?;
        let binding = |key: &str| {
            bindings
                .get(key)
                .and_then(Value::as_str)
                .ok_or("Missing job-search binding")
        };
        let column_id = binding("status.lead")?;
        let company_field = binding("field.company")?;
        let role_field = binding("field.role")?;
        let url_field = binding("field.url")?;
        if entities
            .get(column_id)
            .and_then(|entity| entity.get("kind"))
            .and_then(Value::as_str)
            != Some("column")
        {
            return Err("Lead column is missing".into());
        }
        let (_, entities_object) = document
            .get(ROOT, "entities")
            .map_err(|error| error.to_string())?
            .ok_or("Missing Match entities")?;
        let id = lead_id.to_owned();
        let now = time::OffsetDateTime::from_unix_timestamp_nanos(now_ms()? * 1_000_000)
            .map_err(|error| error.to_string())?
            .format(time::macros::format_description!(
                "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z"
            ))
            .map_err(|error| error.to_string())?;
        let item = document
            .put_object(&entities_object, &id, ObjType::Map)
            .map_err(|error| error.to_string())?;
        put_text(&mut document, &item, "id", &id)?;
        put_text(
            &mut document,
            &item,
            "title",
            &format!("{company} — {role}"),
        )?;
        put_text(&mut document, &item, "body", body)?;
        document
            .put(&item, "deleted", false)
            .map_err(|error| error.to_string())?;
        put_text(&mut document, &item, "createdAt", &now)?;
        put_text(&mut document, &item, "updatedAt", &now)?;
        let placement = document
            .put_object(&item, "placement", ObjType::Map)
            .map_err(|error| error.to_string())?;
        put_text(&mut document, &placement, "parentId", column_id)?;
        put_text(
            &mut document,
            &placement,
            "rank",
            &format!("{}/1", now_ms()?),
        )?;
        let values = document
            .put_object(&item, "values", ObjType::Map)
            .map_err(|error| error.to_string())?;
        put_text(&mut document, &values, company_field, company)?;
        put_text(&mut document, &values, role_field, role)?;
        put_text(&mut document, &values, url_field, job_url)?;
        let message = json!({"version":1,"transactionId":id,"action":"createItem","entityIds":[id],
            "personId":member.payload.person_id,"deviceId":member.payload.device_id})
        .to_string();
        let hash = document
            .commit_with(CommitOptions::default().with_message(message))
            .ok_or("Automerge produced no lead change")?
            .to_string();
        let signed = sign_json_envelope(
            device_seed,
            serde_json::to_value(WorkspaceChangeAuthorizationPayload {
                kind: "workspace-changes".into(),
                version: 1,
                workspace_id: self.workspace_id.clone(),
                hashes: vec![hash.clone()],
                person_id: member.payload.person_id.clone(),
                device_id: member.payload.device_id.clone(),
            })
            .map_err(|error| error.to_string())?,
            &member.payload.device_id,
            DEFAULT_SIGNATURE_DOMAIN,
        )?;
        let mut proof = state
            .authorization
            .ok_or("Missing Match write authorization")?;
        proof.get_mut("records").and_then(Value::as_array_mut)
            .ok_or("Missing Match write authorizations")?
            .push(json!({"signed":signed,"publicKey":member.public_key,"certificates":member.certificates,
                "grant":member.grant,"ownerPublicKey":member.owner_public_key,
                "ownerCertificates":member.owner_certificates}));
        self.persist_document(&document.save(), Some(&proof), &[hash])?;
        Ok(id)
    }

    pub fn create_chat_message(
        &mut self,
        peer: &Value,
        device_seed: &[u8; 32],
        message_id: &str,
        body: &str,
    ) -> Result<String, String> {
        let body = body.trim();
        if body.is_empty() || body.chars().count() > 8_000 || message_id.len() > 80 {
            return Err("Chat message must contain 1–8,000 characters".into());
        }
        let authority = self.authority()?;
        let member = verify_workspace_member_bundle(
            peer.clone(),
            VerifyWorkspaceMemberOptions {
                workspace_id: Some(self.workspace_id.clone()),
                owner_person_id: Some(authority.expected_current_owner.person_id.clone()),
                owner_public_key: Some(authority.expected_current_owner.public_key.clone()),
                owner_certificates: authority.expected_current_owner.certificates.clone(),
                owner_history: vec![authority.genesis_owner.clone()],
                ..Default::default()
            },
            now_ms()?,
        )?;
        if member.role == meta_mesh_core::WorkspaceRole::Visitor {
            return Err("Lighthouse needs chat.write permission".into());
        }
        let state = self.snapshot()?;
        let chat_scope = match_chat_scope(&state.document)?;
        let created_at = time::OffsetDateTime::from_unix_timestamp_nanos(now_ms()? * 1_000_000)
            .map_err(|error| error.to_string())?
            .format(time::macros::format_description!(
                "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z"
            ))
            .map_err(|error| error.to_string())?;
        let record_id = format!("{}:{}", member.payload.device_id, message_id);
        let record_for = |kind: &str, id: String, text: &str, revision: u64| {
            let payload = json!({
                "kind": kind, "version": 1, "workspaceId": chat_scope,
                "personId": member.payload.person_id, "deviceId": member.payload.device_id,
                "id": id, "createdAt": created_at, "text": text, "revision": revision,
            });
            let signed = sign_json_envelope(
                device_seed,
                payload,
                &member.payload.device_id,
                DEFAULT_SIGNATURE_DOMAIN,
            )?;
            Ok::<Value, String>(json!({
                "signed": signed,
                "publicKey": member.public_key,
                "certificates": member.certificates,
                "authority": {
                    "publicKey": member.owner_public_key,
                    "certificates": member.owner_certificates,
                    "grant": member.grant,
                }
            }))
        };
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| "Lighthouse state lock poisoned")?;
        let messages = guard
            .state
            .chat
            .get("messages")
            .and_then(Value::as_array)
            .ok_or("Invalid stored chat")?;
        if messages.iter().any(|record| {
            record.pointer("/signed/payload/id").and_then(Value::as_str) == Some(record_id.as_str())
                && record
                    .pointer("/signed/payload/workspaceId")
                    .and_then(Value::as_str)
                    == Some(chat_scope.as_str())
        }) {
            return Ok(record_id);
        }
        let mut batch = json!({"version": 1, "messages": [], "profiles": [], "typing": []});
        batch["messages"] = json!([record_for("chat-message", record_id.clone(), body, 0)?]);
        let has_profile = guard
            .state
            .chat
            .get("profiles")
            .and_then(Value::as_array)
            .is_some_and(|profiles| {
                profiles.iter().any(|record| {
                    record
                        .pointer("/signed/payload/personId")
                        .and_then(Value::as_str)
                        == Some(member.payload.person_id.as_str())
                        && record
                            .pointer("/signed/payload/workspaceId")
                            .and_then(Value::as_str)
                            == Some(chat_scope.as_str())
                })
            });
        if !has_profile {
            batch["profiles"] = json!([record_for(
                "chat-profile",
                format!("{}:lighthouse-profile", member.payload.device_id),
                "Lighthouse",
                1,
            )?]);
        }
        let mut next = guard.state.clone();
        retain_chat_scope(&mut next.chat, &chat_scope)?;
        next.chat = merge_chat(&next.chat, &batch)?;
        self.save(&mut guard, next)?;
        Ok(record_id)
    }

    fn authority_for(
        &self,
        state: &MatchLighthouseState,
    ) -> Result<(WorkspaceWriteAuthorizationSnapshot, Value), String> {
        let evidence = state
            .authorization
            .get("authority")
            .ok_or("Missing lighthouse authority")?;
        let records = state
            .authorization
            .get("records")
            .and_then(Value::as_array)
            .ok_or("Missing lighthouse write authorizations")?;
        let (snapshot, merged) = prepare_match_write_authority(
            &state.document,
            evidence,
            None,
            records,
            &self.genesis_person_id,
            now_ms()?,
        )?;
        if snapshot.workspace_id != self.workspace_id {
            return Err("Lighthouse workspace does not match document".into());
        }
        Ok((snapshot, merged))
    }

    fn save(&self, guard: &mut Inner, next: MatchLighthouseState) -> Result<(), String> {
        write_state(&guard.file, &next)?;
        guard.state = next;
        Ok(())
    }
}

fn match_chat_scope(document: &[u8]) -> Result<String, String> {
    let document =
        AutoCommit::load(document).map_err(|error| format!("Invalid Match document: {error}"))?;
    let view =
        serde_json::to_value(AutoSerde::from(&document)).map_err(|error| error.to_string())?;
    let owner = view
        .get("ownerPersonId")
        .and_then(Value::as_str)
        .ok_or("Match workspace has no owner")?;
    let board_id = view
        .get("entities")
        .and_then(Value::as_object)
        .and_then(|entities| {
            entities.iter().find_map(|(id, entity)| {
                (entity.get("kind").and_then(Value::as_str) == Some("board")).then_some(id)
            })
        })
        .ok_or("Match workspace has no board")?;
    Ok(format!("{owner}:{board_id}"))
}

fn retain_chat_scope(chat: &mut Value, scope: &str) -> Result<(), String> {
    for section in ["messages", "profiles", "typing"] {
        chat.get_mut(section)
            .and_then(Value::as_array_mut)
            .ok_or("Invalid stored chat")?
            .retain(|record| {
                record
                    .pointer("/signed/payload/workspaceId")
                    .and_then(Value::as_str)
                    == Some(scope)
            });
    }
    Ok(())
}

fn put_text(
    document: &mut AutoCommit,
    object: &ObjId,
    key: &str,
    text: &str,
) -> Result<(), String> {
    let value = document
        .put_object(object, key, ObjType::Text)
        .map_err(|error| error.to_string())?;
    document
        .splice_text(&value, 0, 0, text)
        .map_err(|error| error.to_string())
}

fn verified_mesh_for(
    store: &MatchScopeStore,
    state: &MatchLighthouseState,
) -> Result<Value, String> {
    let (authority, _) = store.authority_for(state)?;
    let existing = state
        .mesh
        .as_ref()
        .and_then(|mesh| mesh.get("peers"))
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let peers = merge_verified_peer_catalog(existing, &[], &authority, now_ms()?)?;
    Ok(json!({"version": 1, "peers": peers, "revocations": []}))
}

impl NativeScopeHost for MatchScopeStore {
    fn snapshot(&mut self) -> Result<NativeScopeSnapshot, String> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| "Lighthouse state lock poisoned")?;
        Ok(NativeScopeSnapshot {
            document: guard.state.document.clone(),
            authorization: Some(guard.state.authorization.clone()),
            chat: Some(guard.state.chat.clone()),
            mesh: Some(verified_mesh_for(self, &guard.state)?),
        })
    }

    fn persist_document(
        &mut self,
        candidate: &[u8],
        proof: Option<&Value>,
        accepted_hashes: &[String],
    ) -> Result<(), String> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| "Lighthouse state lock poisoned")?;
        let incoming = proof
            .and_then(|value| value.get("authority"))
            .ok_or("Missing incoming Match authority")?;
        let incoming_records = proof
            .and_then(|value| value.get("records"))
            .and_then(Value::as_array)
            .ok_or("Missing incoming Match write authorizations")?;
        let known = guard.state.authorization.get("authority");
        let (snapshot, merged) = prepare_match_write_authority(
            candidate,
            incoming,
            known,
            incoming_records,
            &self.genesis_person_id,
            now_ms()?,
        )?;
        let verified = admit_match_candidate(
            Some(&guard.state.document),
            candidate,
            accepted_hashes,
            proof,
            snapshot,
            now_ms()?,
        )?;
        let records = merge_records(
            guard
                .state
                .authorization
                .get("records")
                .and_then(Value::as_array),
            &verified,
        );
        let mut next = guard.state.clone();
        next.document = candidate.to_vec();
        next.authorization = json!({"version": 1, "records": records, "authority": merged});
        self.save(&mut guard, next)
    }

    fn merge_authorization(&mut self, incoming: &Value) -> Result<(), String> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| "Lighthouse state lock poisoned")?;
        let incoming_evidence = incoming.get("authority").ok_or("Missing Match authority")?;
        let incoming_records = incoming
            .get("records")
            .and_then(Value::as_array)
            .ok_or("Missing Match write authorizations")?;
        let (snapshot, merged) = prepare_match_write_authority(
            &guard.state.document,
            incoming_evidence,
            guard.state.authorization.get("authority"),
            incoming_records,
            &self.genesis_person_id,
            now_ms()?,
        )?;
        let verified = admit_match_candidate(
            Some(&guard.state.document),
            &guard.state.document,
            &[],
            Some(incoming),
            snapshot,
            now_ms()?,
        )?;
        let records = merge_records(
            guard
                .state
                .authorization
                .get("records")
                .and_then(Value::as_array),
            &verified,
        );
        let mut next = guard.state.clone();
        next.authorization = json!({"version": 1, "records": records, "authority": merged});
        self.save(&mut guard, next)
    }

    fn merge_chat(&mut self, incoming: &Value) -> Result<(), String> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| "Lighthouse state lock poisoned")?;
        let mut next = guard.state.clone();
        next.chat = merge_chat(&next.chat, incoming)?;
        self.save(&mut guard, next)
    }

    fn merge_mesh(&mut self, incoming: &Value) -> Result<(), String> {
        let catalog = validate_mesh_catalog(incoming.clone())?;
        if !catalog.device_revocations.is_empty()
            || !catalog.departures.is_empty()
            || !catalog.revocations.is_empty()
            || catalog
                .ownership_transfers
                .as_ref()
                .is_some_and(|records| !records.is_empty())
            || catalog.succession_policy.is_some()
            || catalog
                .succession_votes
                .as_ref()
                .is_some_and(|records| !records.is_empty())
            || catalog
                .succession_claims
                .as_ref()
                .is_some_and(|records| !records.is_empty())
        {
            return Err("Lighthouse cannot apply mesh authority changes yet".into());
        }
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| "Lighthouse state lock poisoned")?;
        let (authority, _) = self.authority_for(&guard.state)?;
        let existing = guard
            .state
            .mesh
            .as_ref()
            .and_then(|mesh| mesh.get("peers"))
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let peers = merge_verified_peer_catalog(existing, &catalog.peers, &authority, now_ms()?)?;
        let mut next = guard.state.clone();
        next.mesh = Some(json!({"version": 1, "peers": peers, "revocations": []}));
        self.save(&mut guard, next)
    }

    fn merge_durable_batch(&mut self, _: &[u8]) -> Result<(), String> {
        Err("Match lighthouse does not accept workspace-set imports".into())
    }

    fn merge_owner_offer(&mut self, _: &[u8]) -> Result<(), String> {
        Err("Match lighthouse does not accept owner workspace offers".into())
    }

    fn receive_gossip(&mut self, _: &[u8]) -> Result<(), String> {
        // Gossip is a wake-up hint; periodic anti-entropy owns document delivery.
        Ok(())
    }
}

pub struct MatchLighthouseHost {
    pub workspace_id: String,
    pub secret: String,
    pub local_device_id: String,
    pub local_handshake: MeshHandshake,
    pub store: MatchScopeStore,
}

impl NativeScopeServiceHost for MatchLighthouseHost {
    type ScopeHost = MatchScopeStore;

    fn local_device_id(&self) -> &str {
        &self.local_device_id
    }

    fn credential(&mut self, secret: &str) -> Result<Option<NativeScopeCredential>, String> {
        Ok((secret == self.secret).then(|| NativeScopeCredential {
            workspace_id: self.workspace_id.clone(),
            secret: self.secret.clone(),
        }))
    }

    fn prepare_handshake(
        &mut self,
        workspace_id: &str,
        _: &MeshHandshake,
    ) -> Result<(WorkspaceWriteAuthorizationSnapshot, Value), String> {
        if workspace_id != self.workspace_id {
            return Err("Wrong lighthouse workspace".into());
        }
        Ok((
            self.store.authority()?,
            serde_json::to_value(&self.local_handshake).map_err(|error| error.to_string())?,
        ))
    }

    fn authority(
        &mut self,
        workspace_id: &str,
    ) -> Result<WorkspaceWriteAuthorizationSnapshot, String> {
        if workspace_id != self.workspace_id {
            return Err("Wrong lighthouse workspace".into());
        }
        self.store.authority()
    }

    fn outgoing_handshake(&mut self, workspace_id: &str) -> Result<Value, String> {
        if workspace_id != self.workspace_id {
            return Err("Wrong lighthouse workspace".into());
        }
        serde_json::to_value(&self.local_handshake).map_err(|error| error.to_string())
    }

    fn open_scope(&mut self, peer: &MeshPeerAdmission) -> Result<Self::ScopeHost, String> {
        if peer.workspace_id != self.workspace_id {
            return Err("Wrong lighthouse workspace".into());
        }
        Ok(self.store.clone())
    }
}

fn write_state(file: &FileScopeStore, state: &MatchLighthouseState) -> Result<(), String> {
    let bytes = serde_json::to_vec(state).map_err(|error| error.to_string())?;
    file.write_validated(&bytes, None, |_, _| Ok(()))
}

fn merge_records(existing: Option<&Vec<Value>>, incoming: &[Value]) -> Vec<Value> {
    let mut seen = BTreeSet::new();
    existing
        .into_iter()
        .flatten()
        .chain(incoming)
        .filter(|record| seen.insert(record.to_string()))
        .cloned()
        .collect()
}

fn merge_chat(current: &Value, incoming: &Value) -> Result<Value, String> {
    if incoming.get("version").and_then(Value::as_u64) != Some(1) {
        return Err("Invalid chat batch".into());
    }
    if serde_json::to_vec(incoming)
        .map_err(|error| error.to_string())?
        .len()
        > 8 * 1024 * 1024
    {
        return Err("Invalid chat batch".into());
    }
    if incoming
        .get("typing")
        .is_some_and(|value| value.as_array().is_none_or(|items| items.len() > 512))
    {
        return Err("Invalid chat batch".into());
    }
    let mut result = serde_json::Map::new();
    for (field, limit) in [("messages", 20_000), ("profiles", 2_000)] {
        let old = current
            .get(field)
            .and_then(Value::as_array)
            .ok_or("Invalid stored chat")?;
        let new = incoming
            .get(field)
            .and_then(Value::as_array)
            .ok_or("Invalid chat batch")?;
        if new.len() > if field == "messages" { 2_000 } else { 512 } {
            return Err("Invalid chat batch".into());
        }
        let mut seen = BTreeSet::new();
        let values = old
            .iter()
            .chain(new)
            .filter(|record| {
                record
                    .pointer("/signed/signature")
                    .and_then(Value::as_str)
                    .is_some_and(|signature| !signature.is_empty())
            })
            .filter(|record| seen.insert(record.pointer("/signed/signature").unwrap().to_string()))
            .take(limit + 1)
            .cloned()
            .collect::<Vec<_>>();
        if values.len() > limit {
            return Err("Lighthouse chat storage limit exceeded".into());
        }
        result.insert(field.into(), Value::Array(values));
    }
    result.insert("version".into(), json!(1));
    result.insert("typing".into(), json!([]));
    Ok(Value::Object(result))
}

pub fn now_ms() -> Result<i128, String> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_millis() as i128)
}

#[cfg(test)]
mod tests {
    use super::*;
    use automerge::{ROOT, transaction::Transactable};
    use meta_mesh_core::{
        DEFAULT_SIGNATURE_DOMAIN, DeviceCertificatePayload, WorkspaceAuthority,
        WorkspaceChangeAuthorizationPayload, public_key_from_seed, public_key_id,
        sign_device_certificate, sign_json_envelope,
    };

    #[test]
    fn signed_document_survives_restart_but_unsigned_change_never_replaces_it() {
        let public_key = public_key_from_seed(&[1; 32]).unwrap();
        let person_id = public_key_id(&public_key).unwrap();
        let device_public_key = public_key_from_seed(&[2; 32]).unwrap();
        let device_id = public_key_id(&device_public_key).unwrap();
        let certificate = sign_device_certificate(
            &[1; 32],
            DeviceCertificatePayload {
                kind: "device-certificate".into(),
                version: 1,
                person_id: person_id.clone(),
                device_id: device_id.clone(),
                device_public_key,
                issuer_certificate_hash: None,
                can_enroll_devices: true,
            },
            &person_id,
            DEFAULT_SIGNATURE_DOMAIN,
        )
        .unwrap();
        let owner = WorkspaceAuthority {
            person_id: person_id.clone(),
            public_key: public_key.clone(),
            certificates: vec![certificate.clone()],
        };
        let evidence = json!({
            "genesisOwner": owner, "genesisEpoch": 1,
            "currentOwner": owner, "currentEpoch": 1,
            "ownershipTransfers": [], "successionClaims": [],
            "revocations": [], "deviceRevocations": [], "departures": [],
        });
        let proof_for = |hashes: Vec<String>| {
            let signed = sign_json_envelope(
                &[2; 32],
                json!(WorkspaceChangeAuthorizationPayload {
                    kind: "workspace-changes".into(),
                    version: 1,
                    workspace_id: "board".into(),
                    hashes,
                    person_id: person_id.clone(),
                    device_id: device_id.clone(),
                }),
                &device_id,
                DEFAULT_SIGNATURE_DOMAIN,
            )
            .unwrap();
            json!({"version": 1, "records": [{
                "signed": signed, "publicKey": public_key, "certificates": [certificate]
            }], "authority": evidence})
        };
        let mut document = AutoCommit::new();
        document.put(ROOT, "id", "board").unwrap();
        document
            .put(ROOT, "ownerPersonId", person_id.clone())
            .unwrap();
        document.put(ROOT, "title", "Original").unwrap();
        let entities = document
            .put_object(ROOT, "entities", automerge::ObjType::Map)
            .unwrap();
        let board = document
            .put_object(&entities, "board-1", automerge::ObjType::Map)
            .unwrap();
        document.put(&board, "kind", "board").unwrap();
        let baseline = document.save();
        let initial_hashes = document
            .get_changes(&[])
            .iter()
            .map(|change| change.hash().to_string())
            .collect();
        let initial = MatchLighthouseState {
            document: baseline.clone(),
            authorization: proof_for(initial_hashes),
            chat: empty_chat(),
            mesh: None,
        };
        let path = std::env::temp_dir().join(format!(
            "match-lighthouse-{}-{}.json",
            std::process::id(),
            now_ms().unwrap()
        ));
        let mut store = MatchScopeStore::open(
            "board".into(),
            person_id.clone(),
            path.clone(),
            initial.clone(),
        )
        .unwrap();
        document.put(ROOT, "title", "Updated").unwrap();
        let candidate = document.save();
        let new_hash = document.get_heads()[0].to_string();
        assert!(
            store
                .persist_document(
                    &candidate,
                    Some(&json!({
                        "version": 1, "records": [], "authority": evidence,
                    })),
                    std::slice::from_ref(&new_hash)
                )
                .is_err()
        );
        assert_eq!(store.snapshot().unwrap().document, baseline);
        store
            .persist_document(
                &candidate,
                Some(&proof_for(vec![new_hash])),
                &[document.get_heads()[0].to_string()],
            )
            .unwrap();
        assert!(
            store
                .persist_document(&baseline, Some(&initial.authorization), &[])
                .is_err()
        );
        assert_eq!(store.snapshot().unwrap().document, candidate);
        let issued_at = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
        let advertisement = sign_json_envelope(
            &[2; 32],
            json!({"kind":"peer-advertisement","version":1,"workspaceId":"board",
                "personId":person_id,"deviceId":device_id,"instanceId":"test",
                "endpoint":"signed-route","issuedAt":issued_at,"routeSequence":1}),
            &device_id,
            DEFAULT_SIGNATURE_DOMAIN,
        )
        .unwrap();
        let peer = json!({"advertisement":advertisement,"publicKey":public_key,
            "certificates":[certificate]});
        let message_id = store
            .create_chat_message(&peer, &[2; 32], "intake-test", "New lead")
            .unwrap();
        let chat = store.snapshot().unwrap().chat.unwrap();
        assert_eq!(
            chat.pointer("/messages/0/signed/payload/id")
                .and_then(Value::as_str),
            Some(message_id.as_str())
        );
        assert_eq!(
            chat.pointer("/profiles/0/signed/payload/text")
                .and_then(Value::as_str),
            Some("Lighthouse")
        );
        assert_eq!(
            chat.pointer("/messages/0/signed/payload/workspaceId")
                .and_then(Value::as_str),
            Some(format!("{person_id}:board-1").as_str())
        );
        store.merge_mesh(&json!({"version":1,"peers":[peer, {"advertisement":{"payload":{"endpoint":"fake"}}}],
            "revocations":[]})).unwrap();
        assert_eq!(
            store.authorized_peer_endpoints().unwrap(),
            vec!["signed-route"]
        );
        assert!(
            store
                .merge_mesh(&json!({"version":1,"peers":[],"revocations":[{}]}))
                .is_err()
        );
        let mut reopened =
            MatchScopeStore::open("board".into(), person_id, path.clone(), initial).unwrap();
        assert_eq!(reopened.snapshot().unwrap().document, candidate);
        assert_eq!(
            reopened.authorized_peer_endpoints().unwrap(),
            vec!["signed-route"]
        );
        std::fs::remove_file(path).unwrap();
    }
}
