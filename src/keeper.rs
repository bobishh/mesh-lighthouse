use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use match_lighthouse::{MatchLighthouseHost, MatchScopeStore};
use meta_mesh_core::{
    MeshHandshake, MeshPeerAdmission, WorkspaceItem, WorkspaceJoinInvitation,
    WorkspaceWriteAuthorizationSnapshot,
};
use meta_mesh_native::{
    FileScopeStore, NativeScopeCredential, NativeScopeHost, NativeScopeServiceHost,
    NativeScopeSnapshot,
};
use serde_json::{Value, json};

use crate::{Config, join};

pub(crate) struct Registry {
    config: Config,
    config_path: PathBuf,
    scopes: BTreeMap<String, MatchLighthouseHost>,
}

#[derive(Clone)]
pub(crate) struct KeeperHost {
    device_id: String,
    registry: Arc<Mutex<Registry>>,
}

fn scope_host(config: &Config) -> Result<MatchLighthouseHost, String> {
    if config.local_handshake.workspace_id != config.workspace_id {
        return Err("Keeper handshake targets another scope".into());
    }
    let store = MatchScopeStore::open(
        config.workspace_id.clone(),
        config.genesis_person_id.clone(),
        config.state_path.clone(),
        config.initial_state.clone(),
    )?;
    let authority = store.authority()?;
    let verified = meta_mesh_core::verify_workspace_member_bundle(
        config.local_handshake.peer.clone(),
        meta_mesh_core::VerifyWorkspaceMemberOptions {
            workspace_id: Some(config.workspace_id.clone()),
            owner_person_id: Some(authority.expected_current_owner.person_id.clone()),
            owner_public_key: Some(authority.expected_current_owner.public_key.clone()),
            owner_certificates: authority.expected_current_owner.certificates.clone(),
            owner_history: vec![authority.genesis_owner.clone()],
            allow_stale_route: true,
            ..Default::default()
        },
        match_lighthouse::now_ms()?,
    )?;
    let secret: [u8; 32] = config
        .iroh_secret
        .as_slice()
        .try_into()
        .map_err(|_| "Invalid keeper endpoint seed")?;
    if verified.payload.device_id != config.device_id
        || verified.payload.endpoint != iroh::SecretKey::from(secret).public().to_string()
    {
        return Err("Keeper advertisement does not match service device and endpoint".into());
    }
    Ok(MatchLighthouseHost {
        workspace_id: config.workspace_id.clone(),
        secret: config.transport_secret.clone(),
        local_device_id: config.device_id.clone(),
        local_handshake: config.local_handshake.clone(),
        store,
    })
}

impl KeeperHost {
    pub(crate) fn open(config: Config, config_path: PathBuf) -> Result<Self, String> {
        let mut scopes = BTreeMap::new();
        for scope in std::iter::once(&config).chain(config.additional_scopes.iter()) {
            if scope.device_id != config.device_id
                || scope.iroh_secret != config.iroh_secret
                || scope.device_seed != config.device_seed
                || scope.identity_seed != config.identity_seed
            {
                return Err("All keeper scopes must use one service identity and device".into());
            }
            if scopes
                .values()
                .any(|host: &MatchLighthouseHost| host.secret == scope.transport_secret)
            {
                return Err("Keeper scope secrets must be distinct".into());
            }
            if scopes
                .insert(scope.workspace_id.clone(), scope_host(scope)?)
                .is_some()
            {
                return Err("Duplicate keeper scope".into());
            }
        }
        Ok(Self {
            device_id: config.device_id.clone(),
            registry: Arc::new(Mutex::new(Registry {
                config,
                config_path,
                scopes,
            })),
        })
    }

    pub(crate) fn scopes(&self) -> Result<Vec<(String, String, Vec<String>)>, String> {
        let registry = self
            .registry
            .lock()
            .map_err(|_| "Keeper registry lock poisoned")?;
        registry
            .scopes
            .values()
            .map(|scope| {
                Ok((
                    scope.workspace_id.clone(),
                    scope.secret.clone(),
                    scope.store.authorized_peer_endpoints()?,
                ))
            })
            .collect()
    }

    pub(crate) fn primary_store(&self) -> Result<(MatchScopeStore, Value), String> {
        let registry = self
            .registry
            .lock()
            .map_err(|_| "Keeper registry lock poisoned")?;
        let scope = registry
            .scopes
            .get(&registry.config.workspace_id)
            .ok_or("Missing intake scope")?;
        Ok((scope.store.clone(), scope.local_handshake.peer.clone()))
    }

    pub(crate) fn attach_owner_inventory(
        &self,
        workspace: &str,
        route: &str,
        secret: &str,
        frame: Vec<u8>,
    ) -> Result<Vec<u8>, String> {
        let registry = self
            .registry
            .lock()
            .map_err(|_| "Keeper registry lock poisoned")?;
        let Some(controller) = registry.config.controller_person_id.as_deref() else {
            return Ok(frame);
        };
        let scope = registry
            .scopes
            .get(workspace)
            .ok_or("Unknown keeper scope")?;
        let snapshot = scope.store.clone().snapshot()?;
        // Catalog entries were verified against signed authority by MatchScopeStore.
        let owner_route = snapshot
            .mesh
            .as_ref()
            .and_then(|mesh| mesh["peers"].as_array())
            .is_some_and(|peers| {
                peers.iter().any(|peer| {
                    peer.pointer("/advertisement/payload/personId")
                        .and_then(Value::as_str)
                        == Some(controller)
                        && peer
                            .pointer("/advertisement/payload/endpoint")
                            .and_then(Value::as_str)
                            == Some(route)
                })
            });
        if !owner_route {
            return Ok(frame);
        }
        let mut handshake = meta_mesh_core::decode_mesh_handshake(
            &frame,
            "mesh-handshake-request",
            secret,
            workspace,
        )?;
        handshake.owner_workspace_ids = Some(registry.scopes.keys().cloned().collect());
        meta_mesh_core::encode_mesh_handshake(
            "mesh-handshake-request",
            secret,
            serde_json::to_value(handshake).map_err(|error| error.to_string())?,
        )
    }

    pub(crate) fn refresh_routes(&self, sequence: u64) -> Result<(), String> {
        let mut registry = self
            .registry
            .lock()
            .map_err(|_| "Keeper registry lock poisoned")?;
        let seed: [u8; 32] = registry
            .config
            .device_seed
            .as_slice()
            .try_into()
            .map_err(|_| "Invalid keeper device seed")?;
        for scope in registry.scopes.values_mut() {
            crate::refresh_route(&mut scope.local_handshake, &seed, sequence)?;
        }
        Ok(())
    }
}

impl NativeScopeServiceHost for KeeperHost {
    type ScopeHost = KeeperScope;
    fn local_device_id(&self) -> &str {
        &self.device_id
    }

    fn credential(&mut self, secret: &str) -> Result<Option<NativeScopeCredential>, String> {
        let registry = self
            .registry
            .lock()
            .map_err(|_| "Keeper registry lock poisoned")?;
        Ok(registry
            .scopes
            .values()
            .find(|scope| scope.secret == secret)
            .map(|scope| NativeScopeCredential {
                workspace_id: scope.workspace_id.clone(),
                secret: scope.secret.clone(),
            }))
    }

    fn prepare_handshake(
        &mut self,
        workspace_id: &str,
        request: &MeshHandshake,
    ) -> Result<(WorkspaceWriteAuthorizationSnapshot, Value), String> {
        let mut response = self.outgoing_handshake(workspace_id)?;
        let registry = self
            .registry
            .lock()
            .map_err(|_| "Keeper registry lock poisoned")?;
        // Native admission verifies this signed request before sending response.
        // Unauthenticated claims never receive the owner's scope inventory.
        if registry
            .config
            .controller_person_id
            .as_deref()
            .is_some_and(|owner| {
                request
                    .peer
                    .pointer("/advertisement/payload/personId")
                    .and_then(Value::as_str)
                    == Some(owner)
            })
        {
            response["ownerWorkspaceIds"] = json!(registry.scopes.keys().collect::<Vec<_>>());
        }
        drop(registry);
        Ok((self.authority(workspace_id)?, response))
    }

    fn authority(
        &mut self,
        workspace_id: &str,
    ) -> Result<WorkspaceWriteAuthorizationSnapshot, String> {
        self.registry
            .lock()
            .map_err(|_| "Keeper registry lock poisoned")?
            .scopes
            .get(workspace_id)
            .ok_or("Unknown keeper scope")?
            .store
            .authority()
    }

    fn outgoing_handshake(&mut self, workspace_id: &str) -> Result<Value, String> {
        let registry = self
            .registry
            .lock()
            .map_err(|_| "Keeper registry lock poisoned")?;
        let scope = registry
            .scopes
            .get(workspace_id)
            .ok_or("Unknown keeper scope")?;
        let mut handshake = scope.local_handshake.clone();
        handshake.owner_workspace_ids = None;
        serde_json::to_value(handshake).map_err(|error| error.to_string())
    }

    fn open_scope(&mut self, peer: &MeshPeerAdmission) -> Result<KeeperScope, String> {
        let registry = self
            .registry
            .lock()
            .map_err(|_| "Keeper registry lock poisoned")?;
        let store = registry
            .scopes
            .get(&peer.workspace_id)
            .ok_or("Unknown keeper scope")?
            .store
            .clone();
        Ok(KeeperScope {
            store,
            registry: Arc::clone(&self.registry),
            peer: peer.clone(),
        })
    }
}

pub(crate) struct KeeperScope {
    store: MatchScopeStore,
    registry: Arc<Mutex<Registry>>,
    peer: MeshPeerAdmission,
}

impl NativeScopeHost for KeeperScope {
    fn read_proof_page(&mut self, key: &str) -> Result<Option<Vec<u8>>, String> {
        self.store.read_proof_page(key)
    }
    fn write_proof_page(&mut self, key: &str, payload: &[u8]) -> Result<(), String> {
        self.store.write_proof_page(key, payload)
    }
    fn clear_proof_pages(&mut self) -> Result<(), String> {
        self.store.clear_proof_pages()
    }
    fn snapshot(&mut self) -> Result<NativeScopeSnapshot, String> {
        self.store.snapshot()
    }
    fn persist_document(
        &mut self,
        document: &[u8],
        proof: Option<&Value>,
        accepted_hashes: &[String],
    ) -> Result<(), String> {
        self.store
            .persist_document(document, proof, accepted_hashes)
    }
    fn merge_authorization(&mut self, value: &Value) -> Result<(), String> {
        self.store.merge_authorization(value)
    }
    fn merge_chat(&mut self, value: &Value) -> Result<(), String> {
        self.store.merge_chat(value)
    }
    fn merge_mesh(&mut self, value: &Value) -> Result<(), String> {
        self.store.merge_mesh(value)
    }
    fn merge_durable_batch(&mut self, bytes: &[u8]) -> Result<(), String> {
        self.store.merge_durable_batch(bytes)
    }
    fn receive_gossip(&mut self, bytes: &[u8]) -> Result<(), String> {
        self.store.receive_gossip(bytes)
    }

    fn merge_owner_offer(&mut self, bytes: &[u8]) -> Result<(), String> {
        let value: Value =
            serde_json::from_slice(bytes).map_err(|_| "Invalid keeper owner offer")?;
        let mut registry = self
            .registry
            .lock()
            .map_err(|_| "Keeper registry lock poisoned")?;
        let controller = registry
            .config
            .controller_person_id
            .as_deref()
            .ok_or("Keeper is not connected to an owner")?;
        if self.peer.person_id != controller
            || value["controllerPersonId"].as_str() != Some(controller)
            || value["version"] != 1
        {
            return Err("Keeper offer is not from the approved owner".into());
        }
        let workspace_id = value["workspaceId"]
            .as_str()
            .filter(|id| !id.is_empty())
            .ok_or("Missing keeper scope id")?;
        let envelope = &value["envelope"];
        let workspace = &value["workspace"];
        if envelope["workspaceId"] != workspace_id
            || workspace["id"] != workspace_id
            || envelope["ownerPersonId"] != controller
        {
            return Err("Keeper offer scope or owner mismatch".into());
        }
        if let Some(existing) = registry.scopes.get(workspace_id)
            && existing.secret != envelope["transportSecret"].as_str().unwrap_or("")
        {
            return Err("Keeper scope conflicts with existing trust".into());
        }
        let issuer = envelope["peers"]
            .as_array()
            .ok_or("Missing owner peers")?
            .iter()
            .find(|peer| {
                peer.pointer("/advertisement/payload/deviceId")
                    .and_then(Value::as_str)
                    == Some(self.peer.device_id.as_str())
            })
            .ok_or("Keeper offer omits its authenticated owner device")?;
        let device_seed: [u8; 32] = registry
            .config
            .device_seed
            .as_slice()
            .try_into()
            .map_err(|_| "Invalid device seed")?;
        let identity_seed: [u8; 32] = registry
            .config
            .identity_seed
            .as_slice()
            .try_into()
            .map_err(|_| "Invalid identity seed")?;
        let iroh_secret: [u8; 32] = registry
            .config
            .iroh_secret
            .as_slice()
            .try_into()
            .map_err(|_| "Invalid endpoint seed")?;
        let certificate = registry.config.local_handshake.peer["certificates"]
            .as_array()
            .and_then(|certificates| certificates.first())
            .ok_or("Missing keeper certificate")?;
        let certificate = serde_json::from_value(certificate.clone())
            .map_err(|_| "Invalid keeper certificate")?;
        let public_key = meta_mesh_core::public_key_from_seed(&identity_seed)?;
        let person_id = meta_mesh_core::public_key_id(&public_key)?;
        let endpoint = registry
            .config
            .local_handshake
            .peer
            .pointer("/advertisement/payload/endpoint")
            .and_then(Value::as_str)
            .ok_or("Missing keeper endpoint")?;
        let bundle = join::guest_bundle(
            workspace_id,
            &person_id,
            &registry.config.device_id,
            &public_key,
            &certificate,
            &device_seed,
            endpoint,
        )
        .map_err(|error| error.to_string())?;
        let issuer_key = issuer["certificates"]
            .as_array()
            .and_then(|certificates| {
                certificates.iter().find(|certificate| {
                    certificate
                        .pointer("/payload/deviceId")
                        .and_then(Value::as_str)
                        == Some(self.peer.device_id.as_str())
                })
            })
            .and_then(|certificate| certificate.pointer("/payload/devicePublicKey"))
            .and_then(Value::as_str)
            .ok_or("Missing owner device public key")?;
        let invite = WorkspaceJoinInvitation {
            version: 1,
            kind: "workspace-join".into(),
            invitation_id: String::new(),
            issuer_person_id: controller.into(),
            issuer_device_id: self.peer.device_id.clone(),
            issuer_public_key: issuer_key.into(),
            issuer_endpoint: self.peer.endpoint.clone(),
            workspace_id: workspace_id.into(),
            workspace_title: String::new(),
            workspaces: vec![WorkspaceItem {
                id: workspace_id.into(),
                title: String::new(),
            }],
            role: String::new(),
            created_at: String::new(),
            expires_at: String::new(),
            secret: String::new(),
        };
        let response = serde_json::to_vec(&json!({ "grants": [value["grant"]], "meshWorkspaces": [envelope],
            "snapshot": URL_SAFE_NO_PAD.encode(serde_json::to_vec(&vec![workspace]).map_err(|error| error.to_string())?) }))
            .map_err(|error| error.to_string())?;
        let directory = registry
            .config_path
            .parent()
            .ok_or("Invalid keeper registry path")?
            .join(format!("scope-{:032x}", rand::random::<u128>()));
        join::create_private_directory(&directory).map_err(|error| error.to_string())?;
        let mut pending = PendingScopeDirectory(Some(directory.clone()));
        let scope = join::prepare_config(
            &invite,
            &response,
            &directory,
            &person_id,
            &registry.config.device_id,
            &bundle,
            identity_seed,
            &device_seed,
            iroh_secret,
        )
        .map_err(|error| error.to_string())?;
        if let Some(existing) = registry.scopes.get(workspace_id) {
            let mut store = existing.store.clone();
            let state = &scope.initial_state;
            let mut doc = automerge::AutoCommit::load(&store.snapshot()?.document)
                .map_err(|error| error.to_string())?;
            let heads = doc.get_heads();
            let mut incoming =
                automerge::AutoCommit::load(&state.document).map_err(|error| error.to_string())?;
            doc.merge(&mut incoming)
                .map_err(|error| error.to_string())?;
            let hashes = doc
                .get_changes(&heads)
                .iter()
                .map(|change| change.hash().to_string())
                .collect::<Vec<_>>();
            store.persist_document(&doc.save(), Some(&state.authorization), &hashes)?;
            store.merge_authorization(&state.authorization)?;
            store.merge_chat(&state.chat)?;
            if let Some(mesh) = &state.mesh {
                store.merge_mesh(mesh)?;
            }
            return Ok(());
        }
        let host = scope_host(&scope)?;
        let mut next = registry.config.clone();
        next.additional_scopes.push(scope);
        FileScopeStore::new(&registry.config_path).write_validated(
            &serde_json::to_vec(&next).map_err(|error| error.to_string())?,
            None,
            |_, _| Ok(()),
        )?;
        pending.0 = None;
        registry.config = next;
        registry.scopes.insert(workspace_id.into(), host);
        eprintln!("Lighthouse activated workspace {workspace_id}");
        Ok(())
    }
}

// Only directories created by this offer are removed on failed validation/commit.
struct PendingScopeDirectory(Option<PathBuf>);
impl Drop for PendingScopeDirectory {
    fn drop(&mut self) {
        if let Some(path) = &self.0 {
            let _ = std::fs::remove_dir_all(path);
        }
    }
}

#[cfg(test)]
#[path = "keeper_tests.rs"]
mod tests;
