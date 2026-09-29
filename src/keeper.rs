use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use match_lighthouse::{MatchLighthouseHost, MatchScopeStore};
use meta_mesh_core::{
    DeviceCertificate, MeshHandshake, MeshPeerAdmission, PublicIdentity,
    VerifyWorkspaceMemberOptions, WorkspaceItem, WorkspaceJoinInvitation, WorkspaceRole,
    WorkspaceWriteAuthorizationSnapshot, public_key_id, verify_workspace_grant,
    verify_workspace_member_bundle,
};
use meta_mesh_native::{
    FileScopeStore, NativeOwnerOfferSnapshot, NativeScopeCredential, NativeScopeHost,
    NativeScopeServiceHost, NativeScopeSnapshot,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{Config, ProvisioningCommit, join};

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

fn current_owner(scope: &MatchLighthouseHost) -> Result<String, String> {
    Ok(scope.store.authority()?.expected_current_owner.person_id)
}

fn owner_workspace_ids(registry: &Registry, owner_person_id: &str) -> Result<Vec<String>, String> {
    let mut workspace_ids = registry
        .scopes
        .iter()
        .filter_map(|(workspace_id, scope)| match current_owner(scope) {
            Ok(owner) if owner == owner_person_id => Some(Ok(workspace_id.clone())),
            Ok(_) => None,
            Err(error) => Some(Err(error)),
        })
        .collect::<Result<Vec<_>, _>>()?;
    workspace_ids.sort();
    Ok(workspace_ids)
}

fn owner_follows_future_boards(registry: &Registry, owner_person_id: &str) -> Result<bool, String> {
    let has_current_board = registry.scopes.iter().try_fold(
        false,
        |found, (workspace_id, scope)| -> Result<bool, String> {
            if found || current_owner(scope)? != owner_person_id {
                return Ok(found);
            }
            let original_owner = std::iter::once(&registry.config)
                .chain(registry.config.additional_scopes.iter())
                .find(|config| config.workspace_id == *workspace_id)
                .and_then(|config| config.controller_person_id.as_deref());
            Ok(original_owner == Some(owner_person_id))
        },
    )?;
    Ok(future_policy_matches_owner(
        owner_person_id,
        has_current_board,
        &registry.config.provisioning_commits,
    ))
}

fn future_policy_matches_owner(
    owner_person_id: &str,
    has_current_board: bool,
    commits: &[ProvisioningCommit],
) -> bool {
    has_current_board
        && commits.iter().any(|commit| {
            commit.future_boards && commit.controller_person_id.as_deref() == Some(owner_person_id)
        })
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
    pub(crate) fn open(mut config: Config, config_path: PathBuf) -> Result<Self, String> {
        // Prior releases had one controller identity for all future-board commits.
        // Import that identity before any new per-scope owner metadata is written.
        if let Some(legacy_owner) = config.controller_person_id.clone() {
            for commit in &mut config.provisioning_commits {
                if commit.future_boards && commit.controller_person_id.is_none() {
                    commit.controller_person_id = Some(legacy_owner.clone());
                }
            }
        }
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

    pub(crate) fn configuration(&self) -> Result<Config, String> {
        Ok(self
            .registry
            .lock()
            .map_err(|_| "Keeper registry lock poisoned")?
            .config
            .clone())
    }

    pub(crate) fn admin_overview(&self) -> Result<Value, String> {
        self.overview_for_owner(None)
    }

    fn overview_for_owner(&self, owner_filter: Option<&str>) -> Result<Value, String> {
        let registry = self
            .registry
            .lock()
            .map_err(|_| "Keeper registry lock poisoned")?;
        let mut boards = Vec::with_capacity(registry.scopes.len());
        let peer = serde_json::to_value(&registry.config.local_handshake.peer)
            .map_err(|error| error.to_string())?;
        for (workspace_id, scope) in &registry.scopes {
            let owner_person_id = current_owner(scope)?;
            if owner_filter.is_some_and(|owner| owner != owner_person_id) {
                continue;
            }
            let (title, heads) = scope.store.document_overview()?;
            let config = std::iter::once(&registry.config)
                .chain(registry.config.additional_scopes.iter())
                .find(|config| config.workspace_id == *workspace_id)
                .ok_or("Missing keeper board configuration")?;
            let modified = fs::metadata(&config.state_path)
                .and_then(|metadata| metadata.modified())
                .ok()
                .and_then(|modified| modified.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|duration| duration.as_secs());
            let title = title
                .filter(|title| !title.trim().is_empty())
                .unwrap_or_else(|| {
                    if *workspace_id == registry.config.workspace_id {
                        "Primary workspace".into()
                    } else {
                        format!("Board {}", workspace_id.get(..8).unwrap_or(workspace_id))
                    }
                });
            boards.push(json!({
                "workspaceId": workspace_id,
                "ownerPersonId": owner_person_id,
                "title": title,
                "isPrimary": *workspace_id == registry.config.workspace_id,
                "heads": heads,
                "peerCount": scope.store.authorized_peer_endpoints()?.len(),
                "lastSavedAt": modified,
            }));
        }
        boards.sort_by_key(|board| !board["isPrimary"].as_bool().unwrap_or(false));
        Ok(json!({
            "keeper": {
                "displayName": peer.pointer("/advertisement/payload/deviceName").and_then(Value::as_str).unwrap_or("Lighthouse"),
                "personId": peer.pointer("/advertisement/payload/personId").and_then(Value::as_str).unwrap_or_default(),
                "deviceId": registry.config.device_id,
                "boards": boards,
            }
        }))
    }

    /// Owner view contains only boards whose verified current authority belongs to owner.
    pub(crate) fn owner_overview(&self, owner_person_id: &str) -> Result<Value, String> {
        self.overview_for_owner(Some(owner_person_id))
    }

    pub(crate) fn provisioning_commit(
        &self,
        pairing_id: &str,
    ) -> Result<Option<ProvisioningCommit>, String> {
        Ok(self
            .registry
            .lock()
            .map_err(|_| "Keeper registry lock poisoned")?
            .config
            .provisioning_commits
            .iter()
            .find(|commit| commit.pairing_id == pairing_id)
            .cloned())
    }

    /// Make fully staged scopes visible in one durable config replacement.
    /// Caller sends the workspace-join ACK only after this returns success.
    pub(crate) fn activate_provisioned_scopes(
        &self,
        mut staged: Vec<Config>,
        mut commit: ProvisioningCommit,
    ) -> Result<(), String> {
        let mut registry = self
            .registry
            .lock()
            .map_err(|_| "Keeper registry lock poisoned")?;
        let mut next = registry.config.clone();
        if let Some(previous) = next
            .provisioning_commits
            .iter()
            .find(|previous| previous.pairing_id == commit.pairing_id)
        {
            let same_operation = previous.pairing_id == commit.pairing_id
                && previous.operation_id == commit.operation_id
                && previous.transcript_hash == commit.transcript_hash
                && previous.invitation_id == commit.invitation_id
                && previous.workspace_ids == commit.workspace_ids
                && previous.snapshot_hash == commit.snapshot_hash
                && previous.future_boards == commit.future_boards
                && (previous.controller_person_id.is_none()
                    || previous.controller_person_id == commit.controller_person_id);
            return if same_operation {
                Ok(())
            } else {
                Err("Provisioning operation conflicts with durable activation".into())
            };
        }
        if staged.is_empty() {
            return Err("Provisioning has no staged scopes".into());
        }
        let mut staged_hosts = Vec::with_capacity(staged.len());
        let mut staged_owner: Option<String> = None;
        for scope in &mut staged {
            if scope.device_id != next.device_id
                || scope.iroh_secret != next.iroh_secret
                || scope.device_seed != next.device_seed
                || scope.identity_seed != next.identity_seed
            {
                return Err("Staged scope does not use this keeper identity".into());
            }
            if registry.scopes.contains_key(&scope.workspace_id)
                || staged_hosts
                    .iter()
                    .any(|(workspace_id, _): &(String, MatchLighthouseHost)| {
                        workspace_id == &scope.workspace_id
                    })
            {
                return Err("Provisioned scope already exists".into());
            }
            let host = scope_host(scope)?;
            let owner = host.store.authority()?.expected_current_owner.person_id;
            if staged_owner
                .as_deref()
                .is_some_and(|staged_owner| staged_owner != owner)
            {
                return Err("Provisioning cannot mix owners in one activation".into());
            }
            staged_owner = Some(owner.clone());
            if scope
                .controller_person_id
                .as_deref()
                .is_some_and(|controller| controller != owner)
            {
                return Err("Staged scope controller is not its verified current owner".into());
            }
            // Persist original owner identity for policy lineage, even when future following is off.
            scope.controller_person_id = Some(owner);
            staged_hosts.push((scope.workspace_id.clone(), host));
        }
        if commit
            .controller_person_id
            .as_deref()
            .is_some_and(|controller| staged_owner.as_deref() != Some(controller))
        {
            return Err("Provisioning controller is not the verified staged owner".into());
        }
        commit.controller_person_id = staged_owner;
        let staged_ids = staged
            .iter()
            .map(|scope| scope.workspace_id.clone())
            .collect::<Vec<_>>();
        if commit.workspace_ids != staged_ids {
            return Err("Provisioning commit does not match staged scopes".into());
        }
        let config_directory = registry
            .config_path
            .parent()
            .ok_or("Invalid keeper registry path")?;
        let moved = relocate_provisioned_scope_dirs(config_directory, &mut staged, &commit)?;
        let relocated_hosts = staged
            .iter()
            .map(|scope| scope_host(scope).map(|host| (scope.workspace_id.clone(), host)))
            .collect::<Result<Vec<_>, _>>();
        staged_hosts = match relocated_hosts {
            Ok(hosts) => hosts,
            Err(error) => {
                rollback_provisioned_scope_dirs(&moved);
                return Err(error);
            }
        };
        next.additional_scopes.extend(staged.iter().cloned());
        next.provisioning_commits.push(commit);
        let bytes = match serde_json::to_vec(&next) {
            Ok(bytes) => bytes,
            Err(error) => {
                rollback_provisioned_scope_dirs(&moved);
                return Err(error.to_string());
            }
        };
        if let Err(error) =
            FileScopeStore::new(&registry.config_path).write_validated(&bytes, None, |_, _| Ok(()))
        {
            rollback_provisioned_scope_dirs(&moved);
            return Err(error);
        }
        for scope in &staged {
            let _ = fs::remove_file(
                scope
                    .state_path
                    .parent()
                    .unwrap_or(config_directory)
                    .join(".lighthouse-provisioning.json"),
            );
        }
        registry.config = next;
        registry.scopes.extend(staged_hosts);
        Ok(())
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
        let scope = registry
            .scopes
            .get(workspace)
            .ok_or("Unknown keeper scope")?;
        let owner = current_owner(scope)?;
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
                        == Some(owner.as_str())
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
        handshake.owner_workspace_ids = Some(owner_workspace_ids(&registry, &owner)?);
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

fn relocate_provisioned_scope_dirs(
    service_directory: &std::path::Path,
    staged: &mut [Config],
    commit: &ProvisioningCommit,
) -> Result<Vec<(PathBuf, PathBuf)>, String> {
    let scopes_root = service_directory.join("scopes");
    if !scopes_root.exists() {
        join::create_private_directory(&scopes_root).map_err(|error| error.to_string())?;
    }
    // Persist the scopes entry before the registry can durably reference it.
    // Repeat on retry: a prior attempt may have created it before sync failed.
    fs::File::open(service_directory)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| error.to_string())?;
    let mut moved = Vec::new();
    for scope in staged {
        let staging = scope
            .state_path
            .parent()
            .ok_or("Invalid staged scope state path")?
            .to_path_buf();
        let key = URL_SAFE_NO_PAD.encode(Sha256::digest(scope.workspace_id.as_bytes()));
        let destination = scopes_root.join(key);
        if destination.exists() {
            let marker_path = destination.join(".lighthouse-provisioning.json");
            let marker_bytes = match fs::read(&marker_path) {
                Ok(bytes) => bytes,
                Err(_) => {
                    rollback_provisioned_scope_dirs(&moved);
                    return Err(
                        "Persistent scope directory already exists without registry entry".into(),
                    );
                }
            };
            let marker: ScopeActivationMarker = match serde_json::from_slice(&marker_bytes) {
                Ok(marker) => marker,
                Err(_) => {
                    rollback_provisioned_scope_dirs(&moved);
                    return Err("Invalid orphaned scope activation marker".into());
                }
            };
            if marker != ScopeActivationMarker::new(commit, &scope.workspace_id)
                || !destination.join("state.json").is_file()
            {
                rollback_provisioned_scope_dirs(&moved);
                return Err("Persistent scope directory belongs to another activation".into());
            }
            if let Err(error) = fs::remove_dir_all(&staging) {
                rollback_provisioned_scope_dirs(&moved);
                return Err(error.to_string());
            }
            scope.state_path = destination.join("state.json");
            continue;
        }
        let marker =
            match serde_json::to_vec(&ScopeActivationMarker::new(commit, &scope.workspace_id)) {
                Ok(marker) => marker,
                Err(error) => {
                    rollback_provisioned_scope_dirs(&moved);
                    return Err(error.to_string());
                }
            };
        if let Err(error) =
            write_scope_marker(&staging.join(".lighthouse-provisioning.json"), &marker)
        {
            rollback_provisioned_scope_dirs(&moved);
            return Err(error);
        }
        if let Err(error) = fs::rename(&staging, &destination) {
            rollback_provisioned_scope_dirs(&moved);
            return Err(error.to_string());
        }
        moved.push((staging, destination.clone()));
        scope.state_path = destination.join("state.json");
    }
    if let Err(error) = fs::File::open(&scopes_root).and_then(|directory| directory.sync_all()) {
        rollback_provisioned_scope_dirs(&moved);
        return Err(error.to_string());
    }
    Ok(moved)
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct ScopeActivationMarker {
    pairing_id: String,
    operation_id: String,
    transcript_hash: String,
    invitation_id: String,
    snapshot_hash: String,
    future_boards: bool,
    workspace_id: String,
}

impl ScopeActivationMarker {
    fn new(commit: &ProvisioningCommit, workspace_id: &str) -> Self {
        Self {
            pairing_id: commit.pairing_id.clone(),
            operation_id: commit.operation_id.clone(),
            transcript_hash: commit.transcript_hash.clone(),
            invitation_id: commit.invitation_id.clone(),
            snapshot_hash: commit.snapshot_hash.clone(),
            future_boards: commit.future_boards,
            workspace_id: workspace_id.to_owned(),
        }
    }
}

fn write_scope_marker(path: &std::path::Path, bytes: &[u8]) -> Result<(), String> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|error| error.to_string())?;
    file.write_all(bytes).map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())
}

fn rollback_provisioned_scope_dirs(moved: &[(PathBuf, PathBuf)]) {
    for (staging, destination) in moved.iter().rev() {
        if std::fs::rename(destination, staging).is_err() {
            let _ = std::fs::remove_dir_all(destination);
        }
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
        if let Some(owner) = registry
            .scopes
            .get(workspace_id)
            .map(current_owner)
            .transpose()?
        {
            if request
                .peer
                .pointer("/advertisement/payload/personId")
                .and_then(Value::as_str)
                == Some(owner.as_str())
            {
                response["ownerWorkspaceIds"] = json!(owner_workspace_ids(&registry, &owner)?);
            }
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
    fn prepare_owner_offer(
        &mut self,
        bytes: &[u8],
    ) -> Result<Option<NativeOwnerOfferSnapshot>, String> {
        let value: Value =
            serde_json::from_slice(bytes).map_err(|_| "Invalid keeper owner offer")?;
        let mut registry = self
            .registry
            .lock()
            .map_err(|_| "Keeper registry lock poisoned")?;
        let workspace_id = value["workspaceId"]
            .as_str()
            .filter(|id| !id.is_empty())
            .ok_or("Missing keeper scope id")?;
        let controller = self.peer.person_id.as_str();
        if value["controllerPersonId"].as_str() != Some(controller) || value["version"] != 1 {
            return Err("Keeper owner offer does not match authenticated owner".into());
        }
        let known_owner = registry
            .scopes
            .get(workspace_id)
            .map(current_owner)
            .transpose()?;
        let authorized = if let Some(owner) = known_owner {
            owner == controller
        } else {
            owner_follows_future_boards(&registry, controller)?
        };
        if !authorized {
            return Err("Keeper owner offer is not authorized by this owner's policy".into());
        }
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
        let owner_public_key = envelope["ownerPublicKey"]
            .as_str()
            .ok_or("Missing owner public key")?;
        if public_key_id(owner_public_key)? != controller {
            return Err("Keeper offer owner key mismatch".into());
        }
        let owner_certificates: Vec<DeviceCertificate> =
            serde_json::from_value(envelope["ownerCertificates"].clone())
                .map_err(|_| "Invalid owner certificates")?;
        let owner = PublicIdentity {
            person_id: controller.to_owned(),
            public_key: owner_public_key.to_owned(),
            display_name: String::new(),
        };
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
        let verified_issuer = verify_workspace_member_bundle(
            issuer.clone(),
            VerifyWorkspaceMemberOptions {
                workspace_id: Some(workspace_id.to_owned()),
                owner_person_id: Some(controller.to_owned()),
                owner_public_key: Some(owner_public_key.to_owned()),
                owner_certificates: owner_certificates.clone(),
                ..Default::default()
            },
            match_lighthouse::now_ms()?,
        )?;
        if verified_issuer.role != WorkspaceRole::Owner
            || verified_issuer.payload.person_id != controller
            || verified_issuer.payload.endpoint != self.peer.endpoint
        {
            return Err("Keeper offer issuer differs from authenticated owner".into());
        }
        let service_identity_seed: [u8; 32] = registry
            .config
            .identity_seed
            .as_slice()
            .try_into()
            .map_err(|_| "Invalid keeper identity seed")?;
        let service_person_id = public_key_id(&meta_mesh_core::public_key_from_seed(
            &service_identity_seed,
        )?)?;
        let grant: meta_mesh_core::WorkspaceGrant = serde_json::from_value(value["grant"].clone())
            .map_err(|_| "Missing signed keeper scope grant")?;
        if verify_workspace_grant(
            &grant,
            workspace_id,
            &service_person_id,
            &owner,
            &owner_certificates,
        )? != WorkspaceRole::Visitor
        {
            return Err("Keeper offer grant does not authorize visitor access".into());
        }
        let manifest = workspace
            .get("authorization")
            .cloned()
            .ok_or("Missing authorization manifest")?;
        if manifest["kind"] != "workspace-authorization-manifest"
            || manifest["version"] != 2
            || manifest["workspaceId"] != workspace_id
        {
            return Ok(None);
        }
        let candidate = URL_SAFE_NO_PAD
            .decode(
                workspace["bytes"]
                    .as_str()
                    .ok_or("Missing owner document")?,
            )
            .map_err(|_| "Invalid owner document encoding")?;
        let local = if let Some(scope) = registry.scopes.get_mut(workspace_id) {
            scope.store.snapshot()?.document
        } else {
            automerge::AutoCommit::new().save()
        };
        Ok(Some(NativeOwnerOfferSnapshot {
            workspace_id: workspace_id.to_owned(),
            candidate,
            local,
            manifest,
        }))
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
        let workspace_id = value["workspaceId"]
            .as_str()
            .filter(|id| !id.is_empty())
            .ok_or("Missing keeper scope id")?;
        let controller = self.peer.person_id.as_str();
        if value["controllerPersonId"].as_str() != Some(controller)
            || value["version"] != 1
            || self.store.authority()?.expected_current_owner.person_id != controller
        {
            return Err("Keeper offer is not from this scope's verified owner".into());
        }
        if registry
            .scopes
            .get(workspace_id)
            .map(current_owner)
            .transpose()?
            .is_some_and(|owner| owner != controller)
        {
            return Err("Keeper offer targets another owner's scope".into());
        }
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
        let mut scope = join::prepare_config(
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
        scope.controller_person_id = Some(controller.to_owned());
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
