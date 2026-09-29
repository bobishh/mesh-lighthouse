use std::sync::Arc;

use meta_mesh_native::NativeNode;

use crate::{Config, ProvisioningCommit, join, keeper::KeeperHost, pairing::ProvisionedScope};

#[derive(Clone)]
pub(crate) struct ProvisioningService {
    host: KeeperHost,
    node: Arc<NativeNode>,
}

impl ProvisioningService {
    pub(crate) fn new(host: KeeperHost, node: Arc<NativeNode>) -> Self {
        Self { host, node }
    }

    pub(crate) fn durable_commit(
        &self,
        pairing_id: &str,
    ) -> Result<Option<ProvisioningCommit>, String> {
        self.host.provisioning_commit(pairing_id)
    }

    pub(crate) async fn provision(
        &self,
        pairing_id: &str,
        operation_id: &str,
        transcript_hash: &str,
        invitation: meta_mesh_core::WorkspaceJoinInvitation,
        workspace_ids: Vec<String>,
        future_boards: bool,
    ) -> Result<Vec<ProvisionedScope>, String> {
        let invitation_id = invitation.invitation_id.clone();
        let controller_person_id = invitation.issuer_person_id.clone();
        let expected_commit = ProvisioningCommit {
            pairing_id: pairing_id.into(),
            operation_id: operation_id.into(),
            transcript_hash: transcript_hash.into(),
            invitation_id: invitation_id.clone(),
            workspace_ids: workspace_ids.clone(),
            snapshot_hash: String::new(),
            future_boards,
            controller_person_id: Some(controller_person_id.clone()),
        };
        if let Some(previous) = self.host.provisioning_commit(pairing_id)? {
            if previous.pairing_id != expected_commit.pairing_id
                || previous.operation_id != expected_commit.operation_id
                || previous.transcript_hash != expected_commit.transcript_hash
                || previous.invitation_id != expected_commit.invitation_id
                || previous.workspace_ids != expected_commit.workspace_ids
                || previous.future_boards != expected_commit.future_boards
                || previous
                    .controller_person_id
                    .as_deref()
                    .is_some_and(|owner| owner != controller_person_id)
                || previous.snapshot_hash.is_empty()
            {
                return Err("Provisioning retry conflicts with durable activation".into());
            }
        }

        let config: Config = self.host.configuration()?;
        let service_directory = config
            .state_path
            .parent()
            .ok_or("Invalid Lighthouse state directory")?
            .to_path_buf();
        let host = self.host.clone();
        let result = join::provision_existing_identity(
            invitation,
            &workspace_ids,
            pairing_id,
            operation_id,
            transcript_hash,
            future_boards,
            &config,
            &self.node,
            &service_directory,
            move |staged, mut commit| {
                if commit
                    .controller_person_id
                    .as_deref()
                    .is_some_and(|owner| owner != controller_person_id)
                {
                    return Err("Provisioning controller differs from accepted invitation".into());
                }
                commit.controller_person_id = Some(controller_person_id);
                host.activate_provisioned_scopes(staged, commit)
            },
        )
        .await
        .map_err(|error| error.to_string())?;
        Ok(active_scopes(result))
    }
}

fn active_scopes(workspace_ids: Vec<String>) -> Vec<ProvisionedScope> {
    workspace_ids
        .into_iter()
        .map(|workspace_id| ProvisionedScope {
            workspace_id,
            status: "active".into(),
            error: None,
        })
        .collect()
}
