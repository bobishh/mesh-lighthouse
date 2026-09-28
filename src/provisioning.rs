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

    pub(crate) async fn provision(
        &self,
        pairing_id: &str,
        operation_id: &str,
        transcript_hash: &str,
        invitation: meta_mesh_core::WorkspaceJoinInvitation,
        workspace_ids: Vec<String>,
    ) -> Result<Vec<ProvisionedScope>, String> {
        let invitation_id = invitation.invitation_id.clone();
        if let Some(previous) = self.host.provisioning_commit(pairing_id)? {
            let requested = ProvisioningCommit {
                pairing_id: pairing_id.into(),
                operation_id: operation_id.into(),
                transcript_hash: transcript_hash.into(),
                invitation_id,
                workspace_ids: workspace_ids.clone(),
            };
            if previous != requested {
                return Err("Provisioning retry conflicts with durable activation".into());
            }
            return Ok(active_scopes(workspace_ids));
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
            &config,
            &self.node,
            &service_directory,
            move |staged, commit| host.activate_provisioned_scopes(staged, commit),
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
