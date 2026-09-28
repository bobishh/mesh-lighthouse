use std::{
    collections::{HashMap, HashSet},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use iroh::{EndpointAddr, EndpointId};
use match_lighthouse::now_ms;
use meta_mesh_native::{NativeBrowserConnection, NativeNode, NativeScopeService, publish_scope_to};
use tokio::sync::Mutex;

use crate::keeper::KeeperHost;

type Service = Arc<Mutex<NativeScopeService<KeeperHost>>>;

/// Each scope/route owns its retry loop. Network waits never hold the service
/// lock or postpone replication of another board.
pub(crate) async fn run(
    node: Arc<NativeNode>,
    service: Service,
    host: KeeperHost,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut workers = HashMap::<(String, String), tokio::task::JoinHandle<()>>::new();
    let mut authorized = HashSet::<String>::new();
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tick.tick().await;
        let mut targets = HashMap::new();
        for (workspace, secret, routes) in host.scopes()? {
            for route in routes {
                if route != node.endpoint_id().to_string() {
                    targets.insert((workspace.clone(), route), secret.clone());
                }
            }
        }
        let next_authorized = targets
            .keys()
            .map(|(_, route)| route.clone())
            .collect::<HashSet<_>>();
        for route in next_authorized.difference(&authorized) {
            if let Ok(id) = EndpointId::from_str(route) {
                node.authorize_peer(id);
            }
        }
        for route in authorized.difference(&next_authorized) {
            if let Ok(id) = EndpointId::from_str(route) {
                node.revoke_peer(&id);
            }
        }
        authorized = next_authorized;
        let removed = workers
            .keys()
            .filter(|key| !targets.contains_key(*key))
            .cloned()
            .collect::<Vec<_>>();
        for (workspace, route) in removed {
            if let Some(worker) = workers.remove(&(workspace.clone(), route.clone())) {
                worker.abort();
            }
            service.lock().await.forget_peer(&workspace, &route);
        }
        for ((workspace, route), secret) in targets {
            let key = (workspace.clone(), route.clone());
            if workers
                .get(&key)
                .is_some_and(|worker| !worker.is_finished())
            {
                continue;
            }
            let peer_node = Arc::clone(&node);
            let peer_service = Arc::clone(&service);
            let host_for_worker = host.clone();
            workers.insert(
                key,
                tokio::spawn(async move {
                    replicate(
                        peer_node,
                        peer_service,
                        host_for_worker,
                        workspace,
                        secret,
                        route,
                    )
                    .await;
                }),
            );
        }
    }
}

async fn serve_frames(
    connection: Arc<NativeBrowserConnection>,
    service: Service,
    route: String,
    workspace: String,
) -> Result<(), String> {
    let trace = std::env::var_os("LIGHTHOUSE_TRACE_SYNC").is_some();
    loop {
        if trace {
            eprintln!("Scope {workspace} waiting for stream");
        }
        let request = connection
            .accept()
            .await
            .map_err(|error| error.to_string())?;
        let kind = meta_mesh_core::PairingCodec::inspect(request.payload())
            .map(|header| header.frame_type)
            .unwrap_or_else(|_| "invalid".into());
        if trace {
            eprintln!("Scope {workspace} receiving {kind}");
        }
        let started = std::time::Instant::now();
        let mut guard = service.lock().await;
        let waited = started.elapsed();
        let response = guard.receive(&route, request.payload(), now_ms()?);
        drop(guard);
        if trace {
            eprintln!(
                "Scope {workspace} processed {kind} (lock {waited:?}, total {:?})",
                started.elapsed()
            );
        }
        match response {
            Ok(response) => {
                request
                    .respond(response.as_deref().unwrap_or_default())
                    .await
                    .map_err(|error| error.to_string())?;
                if trace {
                    eprintln!("Scope {workspace} responded {kind}");
                }
            }
            Err(error) => {
                // Invalid or unpersisted data receives no success receipt. Drop
                // this stream while preserving unrelated valid streams.
                eprintln!("Lighthouse rejected scope frame: {error}");
            }
        }
    }
}

async fn replicate(
    node: Arc<NativeNode>,
    service: Service,
    host: KeeperHost,
    workspace: String,
    secret: String,
    route: String,
) {
    let Ok(id) = EndpointId::from_str(&route) else {
        return;
    };
    let mut failures = 0u32;
    loop {
        let result = async {
            let connection = Arc::new(node.connect_browser(EndpointAddr::new(id), Duration::from_secs(12))
                .await.map_err(|error| error.to_string())?);
            let mut lifetime = PeerLifetime { connection: Arc::clone(&connection), receiver: None };
            let handshake = service.lock().await.prepare_connect(&workspace, &secret)?;
            let handshake = host.attach_owner_inventory(&workspace, &route, &secret, handshake)?;
            let response = match connection.exchange(&handshake, Duration::from_secs(12)).await {
                Ok(response) => response,
                Err(error) => { connection.close(); return Err(error.to_string()); }
            };
            if let Err(error) = service.lock().await.complete_connect(&workspace, &secret, &route, &response, now_ms()?) {
                connection.close(); return Err(error);
            }
            eprintln!("Lighthouse connected workspace {workspace}");
            lifetime.receiver = Some(tokio::spawn(serve_frames(Arc::clone(&connection), Arc::clone(&service), route.clone(), workspace.clone())));
            let receiver = lifetime.receiver.as_mut().expect("receiver installed");
            let mut tick = tokio::time::interval(Duration::from_secs(1));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let result: Result<(), String> = loop {
                tokio::select! {
                    result = &mut *receiver => break Err(result.map_err(|error| error.to_string()).and_then(|result| result).err().unwrap_or_else(|| "Scope receiver ended".into())),
                    _ = tick.tick() => {
                        if let Err(error) = publish_scope_to(&connection, &service, &workspace, &route, now_ms()?, Duration::from_secs(12)).await {
                            break Err(error);
                        }
                        failures = 0;
                    }
                }
            };
            drop(lifetime);
            result
        }.await;
        service.lock().await.forget_peer(&workspace, &route);
        if let Err(error) = result {
            eprintln!("Lighthouse scope {workspace} reconnecting: {error}");
        }
        failures = failures.saturating_add(1);
        tokio::time::sleep(Duration::from_secs(match failures {
            1 => 1,
            2 => 2,
            3 => 5,
            _ => 10,
        }))
        .await;
    }
}

struct PeerLifetime {
    connection: Arc<NativeBrowserConnection>,
    receiver: Option<tokio::task::JoinHandle<Result<(), String>>>,
}
impl Drop for PeerLifetime {
    fn drop(&mut self) {
        if let Some(receiver) = &self.receiver {
            receiver.abort();
        }
        self.connection.close();
    }
}
