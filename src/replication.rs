use std::{
    collections::{HashMap, HashSet},
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use iroh::{EndpointAddr, EndpointId};
use match_lighthouse::now_ms;
use meta_mesh_native::{NativeBrowserConnection, NativeNode, NativeScopeService, publish_scope_to};
use tokio::sync::Mutex;

use crate::keeper::KeeperHost;

type Service = Arc<Mutex<NativeScopeService<KeeperHost>>>;
static NEXT_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);

fn prefix(value: &str) -> &str {
    value.get(..8).unwrap_or(value)
}

fn frame_label(frame: &str) -> &'static str {
    match frame {
        "mesh-handshake-request" => "mesh-handshake-request",
        "sync-heartbeat" => "sync-heartbeat",
        "sync-update" => "sync-update",
        "mesh-automerge-sync" => "mesh-automerge-sync",
        "mesh-control-sync" => "mesh-control-sync",
        "mesh-durable-batch" => "mesh-durable-batch",
        "mesh-owner-workspace-offer" => "mesh-owner-workspace-offer",
        "mesh-iroh-gossip" => "mesh-iroh-gossip",
        "mesh-blob-request-v1" => "mesh-blob-request-v1",
        "mesh-handoff-request" => "mesh-handoff-request",
        _ => "other",
    }
}

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
    connection_id: String,
    trace: bool,
) -> Result<(), String> {
    loop {
        let request = match connection.accept().await {
            Ok(request) => request,
            Err(error) => {
                if trace {
                    eprintln!(
                        "trace.sync event=stream.accept.failed connection={connection_id} workspace={} route={} cause=peer_or_transport_closed",
                        prefix(&workspace),
                        prefix(&route)
                    );
                }
                return Err(error.to_string());
            }
        };
        let kind = meta_mesh_core::PairingCodec::inspect(request.payload())
            .map(|header| header.frame_type)
            .unwrap_or_else(|_| "invalid".into());
        let kind = frame_label(&kind);
        let started = std::time::Instant::now();
        if trace {
            eprintln!(
                "trace.sync event=frame.start connection={connection_id} workspace={} route={} frame={kind}",
                prefix(&workspace),
                prefix(&route)
            );
        }
        let service_started = std::time::Instant::now();
        let mut guard = service.lock().await;
        let waited = service_started.elapsed();
        let receive_started = std::time::Instant::now();
        let response = guard.receive(&route, request.payload(), now_ms()?);
        let receive_elapsed = receive_started.elapsed();
        drop(guard);
        match response {
            Ok(response) => {
                let send_started = std::time::Instant::now();
                let result = request
                    .respond(response.as_deref().unwrap_or_default())
                    .await;
                if trace {
                    eprintln!(
                        "trace.sync event=frame.done connection={connection_id} workspace={} route={} frame={kind} result={} lock_ms={} receive_ms={} respond_ms={} total_ms={}",
                        prefix(&workspace),
                        prefix(&route),
                        if result.is_ok() { "ok" } else { "error" },
                        waited.as_millis(),
                        receive_elapsed.as_millis(),
                        send_started.elapsed().as_millis(),
                        started.elapsed().as_millis()
                    );
                }
                result.map_err(|error| error.to_string())?;
            }
            Err(error) => {
                // Invalid or unpersisted data receives no success receipt. Drop
                // this stream while preserving unrelated valid streams.
                if trace {
                    eprintln!(
                        "trace.sync event=frame.done connection={connection_id} workspace={} route={} frame={kind} result=rejected lock_ms={} receive_ms={} total_ms={}",
                        prefix(&workspace),
                        prefix(&route),
                        waited.as_millis(),
                        receive_elapsed.as_millis(),
                        started.elapsed().as_millis()
                    );
                }
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
        let connection_id = format!(
            "native-{}",
            NEXT_CONNECTION_ID.fetch_add(1, Ordering::Relaxed)
        );
        let attempt_started = std::time::Instant::now();
        if std::env::var_os("LIGHTHOUSE_TRACE_SYNC").is_some() {
            eprintln!(
                "trace.sync event=connection.attempt.start connection={connection_id} retry={failures} workspace={} route={}",
                prefix(&workspace),
                prefix(&route)
            );
        }
        let result = async {
            let trace = std::env::var_os("LIGHTHOUSE_TRACE_SYNC").is_some();
            let connect_started = std::time::Instant::now();
            let connection = match node.connect_browser(EndpointAddr::new(id), Duration::from_secs(12)).await {
                Ok(connection) => Arc::new(connection),
                Err(error) => {
                    if trace {
                        eprintln!("trace.sync event=connection.dial.failed connection={connection_id} workspace={} route={} elapsed_ms={}", prefix(&workspace), prefix(&route), connect_started.elapsed().as_millis());
                    }
                    return Err(error.to_string());
                }
            };
            if trace {
                eprintln!("trace.sync event=connection.dial.connected connection={connection_id} workspace={} route={} elapsed_ms={}", prefix(&workspace), prefix(&route), connect_started.elapsed().as_millis());
            }
            let mut lifetime = PeerLifetime {
                connection: Arc::clone(&connection),
                receiver: None,
                connection_id: connection_id.clone(),
                workspace: workspace.clone(),
                route: route.clone(),
                trace,
                close_cause: "connection_setup_failed",
            };
            let lock_started = std::time::Instant::now();
            let mut service_guard = service.lock().await;
            let lock_wait = lock_started.elapsed();
            let prepare_started = std::time::Instant::now();
            let prepared = service_guard.prepare_connect(&workspace, &secret);
            let prepare_elapsed = prepare_started.elapsed();
            drop(service_guard);
            let handshake = match prepared {
                Ok(handshake) => handshake,
                Err(error) => {
                    if trace {
                        eprintln!("trace.sync event=handshake.failed connection={connection_id} workspace={} route={} lock_ms={} prepare_ms={} stage=prepare", prefix(&workspace), prefix(&route), lock_wait.as_millis(), prepare_elapsed.as_millis());
                    }
                    return Err(error);
                }
            };
            let handshake = match host.attach_owner_inventory(&workspace, &route, &secret, handshake) {
                Ok(handshake) => handshake,
                Err(error) => {
                    if trace {
                        eprintln!("trace.sync event=handshake.failed connection={connection_id} workspace={} route={} lock_ms={} prepare_ms={} stage=inventory", prefix(&workspace), prefix(&route), lock_wait.as_millis(), prepare_elapsed.as_millis());
                    }
                    return Err(error);
                }
            };
            let handshake_started = std::time::Instant::now();
            let response = match connection.exchange(&handshake, Duration::from_secs(12)).await {
                Ok(response) => response,
                Err(error) => {
                    lifetime.close_cause = "handshake_exchange_failed";
                    connection.close();
                    if trace {
                        eprintln!("trace.sync event=handshake.failed connection={connection_id} workspace={} route={} lock_ms={} prepare_ms={} elapsed_ms={} stage=exchange", prefix(&workspace), prefix(&route), lock_wait.as_millis(), prepare_elapsed.as_millis(), handshake_started.elapsed().as_millis());
                    }
                    return Err(error.to_string());
                }
            };
            if trace {
                eprintln!("trace.sync event=handshake.exchange.done connection={connection_id} workspace={} route={} lock_ms={} prepare_ms={} elapsed_ms={}", prefix(&workspace), prefix(&route), lock_wait.as_millis(), prepare_elapsed.as_millis(), handshake_started.elapsed().as_millis());
            }
            let admission_started = std::time::Instant::now();
            let admission_lock_started = std::time::Instant::now();
            let mut service_guard = service.lock().await;
            let admission_lock_wait = admission_lock_started.elapsed();
            let admission = service_guard.complete_connect(&workspace, &secret, &route, &response, now_ms()?);
            drop(service_guard);
            if let Err(error) = admission {
                lifetime.close_cause = "handshake_admission_rejected";
                connection.close();
                if trace {
                    eprintln!("trace.sync event=handshake.failed connection={connection_id} workspace={} route={} lock_ms={} elapsed_ms={} stage=admission", prefix(&workspace), prefix(&route), admission_lock_wait.as_millis(), admission_started.elapsed().as_millis());
                }
                return Err(error);
            }
            if trace {
                eprintln!("trace.sync event=handshake.admitted connection={connection_id} workspace={} route={} lock_ms={} elapsed_ms={}", prefix(&workspace), prefix(&route), admission_lock_wait.as_millis(), admission_started.elapsed().as_millis());
            }
            eprintln!("Lighthouse connected workspace {workspace} route {} connection {connection_id}", prefix(&route));
            lifetime.receiver = Some(tokio::spawn(serve_frames(Arc::clone(&connection), Arc::clone(&service), route.clone(), workspace.clone(), connection_id.clone(), trace)));
            lifetime.close_cause = "peer_lifetime_ended";
            let receiver = lifetime.receiver.as_mut().expect("receiver installed");
            let mut tick = tokio::time::interval(Duration::from_secs(1));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let result: Result<(), String> = loop {
                tokio::select! {
                result = &mut *receiver => break Err(result.map_err(|error| error.to_string()).and_then(|result| result).err().unwrap_or_else(|| "Scope receiver ended".into())),
                    _ = tick.tick() => {
                        let publish_started = std::time::Instant::now();
                        if trace {
                            eprintln!("trace.sync event=publish.start connection={connection_id} workspace={} route={}", prefix(&workspace), prefix(&route));
                        }
                        if let Err(error) = publish_scope_to(&connection, &service, &workspace, &route, now_ms()?, Duration::from_secs(12)).await {
                            lifetime.close_cause = "scope_publish_failed";
                            if trace {
                                eprintln!("trace.sync event=publish.failed connection={connection_id} workspace={} route={} elapsed_ms={}", prefix(&workspace), prefix(&route), publish_started.elapsed().as_millis());
                            }
                            break Err(error);
                        }
                        if trace {
                            eprintln!("trace.sync event=publish.done connection={connection_id} workspace={} route={} elapsed_ms={}", prefix(&workspace), prefix(&route), publish_started.elapsed().as_millis());
                        }
                        failures = 0;
                    }
                }
            };
            if lifetime.close_cause == "peer_lifetime_ended" {
                lifetime.close_cause = if receiver.is_finished() {
                    "scope_receiver_ended"
                } else {
                    "worker_retry"
                };
            }
            drop(lifetime);
            result
        }.await;
        service.lock().await.forget_peer(&workspace, &route);
        if let Err(error) = result {
            eprintln!("Lighthouse scope {workspace} reconnecting: {error}");
        }
        failures = failures.saturating_add(1);
        let retry_delay = Duration::from_secs(match failures {
            1 => 1,
            2 => 2,
            3 => 5,
            _ => 10,
        });
        if std::env::var_os("LIGHTHOUSE_TRACE_SYNC").is_some() {
            eprintln!(
                "trace.sync event=connection.attempt.done connection={connection_id} retry={} workspace={} route={} result=retry elapsed_ms={} next_retry_ms={} ",
                failures,
                prefix(&workspace),
                prefix(&route),
                attempt_started.elapsed().as_millis(),
                retry_delay.as_millis()
            );
        }
        tokio::time::sleep(retry_delay).await;
    }
}

struct PeerLifetime {
    connection: Arc<NativeBrowserConnection>,
    receiver: Option<tokio::task::JoinHandle<Result<(), String>>>,
    connection_id: String,
    workspace: String,
    route: String,
    trace: bool,
    close_cause: &'static str,
}
impl Drop for PeerLifetime {
    fn drop(&mut self) {
        if let Some(receiver) = &self.receiver {
            receiver.abort();
        }
        if self.trace {
            eprintln!(
                "trace.sync event=connection.close connection={} workspace={} route={} cause={}",
                self.connection_id,
                prefix(&self.workspace),
                prefix(&self.route),
                self.close_cause
            );
        }
        self.connection.close();
    }
}
