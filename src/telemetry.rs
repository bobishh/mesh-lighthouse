//! Bounded, asynchronous diagnostic delivery. Never part of replication commits.
use serde::{Deserialize, Serialize};
use std::{sync::OnceLock, time::Duration};
use tokio::sync::mpsc;

static SINK: OnceLock<mpsc::Sender<Event>> = OnceLock::new();

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub timestamp_ms: u64,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub session_id: String,
    pub event: String,
    #[serde(default)]
    pub workspace_id: String,
    #[serde(default)]
    pub peer_id: String,
    #[serde(default)]
    pub record_id: String,
    #[serde(default)]
    pub connection_id: String,
    #[serde(default)]
    pub phase: String,
    #[serde(default)]
    pub duration_ms: u64,
    #[serde(default)]
    pub outcome: String,
}

impl Event {
    pub fn new(event: &str, workspace: &str, record: &str, phase: &str, duration: u64) -> Self {
        Self {
            timestamp_ms: crate::now_ms().unwrap_or(0).max(0) as u64,
            source: "lighthouse".into(),
            session_id: String::new(),
            event: event.into(),
            workspace_id: workspace.into(),
            peer_id: String::new(),
            record_id: record.into(),
            connection_id: String::new(),
            phase: phase.into(),
            duration_ms: duration,
            outcome: "ok".into(),
        }
    }

    pub fn valid(&self) -> bool {
        let now = crate::now_ms().unwrap_or(0).max(0) as u64;
        self.timestamp_ms <= now.saturating_add(300_000)
            && self.timestamp_ms >= now.saturating_sub(14 * 86_400_000)
            && self.duration_ms <= 86_400_000
            && !self.event.is_empty()
            && [
                &self.source,
                &self.session_id,
                &self.event,
                &self.workspace_id,
                &self.peer_id,
                &self.record_id,
                &self.connection_id,
                &self.phase,
                &self.outcome,
            ]
            .iter()
            .all(|value| {
                value.len() <= 160
                    && value
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || b"._:-".contains(&c))
            })
    }
}

pub fn enabled() -> bool {
    SINK.get().is_some()
}

pub fn emit(event: Event) {
    if event.valid() {
        if let Some(sender) = SINK.get() {
            let _ = sender.try_send(event);
        }
    }
}

pub fn start() {
    let Ok(url) = std::env::var("LIGHTHOUSE_TELEMETRY_URL") else {
        return;
    };
    let user = std::env::var("CLICKHOUSE_USER").unwrap_or_else(|_| "lighthouse".into());
    let password = std::env::var("CLICKHOUSE_PASSWORD").unwrap_or_default();
    let (sender, mut receiver) = mpsc::channel::<Event>(4096);
    if SINK.set(sender).is_err() {
        return;
    }
    tokio::spawn(async move {
        let client = match reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
        {
            Ok(client) => client,
            Err(_) => return,
        };
        let ddl = "CREATE TABLE IF NOT EXISTS default.sync_events (timestamp_ms UInt64, received_at DateTime DEFAULT now(), source LowCardinality(String), session_id String, event LowCardinality(String), workspace_id String, peer_id String, record_id String, connection_id String, phase LowCardinality(String), duration_ms UInt64, outcome LowCardinality(String)) ENGINE=MergeTree ORDER BY (workspace_id, record_id, timestamp_ms, event) TTL received_at + INTERVAL 14 DAY";
        let mut ready = false;
        while let Some(first) = receiver.recv().await {
            let mut batch = vec![first];
            tokio::time::sleep(Duration::from_millis(200)).await;
            while batch.len() < 100 {
                match receiver.try_recv() {
                    Ok(event) => batch.push(event),
                    Err(_) => break,
                }
            }
            if !ready {
                ready = client
                    .post(&url)
                    .basic_auth(&user, Some(&password))
                    .body(ddl)
                    .send()
                    .await
                    .is_ok_and(|response| response.status().is_success());
            }
            let body = batch
                .iter()
                .filter_map(|event| serde_json::to_string(event).ok())
                .collect::<Vec<_>>()
                .join("\n");
            let success = ready
                && client
                    .post(&url)
                    .basic_auth(&user, Some(&password))
                    .query(&[(
                        "query",
                        "INSERT INTO default.sync_events FORMAT JSONEachRow",
                    )])
                    .body(body)
                    .send()
                    .await
                    .is_ok_and(|response| response.status().is_success());
            if !success {
                eprintln!("Telemetry batch unavailable; replication unaffected");
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn diagnostic_ids_are_allowed_but_text_urls_and_unknown_fields_are_rejected() {
        let mut event = Event::new(
            "chat.persisted",
            "workspace-1",
            "device-1:message-1",
            "persist",
            12,
        );
        assert!(event.valid());
        event.record_id = "private message text".into();
        assert!(!event.valid());
        event.record_id = "https://example.com/key?token=secret".into();
        assert!(!event.valid());
        let mut value =
            serde_json::to_value(Event::new("chat.persisted", "w", "m", "persist", 1)).unwrap();
        value["body"] = serde_json::json!("secret");
        assert!(serde_json::from_value::<Event>(value).is_err());
    }
}
