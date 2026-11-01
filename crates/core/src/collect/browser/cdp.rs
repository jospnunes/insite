//! A minimal Chrome DevTools Protocol client over `--remote-debugging-pipe`:
//! JSON messages terminated by a NUL byte, commands on the child's fd 3,
//! responses and events on its fd 4. About twenty commands, no generated types.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};
use tokio::sync::{mpsc, oneshot};

use crate::collect::deadline::Deadline;

/// An event from the browser: method, params and the session it belongs to.
#[derive(Debug)]
pub struct Event {
    pub method: String,
    pub params: Value,
    pub session: Option<String>,
}

type Pending = Arc<Mutex<HashMap<u64, oneshot::Sender<Result<Value, String>>>>>;

pub struct Connection {
    writer: Mutex<Box<dyn Write + Send>>,
    next_id: AtomicU64,
    pending: Pending,
}

impl Connection {
    /// Starts the reader thread; events arrive on the returned channel until the
    /// browser closes the pipe.
    pub fn new(
        reader: impl std::io::Read + Send + 'static,
        writer: impl Write + Send + 'static,
    ) -> (Self, mpsc::UnboundedReceiver<Event>) {
        let pending: Pending = Arc::default();
        let (events_tx, events) = mpsc::unbounded_channel();
        let waiting = pending.clone();
        std::thread::spawn(move || {
            let mut reader = BufReader::with_capacity(1 << 20, reader);
            let mut message = Vec::new();
            loop {
                message.clear();
                match reader.read_until(0, &mut message) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
                if message.last() == Some(&0) {
                    message.pop();
                }
                let Ok(value) = serde_json::from_slice::<Value>(&message) else {
                    continue;
                };
                if let Some(id) = value.get("id").and_then(Value::as_u64) {
                    let result = match value.get("error") {
                        Some(e) => Err(e
                            .get("message")
                            .and_then(Value::as_str)
                            .unwrap_or("CDP error")
                            .to_owned()),
                        None => Ok(value.get("result").cloned().unwrap_or(Value::Null)),
                    };
                    if let Some(tx) = waiting.lock().expect("pending map").remove(&id) {
                        let _ = tx.send(result);
                    }
                } else if let Some(method) = value.get("method").and_then(Value::as_str) {
                    let _ = events_tx.send(Event {
                        method: method.to_owned(),
                        params: value.get("params").cloned().unwrap_or(Value::Null),
                        session: value.get("sessionId").and_then(Value::as_str).map(str::to_owned),
                    });
                }
            }
            // The browser is gone: fail whatever still waits.
            for (_, tx) in waiting.lock().expect("pending map").drain() {
                let _ = tx.send(Err("the browser closed the connection".into()));
            }
        });
        let connection = Connection {
            writer: Mutex::new(Box::new(writer)),
            next_id: AtomicU64::new(1),
            pending,
        };
        (connection, events)
    }

    /// Sends a command and waits for its result, until the deadline.
    pub async fn call(
        &self,
        method: &str,
        params: Value,
        session: Option<&str>,
        deadline: &Deadline,
    ) -> Result<Value, String> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let mut message = json!({ "id": id, "method": method, "params": params });
        if let Some(s) = session {
            message["sessionId"] = json!(s);
        }
        let (tx, rx) = oneshot::channel();
        self.pending.lock().expect("pending map").insert(id, tx);
        let mut bytes = serde_json::to_vec(&message).expect("CDP messages serialize");
        bytes.push(0);
        {
            let mut writer = self.writer.lock().expect("pipe writer");
            writer
                .write_all(&bytes)
                .and_then(|_| writer.flush())
                .map_err(|e| format!("{method}: {e}"))?;
        }
        match deadline.run(rx).await {
            Some(Ok(result)) => result.map_err(|e| format!("{method}: {e}")),
            Some(Err(_)) => Err(format!("{method}: no answer")),
            None => {
                self.pending.lock().expect("pending map").remove(&id);
                Err(format!("{method}: deadline reached"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// A fake browser on the other side of two in-memory pipes.
    #[tokio::test]
    async fn matches_responses_and_forwards_events() {
        let (to_browser_read, to_browser_write) = std::io::pipe().unwrap();
        let (from_browser_read, mut from_browser_write) = std::io::pipe().unwrap();
        std::thread::spawn(move || {
            let mut reader = BufReader::new(to_browser_read);
            let mut buf = Vec::new();
            while reader.read_until(0, &mut buf).unwrap_or(0) > 0 {
                buf.pop();
                let msg: Value = serde_json::from_slice(&buf).unwrap();
                buf.clear();
                let id = msg["id"].as_u64().unwrap();
                let event = json!({"method": "Page.loadEventFired", "params": {"timestamp": 1.5}, "sessionId": "S"});
                let reply = match msg["method"].as_str().unwrap() {
                    "Fail.me" => json!({"id": id, "error": {"code": -32000, "message": "nope"}}),
                    _ => json!({"id": id, "result": {"echo": msg["params"]}}),
                };
                for m in [event, reply] {
                    let mut bytes = serde_json::to_vec(&m).unwrap();
                    bytes.push(0);
                    from_browser_write.write_all(&bytes).unwrap();
                }
            }
        });
        let (conn, mut events) = Connection::new(from_browser_read, to_browser_write);
        let deadline = Deadline::new(tokio::time::Instant::now() + Duration::from_secs(5), None);
        let result = conn
            .call("Echo.it", json!({"x": 1}), Some("S"), &deadline)
            .await
            .unwrap();
        assert_eq!(result["echo"]["x"], 1);
        assert_eq!(
            conn.call("Fail.me", json!({}), None, &deadline).await.unwrap_err(),
            "Fail.me: nope"
        );
        let event = events.recv().await.unwrap();
        assert_eq!(
            (event.method.as_str(), event.session.as_deref()),
            ("Page.loadEventFired", Some("S"))
        );
    }
}
