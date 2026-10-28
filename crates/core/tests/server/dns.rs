//! A tiny authoritative DNS server over UDP for the tests, built on hickory-proto.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

use hickory_resolver::proto::op::{Message, ResponseCode};
use hickory_resolver::proto::rr::rdata::{A, CAA, MX, NS, TXT};
use hickory_resolver::proto::rr::{Name, RData, Record};
use tokio::net::UdpSocket;

/// Zone data: name (no trailing dot) to records. A name present with no record of
/// the asked type answers NODATA; an absent name answers NXDOMAIN; a name listed
/// in `failing` answers SERVFAIL.
#[derive(Default)]
pub struct Zone {
    records: HashMap<String, Vec<RData>>,
    failing: Vec<String>,
}

impl Zone {
    pub fn a(mut self, name: &str, ip: &str) -> Self {
        self.add(name, RData::A(A(ip.parse().unwrap())));
        self
    }

    pub fn txt(mut self, name: &str, text: &str) -> Self {
        self.add(name, RData::TXT(TXT::new(vec![text.to_owned()])));
        self
    }

    pub fn mx(mut self, name: &str, preference: u16, exchange: &str) -> Self {
        self.add(name, RData::MX(MX::new(preference, Name::from_str(exchange).unwrap())));
        self
    }

    pub fn ns(mut self, name: &str, server: &str) -> Self {
        self.add(name, RData::NS(NS(Name::from_str(server).unwrap())));
        self
    }

    pub fn caa_issue(mut self, name: &str, ca: &str) -> Self {
        self.add(
            name,
            RData::CAA(CAA::new_issue(false, Some(Name::from_str(ca).unwrap()), vec![])),
        );
        self
    }

    pub fn failing(mut self, name: &str) -> Self {
        self.failing.push(name.to_owned());
        self
    }

    fn add(&mut self, name: &str, data: RData) {
        self.records.entry(name.to_ascii_lowercase()).or_default().push(data);
    }

    fn answer(&self, query: &Message) -> Message {
        let id = query.metadata.id;
        let op = query.metadata.op_code;
        let Some(q) = query.queries.first() else {
            return Message::error_msg(id, op, ResponseCode::FormErr);
        };
        let name = q.name().to_string().trim_end_matches('.').to_ascii_lowercase();
        let mut response = if self.failing.contains(&name) {
            Message::error_msg(id, op, ResponseCode::ServFail)
        } else {
            match self.records.get(&name) {
                None => Message::error_msg(id, op, ResponseCode::NXDomain),
                Some(records) => {
                    let mut m = Message::response(id, op);
                    for data in records.iter().filter(|d| d.record_type() == q.query_type()) {
                        m.add_answer(Record::from_rdata(q.name().clone(), 60, data.clone()));
                    }
                    m
                }
            }
        };
        response.metadata.authoritative = true;
        response.metadata.recursion_available = true;
        response.metadata.recursion_desired = query.metadata.recursion_desired;
        response.queries = query.queries.clone();
        response
    }
}

/// Serves `zone` on 127.0.0.1 and returns the address.
pub async fn serve(zone: Zone) -> SocketAddr {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((len, peer)) = socket.recv_from(&mut buf).await else {
                return;
            };
            let Ok(query) = Message::from_vec(&buf[..len]) else {
                continue;
            };
            if let Ok(bytes) = zone.answer(&query).to_vec() {
                let _ = socket.send_to(&bytes, peer).await;
            }
        }
    });
    addr
}
