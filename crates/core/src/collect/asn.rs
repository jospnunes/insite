//! Who owns an IP address, through Team Cymru's public DNS service: no API key,
//! no HTTP request, just two TXT queries.

use std::net::IpAddr;

use hickory_resolver::proto::rr::RecordType;

use super::dns::Resolver;
use crate::snapshot::{AsnLookup, DnsResult};

pub async fn lookup(resolver: &Resolver, ip: IpAddr) -> AsnLookup {
    let mut result = AsnLookup {
        ip,
        asn: None,
        prefix: None,
        country: None,
        name: None,
        error: None,
    };
    // "13335 | 104.16.0.0/13 | US | arin | 2014-03-28"; several ASNs may share the first field.
    let origin = match resolver.query(&origin_name(ip), RecordType::TXT).await {
        DnsResult::Records(records) => records.into_iter().next(),
        DnsResult::Failed(e) => {
            result.error = Some(e);
            return result;
        }
        _ => None,
    };
    let Some(origin) = origin else {
        result.error = Some("no AS data returned for this address".into());
        return result;
    };
    let fields: Vec<&str> = origin.split('|').map(str::trim).collect();
    result.asn = fields
        .first()
        .and_then(|f| f.split_whitespace().next())
        .and_then(|a| a.parse().ok());
    result.prefix = fields.get(1).filter(|f| !f.is_empty()).map(|f| (*f).to_owned());
    result.country = fields.get(2).filter(|f| !f.is_empty()).map(|f| (*f).to_owned());

    // "13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US"
    if let Some(asn) = result.asn
        && let DnsResult::Records(records) = resolver.query(&format!("AS{asn}.asn.cymru.com"), RecordType::TXT).await
    {
        result.name = records
            .first()
            .and_then(|r| r.split('|').nth(4))
            .map(|n| n.trim().to_owned())
            .filter(|n| !n.is_empty());
    }
    result
}

/// `9.3.21.104.origin.asn.cymru.com` for IPv4, nibbles for IPv6.
pub fn origin_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, d] = v4.octets();
            format!("{d}.{c}.{b}.{a}.origin.asn.cymru.com")
        }
        IpAddr::V6(v6) => {
            let nibbles: Vec<String> = v6
                .octets()
                .iter()
                .rev()
                .flat_map(|byte| [byte & 0x0f, byte >> 4])
                .map(|n| format!("{n:x}"))
                .collect();
            format!("{}.origin6.asn.cymru.com", nibbles.join("."))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_names() {
        assert_eq!(
            origin_name("104.21.3.9".parse().unwrap()),
            "9.3.21.104.origin.asn.cymru.com"
        );
        let v6 = origin_name("2606:4700::1".parse().unwrap());
        assert!(v6.starts_with("1.0.0.0.0.0.0.0."));
        assert!(v6.ends_with("0.0.7.4.6.0.6.2.origin6.asn.cymru.com"));
    }
}
