//! DNS-01 through dynamic updates (RFC 2136) signed with TSIG (RFC 8945), for BIND, Knot,
//! PowerDNS and any other primary that accepts them (W-DNS-03). Present adds one TXT record to
//! the RRset and cleanup deletes that record by its data, so other values (a wildcard's base
//! name) are never touched.
//!
//! Messages are built with hickory-proto's `update_message` and signed here with ring, so the
//! algorithms RFC 8945 allows are all available (hickory's own signer has no HMAC-SHA1).

use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use hickory_proto::op::{Message, Query, ResponseCode, update_message};
use hickory_proto::rr::rdata::TXT;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use rdock_acme::dns::{DnsError, DnsSolver};
use rdock_model::acme::{DnsTransport, Rfc2136Provider, parse_resolver};
use tracing::debug;

use crate::backoff::{ATTEMPTS, jittered};
use crate::zone::{ZoneFinder, normalize};

mod transport;
mod tsig;

use tsig::TsigKey;

/// TTL of challenge records.
const TTL: u32 = 60;

/// Dynamic updates to one primary nameserver.
#[derive(Debug)]
pub struct Rfc2136Dns {
    server: SocketAddr,
    transport: DnsTransport,
    /// `None` only with `insecure_unsigned: true`.
    key: Option<TsigKey>,
    zones: ZoneFinder,
}

/// One exchange's failure: final, or worth another attempt.
enum Failure {
    Final(DnsError),
    Retry(DnsError),
}

impl Rfc2136Dns {
    /// The provider for `config`. Refuses `hmac-md5`, and a missing key unless
    /// `insecure_unsigned` is set.
    pub fn new(config: &Rfc2136Provider) -> Result<Self, DnsError> {
        let server = parse_resolver(&config.nameserver).ok_or_else(|| {
            DnsError(format!(
                "nameserver `{}` is not an IP address with an optional port",
                config.nameserver
            ))
        })?;
        let key = match (&config.tsig_key_name, &config.tsig_secret) {
            _ if config.insecure_unsigned => None,
            (Some(name), Some(secret)) => Some(TsigKey::new(name, secret, config.tsig_algorithm)?),
            _ => {
                return Err(DnsError(
                    "rfc2136 needs `tsig_key_name` and `tsig_secret` (or `insecure_unsigned: true`)"
                        .into(),
                ));
            }
        };
        Ok(Self {
            server,
            transport: config.transport,
            key,
            zones: ZoneFinder::new(config.zone.as_deref()),
        })
    }

    /// The zone of `fqdn`: the closest name whose SOA the server answers with.
    async fn zone(&self, fqdn: &str) -> Result<String, DnsError> {
        self.zones
            .zone(
                "RFC 2136",
                fqdn,
                |name| async move { self.has_soa(&name).await },
            )
            .await
    }

    async fn has_soa(&self, name: &str) -> Result<bool, DnsError> {
        let name = dns_name(name)?;
        let mut query = Message::query();
        query.add_query(Query::query(name.clone(), RecordType::SOA));
        let answer = self.exchange(query, false).await?;
        match answer.metadata.response_code {
            ResponseCode::NoError | ResponseCode::NXDomain => Ok(answer
                .answers
                .iter()
                .any(|r| r.record_type() == RecordType::SOA && r.name == name)),
            code => Err(DnsError(format!(
                "{} answered {code} to the SOA query for `{name}`; set `zone`",
                self.server
            ))),
        }
    }

    /// Sends an update built for the zone of `fqdn` and checks the answer.
    async fn update(
        &self,
        fqdn: &str,
        value: &str,
        build: fn(Record, Name) -> Message,
    ) -> Result<(), DnsError> {
        let fqdn = normalize(fqdn);
        let zone = dns_name(&self.zone(&fqdn).await?)?;
        let name = dns_name(&fqdn)?;
        if !zone.zone_of(&name) {
            return Err(DnsError(format!("`{fqdn}` is not in the zone `{zone}`")));
        }
        let record = Record::from_rdata(name, TTL, RData::TXT(TXT::new(vec![value.to_owned()])));
        let answer = self.exchange(build(record, zone.clone()), true).await?;
        match answer.metadata.response_code {
            ResponseCode::NoError => Ok(()),
            code => Err(DnsError(format!(
                "{} refused the update of `{fqdn}` in `{zone}`: {code}{}",
                self.server,
                update_hint(code)
            ))),
        }
    }

    /// Sends `message` (signed when `sign` and a key is configured), retrying transport errors,
    /// timeouts and SERVFAIL up to [`ATTEMPTS`] times with jittered waits.
    async fn exchange(&self, message: Message, sign: bool) -> Result<Message, DnsError> {
        let mut retry = 0;
        loop {
            match self.attempt(message.clone(), sign).await {
                Ok(answer) => return Ok(answer),
                Err(Failure::Final(error)) => return Err(error),
                Err(Failure::Retry(error)) => {
                    retry += 1;
                    if retry >= ATTEMPTS {
                        return Err(error);
                    }
                    let wait = jittered(retry);
                    debug!(server = %self.server, ?wait, %error, "retrying the DNS exchange");
                    tokio::time::sleep(wait).await;
                }
            }
        }
    }

    async fn attempt(&self, mut message: Message, sign: bool) -> Result<Message, Failure> {
        let key = match &self.key {
            Some(key) if sign => Some(key.resolve().map_err(Failure::Final)?),
            _ => None,
        };
        let now = unix_now();
        let request_mac = match &key {
            Some(key) => Some(key.sign(&mut message, now).map_err(Failure::Final)?),
            None => None,
        };
        let request = message
            .to_vec()
            .map_err(|e| Failure::Final(DnsError(format!("cannot encode the DNS message: {e}"))))?;
        let bytes = transport::exchange(self.transport, self.server, &request, message.metadata.id)
            .await
            .map_err(|e| Failure::Retry(DnsError(format!("{}: {e}", self.server))))?;
        let answer = Message::from_vec(&bytes).map_err(|e| {
            Failure::Final(DnsError(format!(
                "{} sent an invalid answer: {e}",
                self.server
            )))
        })?;
        if answer.metadata.response_code == ResponseCode::ServFail {
            return Err(Failure::Retry(DnsError(format!(
                "{} answered SERVFAIL",
                self.server
            ))));
        }
        if let (Some(key), Some(mac)) = (&key, &request_mac) {
            key.verify(&answer, &bytes, mac, unix_now())
                .map_err(|e| Failure::Final(DnsError(format!("{}: {e}", self.server))))?;
        }
        Ok(answer)
    }
}

#[async_trait]
impl DnsSolver for Rfc2136Dns {
    async fn present(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
        // Adds one RR to the RRset (RFC 2136 §2.5.1); duplicates are ignored by the server.
        self.update(fqdn, value, |record, zone| {
            update_message::append(record.into(), zone, false, false)
        })
        .await
    }

    async fn cleanup(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
        // Deletes the one RR with this data (RFC 2136 §2.5.4), never the whole RRset.
        self.update(fqdn, value, |record, zone| {
            update_message::delete_by_rdata(record.into(), zone, false)
        })
        .await
    }
}

/// An absolute DNS name.
fn dns_name(name: &str) -> Result<Name, DnsError> {
    let mut parsed =
        Name::from_ascii(name).map_err(|e| DnsError(format!("`{name}` is not a DNS name: {e}")))?;
    parsed.set_fqdn(true);
    Ok(parsed)
}

/// What to check on the server for an update refused with `code`.
fn update_hint(code: ResponseCode) -> &'static str {
    match code {
        ResponseCode::Refused | ResponseCode::NotAuth => {
            " (check that the server allows this key to update `_acme-challenge` TXT records)"
        }
        ResponseCode::NotZone => " (the zone is wrong; set `zone`)",
        _ => "",
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod fake_server;
#[cfg(test)]
mod tests;
