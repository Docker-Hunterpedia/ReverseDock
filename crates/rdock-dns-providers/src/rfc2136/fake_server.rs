//! A primary for one zone, `example.com.`, on one loopback port over UDP and TCP: it answers
//! SOA queries, verifies the TSIG of updates the way RFC 8945 §5 describes (key, MAC, time),
//! applies RFC 2136 additions and deletions to its TXT records, and signs its answers.
//!
//! Its signature checks go through hickory-proto's wire parser (`signed_bitmessage_to_buf`)
//! rather than the client's signing path, so a client that signs the wrong bytes fails here.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use hickory_proto::op::{Message, OpCode, ResponseCode};
use hickory_proto::rr::rdata::SOA;
use hickory_proto::rr::rdata::tsig::{
    TSIG, TsigAlgorithm, TsigError, make_tsig_record, signed_bitmessage_to_buf,
};
use hickory_proto::rr::{DNSClass, Name, RData, Record};
use hickory_proto::serialize::binary::BinEncoder;
use rdock_testkit::dns_contract::ContractFake;
use ring::hmac;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

use super::unix_now;

/// The key the server accepts.
#[derive(Clone)]
pub(super) struct ServerKey {
    pub(super) name: Name,
    pub(super) algorithm: TsigAlgorithm,
    pub(super) secret: Vec<u8>,
}

impl ServerKey {
    pub(super) fn new(name: &str, algorithm: TsigAlgorithm, secret_base64: &str) -> Self {
        Self {
            name: Name::from_ascii(name).unwrap(),
            algorithm,
            secret: STANDARD.decode(secret_base64).unwrap(),
        }
    }

    fn hmac(&self) -> hmac::Key {
        let algorithm = match self.algorithm {
            TsigAlgorithm::HmacSha1 => hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
            TsigAlgorithm::HmacSha256 => hmac::HMAC_SHA256,
            TsigAlgorithm::HmacSha384 => hmac::HMAC_SHA384,
            TsigAlgorithm::HmacSha512 => hmac::HMAC_SHA512,
            ref other => panic!("the fake server does not do {other:?}"),
        };
        hmac::Key::new(algorithm, &self.secret)
    }
}

#[derive(Default)]
struct State {
    /// `None`: unsigned updates are accepted.
    key: Option<ServerKey>,
    /// TXT values by owner name (lower case, no trailing dot).
    txt: BTreeMap<String, Vec<String>>,
    servfail_next: usize,
    received: Vec<Message>,
}

/// The running server.
pub(super) struct FakeDnsServer {
    pub(super) addr: SocketAddr,
    state: Arc<Mutex<State>>,
}

impl FakeDnsServer {
    pub(super) async fn start(key: Option<ServerKey>) -> Self {
        let (udp, tcp) = bind_pair().await;
        let addr = udp.local_addr().unwrap();
        let state = Arc::new(Mutex::new(State {
            key,
            ..State::default()
        }));
        let shared = state.clone();
        tokio::spawn(async move {
            let mut buffer = vec![0; 65_535];
            while let Ok((length, peer)) = udp.recv_from(&mut buffer).await {
                let answer = handle(&mut shared.lock().unwrap(), &buffer[..length]);
                let _ = udp.send_to(&answer, peer).await;
            }
        });
        let shared = state.clone();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = tcp.accept().await {
                let state = shared.clone();
                tokio::spawn(async move {
                    while let Ok(length) = stream.read_u16().await {
                        let mut request = vec![0; usize::from(length)];
                        if stream.read_exact(&mut request).await.is_err() {
                            return;
                        }
                        let answer = handle(&mut state.lock().unwrap(), &request);
                        let mut framed =
                            u16::try_from(answer.len()).unwrap().to_be_bytes().to_vec();
                        framed.extend_from_slice(&answer);
                        if stream.write_all(&framed).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        Self { addr, state }
    }

    /// Every message received, in order.
    pub(super) fn received(&self) -> Vec<Message> {
        self.state.lock().unwrap().received.clone()
    }
}

impl ContractFake for FakeDnsServer {
    fn txt_values(&self, fqdn: &str) -> Vec<String> {
        let state = self.state.lock().unwrap();
        state.txt.get(fqdn).cloned().unwrap_or_default()
    }

    fn accept_only(&self, credential: &str) {
        let mut state = self.state.lock().unwrap();
        state.key.as_mut().unwrap().secret = STANDARD.decode(credential).unwrap();
    }

    fn fail_next_write(&self) {
        self.state.lock().unwrap().servfail_next = 1;
    }
}

/// A UDP socket and a TCP listener on the same loopback port.
async fn bind_pair() -> (UdpSocket, TcpListener) {
    loop {
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        if let Ok(tcp) = TcpListener::bind(udp.local_addr().unwrap()).await {
            return (udp, tcp);
        }
    }
}

fn zone() -> Name {
    Name::from_ascii("example.com.").unwrap()
}

fn handle(state: &mut State, bytes: &[u8]) -> Vec<u8> {
    let Ok(request) = Message::from_vec(bytes) else {
        return Message::error_msg(0, OpCode::Query, ResponseCode::FormErr)
            .to_vec()
            .unwrap();
    };
    state.received.push(request.clone());
    match request.metadata.op_code {
        OpCode::Query => answer_soa(&request).to_vec().unwrap(),
        OpCode::Update => update(state, &request, bytes),
        _ => Message::error_msg(
            request.metadata.id,
            request.metadata.op_code,
            ResponseCode::NotImp,
        )
        .to_vec()
        .unwrap(),
    }
}

/// The SOA at the apex; NOERROR without an answer below it; REFUSED for other zones.
fn answer_soa(request: &Message) -> Message {
    let mut response = Message::response(request.metadata.id, OpCode::Query);
    response.add_queries(request.queries.clone());
    let name = request.queries[0].name().clone();
    let soa = Record::from_rdata(
        zone(),
        3600,
        RData::SOA(SOA::new(
            Name::from_ascii("ns1.example.com.").unwrap(),
            Name::from_ascii("hostmaster.example.com.").unwrap(),
            1,
            3600,
            600,
            86_400,
            60,
        )),
    );
    if name == zone() {
        response.add_answer(soa);
    } else if zone().zone_of(&name) {
        response.add_authority(soa);
    } else {
        response.metadata.response_code = ResponseCode::Refused;
    }
    response
}

/// Why an update was not accepted.
enum Rejection {
    Unsigned,
    Tsig(TsigError),
}

fn update(state: &mut State, request: &Message, bytes: &[u8]) -> Vec<u8> {
    let id = request.metadata.id;
    if state.servfail_next > 0 {
        state.servfail_next -= 1;
        return Message::error_msg(id, OpCode::Update, ResponseCode::ServFail)
            .to_vec()
            .unwrap();
    }
    let key = state.key.clone();
    let request_mac = match &key {
        Some(key) => match verify(key, request, bytes) {
            Ok(mac) => Some(mac),
            Err(Rejection::Unsigned) => {
                return Message::error_msg(id, OpCode::Update, ResponseCode::Refused)
                    .to_vec()
                    .unwrap();
            }
            Err(Rejection::Tsig(error)) => return tsig_error(key, id, error),
        },
        None => None,
    };
    let mut response = Message::response(id, OpCode::Update);
    response.add_queries(request.queries.clone());
    response.metadata.response_code = apply(state, request);
    match (&key, request_mac) {
        (Some(key), Some(mac)) => sign_response(key, response, &mac, unix_now()),
        _ => response.to_vec().unwrap(),
    }
}

/// RFC 8945 §5.2: the key, then the MAC, then the time. Returns the request's MAC.
fn verify(key: &ServerKey, request: &Message, bytes: &[u8]) -> Result<Vec<u8>, Rejection> {
    let signature = request.signature.as_ref().ok_or(Rejection::Unsigned)?;
    if signature.name != key.name || signature.data.algorithm != key.algorithm {
        return Err(Rejection::Tsig(TsigError::BadKey));
    }
    let (covered, record) = signed_bitmessage_to_buf(bytes, None, true)
        .map_err(|_| Rejection::Tsig(TsigError::BadSig))?;
    hmac::verify(&key.hmac(), &covered, &record.data.mac)
        .map_err(|_| Rejection::Tsig(TsigError::BadSig))?;
    if unix_now().abs_diff(record.data.time) > u64::from(record.data.fudge) {
        return Err(Rejection::Tsig(TsigError::BadTime));
    }
    Ok(record.data.mac.clone())
}

/// NOTAUTH with an unsigned TSIG record carrying `error` (RFC 8945 §5.3.2).
fn tsig_error(key: &ServerKey, id: u16, error: TsigError) -> Vec<u8> {
    let mut response = Message::error_msg(id, OpCode::Update, ResponseCode::NotAuth);
    response.signature = Some(Box::new(make_tsig_record(
        key.name.clone(),
        TSIG::new(
            key.algorithm.clone(),
            unix_now(),
            300,
            Vec::new(),
            id,
            Some(error),
            Vec::new(),
        ),
    )));
    response.to_vec().unwrap()
}

/// Signs an answer to a request whose MAC was `request_mac` (RFC 8945 §4.3.1).
pub(super) fn sign_response(
    key: &ServerKey,
    mut response: Message,
    request_mac: &[u8],
    now: u64,
) -> Vec<u8> {
    let stub = TSIG::new(
        key.algorithm.clone(),
        now,
        300,
        Vec::new(),
        response.metadata.id,
        None,
        Vec::new(),
    );
    let mut covered = Vec::new();
    let mut encoder = BinEncoder::new(&mut covered);
    encoder
        .emit_u16(u16::try_from(request_mac.len()).unwrap())
        .unwrap();
    encoder.emit_vec(request_mac).unwrap();
    encoder.emit_vec(&response.to_vec().unwrap()).unwrap();
    stub.emit_tsig_for_mac(&mut encoder, &key.name).unwrap();
    let mac = hmac::sign(&key.hmac(), &covered).as_ref().to_vec();
    response.signature = Some(Box::new(make_tsig_record(
        key.name.clone(),
        stub.set_mac(mac),
    )));
    response.to_vec().unwrap()
}

/// Applies the update section: additions (class IN), deletions of one RR (class NONE) and of
/// an RRset (class ANY), all inside the zone.
fn apply(state: &mut State, request: &Message) -> ResponseCode {
    if request.queries.first().map(hickory_proto::op::Query::name) != Some(&zone()) {
        return ResponseCode::NotAuth;
    }
    if request.authorities.iter().any(|r| !zone().zone_of(&r.name)) {
        return ResponseCode::NotZone;
    }
    for record in &request.authorities {
        let owner = record
            .name
            .to_ascii()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        match (record.dns_class, &record.data) {
            (DNSClass::IN, RData::TXT(txt)) => {
                let values = state.txt.entry(owner).or_default();
                let value = text(txt);
                if !values.contains(&value) {
                    values.push(value);
                }
            }
            (DNSClass::NONE, RData::TXT(txt)) => {
                let value = text(txt);
                if let Some(values) = state.txt.get_mut(&owner) {
                    values.retain(|v| *v != value);
                    if values.is_empty() {
                        state.txt.remove(&owner);
                    }
                }
            }
            (DNSClass::ANY, _) => {
                state.txt.remove(&owner);
            }
            _ => return ResponseCode::FormErr,
        }
    }
    ResponseCode::NoError
}

fn text(txt: &hickory_proto::rr::rdata::TXT) -> String {
    txt.txt_data
        .iter()
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect()
}
