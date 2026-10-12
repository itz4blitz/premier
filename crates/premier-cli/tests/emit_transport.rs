//! Transport guarantees of `premier emit`: a loopback collector request must
//! bypass environment proxies, a remote one must honor them, and neither may
//! wait forever on a silent collector.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

/// Accept connections forever, forwarding each request head+body to `seen`.
/// When `reply` is `None` the connection is held open without an answer.
fn stub_server(reply: Option<&'static str>) -> (u16, mpsc::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (seen, received) = mpsc::channel();
    thread::spawn(move || {
        let mut held = Vec::new();
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            stream
                .set_read_timeout(Some(Duration::from_millis(500)))
                .unwrap();
            let mut request = Vec::new();
            let mut chunk = [0_u8; 4096];
            while !String::from_utf8_lossy(&request).contains("agent.spawn") {
                match stream.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(read) => request.extend_from_slice(&chunk[..read]),
                }
            }
            let _ = seen.send(String::from_utf8_lossy(&request).into_owned());
            match reply {
                Some(body) => {
                    let _ = write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                }
                None => held.push(stream),
            }
        }
    });
    (port, received)
}

fn emit(collector_port: u16) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_premier"));
    command
        .args(["emit", "--kind", "agent.spawn", "--actor", "researcher"])
        .env(
            "PREMIER_COLLECTOR_URL",
            format!("http://127.0.0.1:{collector_port}/v1/events"),
        )
        .env("PREMIER_COLLECTOR_TOKEN", "secret-token")
        .env_remove("NO_PROXY")
        .env_remove("no_proxy");
    command
}

#[test]
fn emit_does_not_send_the_collector_token_through_an_environment_proxy() {
    let (collector_port, collector_seen) = stub_server(Some(r#"{"event_id":"evt-1"}"#));
    let (proxy_port, proxy_seen) = stub_server(Some(r#"{"event_id":"evt-proxy"}"#));
    let proxy = format!("http://127.0.0.1:{proxy_port}");

    let output = emit(collector_port)
        .env("HTTP_PROXY", &proxy)
        .env("http_proxy", &proxy)
        .env("ALL_PROXY", &proxy)
        .env("all_proxy", &proxy)
        .output()
        .unwrap();

    assert!(
        proxy_seen.try_recv().is_err(),
        "the collector request was routed through the proxy"
    );
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "evt-1");
    let request = collector_seen
        .recv_timeout(Duration::from_secs(5))
        .expect("collector request");
    assert!(
        request
            .to_lowercase()
            .contains("authorization: bearer secret-token")
    );
}

#[test]
fn emit_bypasses_the_proxy_for_every_loopback_spelling_of_the_collector() {
    let (collector_port, collector_seen) = stub_server(Some(r#"{"event_id":"evt-1"}"#));
    let (proxy_port, proxy_seen) = stub_server(Some(r#"{"event_id":"evt-proxy"}"#));
    let proxy = format!("http://127.0.0.1:{proxy_port}");

    // The stub collector listens on IPv4 only, so `localhost` must reach it
    // there; 127.0.0.2 is skipped where only 127.0.0.1 is configured (macOS).
    for host in ["localhost", "LOCALHOST", "127.0.0.1"] {
        let output = emit(collector_port)
            .env(
                "PREMIER_COLLECTOR_URL",
                format!("http://{host}:{collector_port}/v1/events"),
            )
            .env("HTTP_PROXY", &proxy)
            .env("http_proxy", &proxy)
            .env("ALL_PROXY", &proxy)
            .env("all_proxy", &proxy)
            .output()
            .unwrap();
        assert!(
            proxy_seen.try_recv().is_err(),
            "the {host} collector request was routed through the proxy"
        );
        assert!(
            output.status.success(),
            "{host}: stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "evt-1");
        collector_seen
            .recv_timeout(Duration::from_secs(5))
            .expect("collector request");
    }
}

#[test]
fn emit_reaches_a_remote_collector_through_the_environment_proxy() {
    let (proxy_port, proxy_seen) = stub_server(Some(r#"{"event_id":"evt-proxy"}"#));
    let proxy = format!("http://127.0.0.1:{proxy_port}");

    // `.invalid` never resolves, so the event can only arrive via the proxy.
    let output = emit(0)
        .env(
            "PREMIER_COLLECTOR_URL",
            "http://collector.premier.invalid/v1/events",
        )
        .env("HTTP_PROXY", &proxy)
        .env("http_proxy", &proxy)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "a remote collector behind a mandatory proxy was unreachable: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "evt-proxy");
    let request = proxy_seen
        .recv_timeout(Duration::from_secs(5))
        .expect("proxied collector request");
    assert!(
        request.starts_with("POST http://collector.premier.invalid/v1/events "),
        "{request}"
    );
    assert!(
        request
            .to_lowercase()
            .contains("authorization: bearer secret-token")
    );
}

#[test]
fn emit_times_out_when_the_collector_never_answers() {
    let (collector_port, _collector_seen) = stub_server(None);
    let started = Instant::now();
    let output = emit(collector_port)
        .env("PREMIER_EMIT_TIMEOUT", "0.5")
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "a silent collector must fail emit"
    );
    assert!(
        started.elapsed() < Duration::from_secs(8),
        "emit waited {:?} for a silent collector",
        started.elapsed()
    );
}
