//! The real HTTP path against a plain-HTTP listener on loopback.

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
};

use openvibes_fetch::http::{Client, MAX_BODY};

/// Serves `reply` to every connection; returns the URL, a connection counter
/// and a stop function.
fn serve(reply: Vec<u8>) -> (String, Arc<AtomicUsize>, impl FnOnce() -> usize) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/x", listener.local_addr().unwrap());
    let addr = listener.local_addr().unwrap();
    let (count, stop) = (
        Arc::new(AtomicUsize::new(0)),
        Arc::new(AtomicBool::new(false)),
    );
    let (c, s) = (count.clone(), stop.clone());
    let t = thread::spawn(move || {
        for mut conn in listener.incoming().flatten() {
            if s.load(Ordering::SeqCst) {
                break;
            }
            c.fetch_add(1, Ordering::SeqCst);
            let mut buf = [0u8; 4096];
            let mut seen = Vec::new();
            while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
                match conn.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => seen.extend_from_slice(&buf[..n]),
                }
            }
            let _ = conn.write_all(&reply);
        }
    });
    let finish = move || {
        stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(addr);
        t.join().unwrap();
        count.load(Ordering::SeqCst)
    };
    (url, Arc::new(AtomicUsize::new(0)), finish)
}

fn response(status: &str, extra: &str, body: &[u8]) -> Vec<u8> {
    let mut r = format!(
        "HTTP/1.1 {status}\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    r.extend_from_slice(body);
    r
}

#[test]
fn redirect_is_an_error_and_not_followed() {
    let (url, _, finish) = serve(response(
        "302 Found",
        "Location: http://evil.invalid/\r\n",
        b"",
    ));
    assert!(Client::new(None).unwrap().fetch(&url).is_err());
    assert_eq!(finish(), 1);
}

#[test]
fn oversize_body_comes_back_over_the_limit() {
    let (url, _, finish) = serve(response("200 OK", "", &vec![b' '; 300 * 1024]));
    let body = Client::new(None).unwrap().fetch(&url).unwrap();
    finish();
    assert_eq!(body.len(), MAX_BODY + 1);
}

#[test]
fn server_error_is_an_error() {
    let (url, _, finish) = serve(response("500 Internal Server Error", "", b"no"));
    assert!(Client::new(None).unwrap().fetch(&url).is_err());
    finish();
}
