use std::{future::poll_fn, sync::Arc};

use axum::http::{Method, Request};
use miro_common::{
    server::Server, AUTH_REQUEST_PADDING, HANDSHAKE_HEADER_AUTH, HANDSHAKE_HEADER_CC_RX,
    HANDSHAKE_HEADER_PADDING, HANDSHAKE_HEADER_UDP, HANDSHAKE_STATUS_OK,
};
use quinn::Endpoint;
use rustls::{Certificate, PrivateKey, RootCertStore};

static ALPN: &[u8] = b"h3";
const LOCAL_ADDRESS: &str = "127.0.0.1:0";
fn create_server() -> Server {
    let cert = "tests/server.cert";
    let key = "tests/server.key";
    let cert = Certificate(std::fs::read(cert).unwrap());
    let key = PrivateKey(std::fs::read(key).unwrap());

    let mut tls_config = rustls::ServerConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    tls_config.max_early_data_size = u32::MAX;
    tls_config.alpn_protocols = vec![ALPN.into()];

    let server_config = quinn::ServerConfig::with_crypto(Arc::new(tls_config));
    let endpoint = quinn::Endpoint::server(server_config, LOCAL_ADDRESS.parse().unwrap()).unwrap();
    Server::new(endpoint)
}

fn create_client() -> Endpoint {
    let mut roots = RootCertStore::empty();
    roots
        .add(&Certificate(std::fs::read("tests/ca.cert").unwrap()))
        .unwrap();
    let mut tls_config = rustls::ClientConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();

    tls_config.enable_early_data = true;
    tls_config.alpn_protocols = vec![ALPN.into()];

    let mut client_endpoint =
        h3_quinn::quinn::Endpoint::client(LOCAL_ADDRESS.parse().unwrap()).unwrap();

    let client_config = quinn::ClientConfig::new(Arc::new(tls_config));
    client_endpoint.set_default_client_config(client_config);

    client_endpoint
}

#[tokio::test(flavor = "multi_thread")]
async fn test_server_handshake() {
    let server = create_server();
    let client = create_client();
    let local_addr = server.local_addr().unwrap();
    let handler = tokio::spawn(async move {
        if let Ok(Some(conn)) = server.accept_connection().await {
             conn.process().await.unwrap();
        }
    });
    let conn = client
        .connect(local_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    let quinn_conn = h3_quinn::Connection::new(conn);

    let (mut driver, mut send_request) = h3::client::new(quinn_conn).await.unwrap();
    let driver = async move { poll_fn(move |cx| driver.poll_close(cx)).await.unwrap() };
    let request = async move {
        let request = Request::builder()
            .method(Method::POST)
            .uri("https://hysteria/auth")
            .header(HANDSHAKE_HEADER_AUTH, "Hello")
            .header(HANDSHAKE_HEADER_CC_RX, 0)
            .header(HANDSHAKE_HEADER_PADDING, AUTH_REQUEST_PADDING.generate())
            .body(())
            .unwrap();

        let mut stream = send_request.send_request(request).await.unwrap();
        stream.finish().await.unwrap();
        let response = stream.recv_response().await.unwrap();
        assert_eq!(response.status(), HANDSHAKE_STATUS_OK);
        assert_eq!(
            response.headers().get(HANDSHAKE_HEADER_UDP).unwrap(),
            "false"
        );
        assert_eq!(
            response.headers().get(HANDSHAKE_HEADER_CC_RX).unwrap(),
            "auto"
        );
        assert_ne!(
            response.headers().get(HANDSHAKE_HEADER_PADDING).unwrap(),
            ""
        );
    };
    tokio::join!(request, driver);
    client.wait_idle().await;
    handler.await.unwrap();
    
}

#[tokio::test(flavor = "multi_thread")]
async fn test_server_invalid_handshake(){
    let server = create_server();
    let client = create_client();
    let local_addr = server.local_addr().unwrap();
    let handler = tokio::spawn(async move {
        if let Ok(Some(conn)) = server.accept_connection().await {
             conn.process().await.unwrap();
        }
    });
    let conn = client
        .connect(local_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    let quinn_conn = h3_quinn::Connection::new(conn);

    let (mut driver, mut send_request) = h3::client::new(quinn_conn).await.unwrap();
    let driver = async move { poll_fn(move |cx| driver.poll_close(cx)).await.unwrap() };
    let request = async move {
        let request = Request::builder()
            .method(Method::POST)
            .uri("https://localhost/auth")
            .header(HANDSHAKE_HEADER_AUTH, "Hello")
            .header(HANDSHAKE_HEADER_CC_RX, 0)
            .header(HANDSHAKE_HEADER_PADDING, "Padding")
            .body(())
            .unwrap();

        let mut stream = send_request.send_request(request).await.unwrap();
        stream.finish().await.unwrap();
        let response = stream.recv_response().await.unwrap();
        assert_eq!(response.status(), 404);
    };
    tokio::join!(request, driver);
    client.wait_idle().await;
    handler.await.unwrap();
}
