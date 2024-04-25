use std::{future::poll_fn, path::Path};

use http::{Method, Request};
use miro_common::{
    server::Server, AUTH_REQUEST_PADDING, HANDSHAKE_HEADER_AUTH, HANDSHAKE_HEADER_CC_RX,
    HANDSHAKE_HEADER_PADDING, HANDSHAKE_HEADER_UDP, HANDSHAKE_STATUS_OK,
};
use s2n_quic::{
    client::Connect,
    provider::{datagram::default::Endpoint, tls},
    Client,
};
use s2n_quic_h3::h3;

const LOCAL_ADDRESS: &str = "127.0.0.1:0";
fn create_server() -> Server {
    let cert = "tests/server.cert";
    let key = "tests/server.key";
    let tls_config = tls::default::Server::builder()
        .with_certificate(Path::new(cert), Path::new(key))
        .unwrap()
        .build()
        .unwrap();
    let datagram_provider = Endpoint::builder()
        .with_recv_capacity(200)
        .unwrap()
        .build()
        .unwrap();
    let server = s2n_quic::Server::builder()
        .with_tls(tls_config)
        .unwrap()
        .with_io(LOCAL_ADDRESS)
        .unwrap()
        .with_datagram(datagram_provider)
        .unwrap()
        .start()
        .unwrap();
    Server::new(server)
}

fn create_client() -> Client {
    let tls_config = tls::default::Client::builder()
        .with_certificate(Path::new("tests/ca.cert"))
        .unwrap()
        .build()
        .unwrap();

    Client::builder()
        .with_tls(tls_config)
        .unwrap()
        .with_io(LOCAL_ADDRESS)
        .unwrap()
        .start()
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn test_server_handshake() {
    let mut server = create_server();
    let mut client = create_client();
    let local_addr = server.local_addr().unwrap();
    let handler = tokio::spawn(async move {
        if let Ok(Some(conn)) = server.accept_connection().await {
            conn.process().await.unwrap();
        }
    });
    let conn = client
        .connect(Connect::new(local_addr).with_server_name("localhost"))
        .await
        .unwrap();
    let conn = s2n_quic_h3::Connection::new(conn);

    let (mut driver, mut send_request) = h3::client::new(conn).await.unwrap();
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
    client.wait_idle().await.unwrap();
    handler.await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_server_invalid_handshake() {
    let mut server = create_server();
    let mut client = create_client();
    let local_addr = server.local_addr().unwrap();
    let handler = tokio::spawn(async move {
        if let Ok(Some(conn)) = server.accept_connection().await {
            conn.process().await.unwrap();
        }
    });
    let conn = client
        .connect(Connect::new(local_addr).with_server_name("localhost"))
        .await
        .unwrap();
    let quinn_conn = s2n_quic_h3::Connection::new(conn);

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
    client.wait_idle().await.unwrap();
    handler.await.unwrap();
}
