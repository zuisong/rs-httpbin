use super::*;

#[tokio::test]
async fn test_websocket_echo() {
    use tokio_stream::StreamExt;
    use tokio_tungstenite::{connect_async_with_config, tungstenite::Message as WsMessage};
    // 启动服务
    let addr = "127.0.0.1:0";
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    let local_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        start_server(listener).await;
    });
    // 等待服务启动
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let url = format!("ws://{local_addr}/websocket/echo?max_fragment_size=2048&max_message_size=10240");

    let (mut ws_stream, _) = connect_async_with_config(url, None, false).await.unwrap();
    ws_stream.send(WsMessage::Text("hello ws".into())).await.unwrap();
    let msg = ws_stream.next().await.unwrap().unwrap();
    assert_eq!(msg, WsMessage::Text("hello ws".into()));
    ws_stream.close(None).await.unwrap();
}

#[tokio::test]
async fn test_websocket_echo_max_message_size() {
    use tokio_stream::StreamExt;
    use tokio_tungstenite::{connect_async_with_config, tungstenite::Message as WsMessage};
    // 启动服务
    let addr = "127.0.0.1:0";
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    let local_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        start_server(listener).await;
    });
    // 等待服务启动
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let url = format!("ws://{local_addr}/websocket/echo?max_fragment_size=2048&max_message_size=10240");

    let (mut ws_stream, _) = connect_async_with_config(url, None, false).await.unwrap();
    ws_stream.send(WsMessage::Text("a".repeat(2049).into())).await.unwrap();
    let msg = ws_stream.next().await;

    dbg!(&msg);
    assert!(msg.unwrap().unwrap().is_close());
}
