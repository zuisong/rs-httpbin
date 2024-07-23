use std::{net::SocketAddr, ops::ControlFlow, time::Duration};

use axum::{
    extract::{
        connect_info::ConnectInfo,
        ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade},
    },
    http::StatusCode,
    response::IntoResponse,
};
use axum_extra::response::ErasedJson;
use serde_json::json;
use tracing::info;

pub async fn ws_handler(ws: Option<WebSocketUpgrade>, ConnectInfo(addr): ConnectInfo<SocketAddr>) -> impl IntoResponse {
    match ws {
        Some(ws) => ws.on_upgrade(move |socket| handle_socket(socket, addr)),
        None => (
            StatusCode::BAD_REQUEST,
            ErasedJson::pretty(json!(
            {
                "status_code": 400,
                "error": "Bad Request",
                "detail": "missing required `Upgrade: websocket` header"
            }
            )),
        )
            .into_response(),
    }
}

async fn handle_socket(mut socket: WebSocket, who: SocketAddr) {
    loop {
        tokio::select! {
          _= tokio::time::sleep(Duration::from_secs(10)) => {
            if let Err(e) = socket.send(Message::Close(None)).await {
              info!("Could not send Close due to {e}, probably it is ok?");
            } else {
              info!("Close sent to {who}")
            }
            break
          }
          msg = socket.recv() => {
            if let Some(Ok(msg)) = msg {
              match process_message(msg, who) {
                ControlFlow::Break(_) => break,
                ControlFlow::Continue(None) => continue,
                ControlFlow::Continue(Some(msg)) => {
                  if let  Err(e) =  socket.send(Message::Text(msg)).await {
                    info!("Could not send msg due to {e}, client {who} abruptly disconnected");
                    break;
                  }
                }
              }
            } else {
              info!("client {who} abruptly disconnected");
              break;
            }
          }
        }
    }

    info!("Websocket context {who} destroyed");
}

fn process_message(msg: Message, who: SocketAddr) -> ControlFlow<(), Option<String>> {
    match msg {
        Message::Text(t) => {
            let msg = format!("echo --> {t}");
            return ControlFlow::Continue(Some(msg));
        }
        Message::Binary(d) => {
            info!(">>> {} sent {} bytes: {:?}", who, d.len(), d);
        }
        Message::Close(c) => {
            if let Some(CloseFrame { code, reason }) = c {
                info!(">>> {who} sent close with code {code} and reason `{reason}`");
            } else {
                info!(">>> {who} somehow sent close message without CloseFrame")
            }
            return ControlFlow::Break(());
        }

        Message::Pong(v) => {
            info!(">>> {who} sent pong with {v:?}");
        }
        Message::Ping(v) => {
            info!(">>> {who} sent ping with {v:?}");
        }
    }
    ControlFlow::Continue(None)
}
