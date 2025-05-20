use std::{net::SocketAddr, ops::ControlFlow, time::Duration};

use axum::{
    extract::{
        connect_info::ConnectInfo,
        ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade, close_code, rejection::WebSocketUpgradeRejection},
    },
    http::StatusCode,
    response::IntoResponse,
};
use axum_extra::{extract::Query, response::ErasedJson};
use serde::{Deserialize, Serialize};
use tracing::info;

#[derive(Deserialize, Serialize)]
pub struct EchoConfig {
    max_fragment_size: Option<usize>,
    max_message_size: Option<usize>,
}

pub async fn ws_echo_handler(
    version: axum::http::Version,
    ws: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Query(params): Query<EchoConfig>,
) -> impl IntoResponse {
    match ws {
        Ok(ws) => {
            tracing::debug!("accepted a WebSocket using {version:?}");

            let mut ws = ws;
            if let Some(size) = params.max_fragment_size {
                ws = ws.max_frame_size(size);
            }
            if let Some(size) = params.max_message_size {
                ws = ws.max_message_size(size);
            }

            ws.on_upgrade(move |socket| handle_socket(socket, addr))
        }
        Err(WebSocketUpgradeRejection::InvalidUpgradeHeader(_)) => (
            StatusCode::BAD_REQUEST,
            ErasedJson::pretty(crate::data::ErrorDetail::new(
                400,
                "Bad Request",
                "missing required `Upgrade: websocket` header",
            )),
        )
            .into_response(),
        Err(e) => e.into_response(),
    }
}

enum Either<L, R> {
    Left(L),
    Right(R),
}

async fn handle_socket(mut socket: WebSocket, who: SocketAddr) {
    loop {
        let res = tokio::select! {
          _ = tokio::time::sleep(Duration::from_secs(10)) => Either::Left(()),
          msg = socket.recv() => Either::Right(msg),
        };

        let msg = match res {
            Either::Left(_) => {
                if let Err(e) = socket.send(Message::Close(None)).await {
                    info!("timeout: Could not send Close due to {e}, probably it is ok?");
                } else {
                    info!("timeout: Close sent to {who}")
                }
                break;
            }
            Either::Right(None) => break,
            Either::Right(Some(Ok(msg))) => msg,
            Either::Right(Some(Err(e))) => {
                info!("Could not receive msg due to {e}, client {who} abruptly disconnected");
                let _ = socket
                    .send(Message::Close(Some(CloseFrame {
                        code: close_code::ERROR,
                        reason: format!("{e:?}").into(),
                    })))
                    .await;
                break;
            }
        };

        match process_message(msg, who) {
            ControlFlow::Break(_) => break,
            ControlFlow::Continue(None) => continue,
            ControlFlow::Continue(Some(msg)) => {
                if let Err(e) = socket.send(msg).await {
                    info!("Could not send msg due to {e}, client {who} abruptly disconnected");
                    break;
                }
            }
        }
    }

    info!("Websocket context {who} destroyed");
}

fn process_message(msg: Message, who: SocketAddr) -> ControlFlow<(), Option<Message>> {
    match msg {
        Message::Text(t) => {
            let msg = format!("{t}");
            info!(">>> {who} sent text message: {msg}");
            return ControlFlow::Continue(Some(Message::Text(t)));
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
