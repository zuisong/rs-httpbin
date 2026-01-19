use std::{
    collections::HashMap,
    error::Error,
    io,
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use axum::{
    extract::{
        State,
        connect_info::ConnectInfo,
        ws::{Message, WebSocket, WebSocketUpgrade, rejection::WebSocketUpgradeRejection},
    },
    response::{Html, IntoResponse, Response},
};
use futures_util::{FutureExt as _, StreamExt};
use tokio::sync::{Mutex, mpsc};
use tracing::{debug, error, info};

#[derive(Clone, Debug)]
pub struct AppState {
    inner: Arc<Mutex<Shared>>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Shared::new())),
        }
    }
}

impl AppState {
    pub fn new() -> Self {
        Self::default()
    }
}

pub async fn ws_handler(
    State(state): State<AppState>,
    ws: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Response {
    match ws {
        Ok(ws) => ws
            .on_upgrade(move |socket| process(state, socket, addr).map(|_res| ()))
            .into_response(),
        Err(_) => Html(include_str!("../assets/ws-chat.html")).into_response(),
    }
}

#[derive(Debug)]
struct Shared {
    peers: HashMap<Id, mpsc::UnboundedSender<Message>>,
}
type Id = uuid::Uuid;

#[derive(Debug)]
struct Peer {
    socket: WebSocket,
    rx: mpsc::UnboundedReceiver<Message>,
}

impl Shared {
    fn new() -> Self {
        Shared { peers: HashMap::new() }
    }

    async fn broadcast(&mut self, _sender: Id, message: &Message) {
        // debug!("{:?}", &self.peers);
        for (id, to_user) in self.peers.iter_mut() {
            println!("{} -> {:?}", id, &message);
            // if *peer.0 != sender {
            let _ = to_user.send(message.clone());
            // }
        }
    }
}

impl Peer {
    async fn new(state: AppState, socket: WebSocket, who: Id) -> io::Result<Peer> {
        let addr = who;
        let (tx, rx) = mpsc::unbounded_channel();
        state.inner.lock().await.peers.insert(addr, tx);
        Ok(Peer { socket, rx })
    }
}

async fn process(state: AppState, ws: WebSocket, addr: SocketAddr) -> Result<(), Box<dyn Error>> {
    let mut lines = ws;
    lines.send(("Please enter your username:").into()).await?;

    let username = match lines.next().await {
        Some(Ok(Message::Text(line))) => line,
        _ => {
            error!("Failed to get username from {addr}. Client disconnected.");
            return Ok(());
        }
    };
    let peer_id = uuid::Uuid::new_v4();
    let mut peer = Peer::new(state.clone(), lines, peer_id).await?;
    {
        let mut state = state.inner.lock().await;
        let msg = format!("{username} has joined the chat");
        info!("{}", msg);
        state.broadcast(peer_id, &msg.into()).await;
    }

    loop {
        let res = tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(10)) => Action::Timeout(()),
            Some( msg) = peer.rx.recv() => Action::RequireSend(msg),
            result = peer.socket.next() => Action::ReceiveMessage(result),
        };
        match res {
            Action::Timeout(()) => peer.socket.send(Message::Ping(vec![].into())).await?,
            Action::RequireSend(msg) => peer.socket.send(msg).await?,
            Action::ReceiveMessage(result) => match result {
                Some(Ok(msg)) => {
                    debug!("{:?}", msg);
                    match msg {
                        Message::Text(msg) => {
                            let mut state = state.inner.lock().await;
                            let msg = format!("{username}({peer_id}): {msg}");
                            state.broadcast(peer_id, &msg.into()).await;
                        }
                        Message::Ping(_) => peer.socket.send(Message::Pong("".into())).await?,
                        Message::Binary(_) => (),
                        Message::Pong(_) => (),
                        Message::Close(_) => break,
                    }
                }
                Some(Err(e)) => {
                    error!("an error occurred while processing messages for {}; error = {:?}", username, e);
                }
                None => break,
            },
        }
    }
    {
        let mut state = state.inner.lock().await;
        state.peers.remove(&peer_id);

        let msg = format!("{username} has left the chat");
        info!("{}", msg);
        state.broadcast(peer_id, &msg.into()).await;
    }

    Ok(())
}

enum Action {
    Timeout(()),
    ReceiveMessage(Option<Result<Message, axum::Error>>),
    RequireSend(Message),
}
