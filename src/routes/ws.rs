use axum::{
    extract::{
        Query, State, WebSocketUpgrade,
        ws::{Message as WsMessage, WebSocket},
    },
    http::StatusCode,
    response::IntoResponse,
};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::state::AppState;

#[derive(Deserialize)]
pub struct WsAuthQuery {
    token: String,
}

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    Query(query): Query<WsAuthQuery>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let row: Option<(Uuid, Uuid)> =
        sqlx::query_as("SELECT id, user_id FROM sessions WHERE token = $1 AND expires_at > now()")
            .bind(&query.token)
            .fetch_optional(&state.db)
            .await
            .unwrap_or(None);

    let (user_id, session_id) = match row {
        Some((id, user_id)) => (user_id, id),
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };

    ws.on_upgrade(move |socket| handle_socket(socket, user_id, session_id, state))
}

async fn handle_socket(socker: WebSocket, user_id: Uuid, session_id: Uuid, state: AppState) {
    let (mut ws_sender, mut ws_receiver) = socker.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();

    state
        .connections
        .write()
        .await
        .entry(user_id)
        .or_default()
        .insert(session_id, tx);
    println!(
        "User {} with sessiond id {} has been connected by WS",
        user_id, session_id
    );

    let mut send_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if ws_sender.send(WsMessage::Text(msg.into())).await.is_err() {
                break;
            }
        }
    });

    loop {
        tokio::select! {
            msg = ws_receiver.next() => match msg {
                Some(Ok(WsMessage::Text(t))) => println!("From {}: {}", user_id, t),
                Some(Ok(_)) => {},
                _ => break,
            },
            _ = &mut send_task => break,
        }
    }

    send_task.abort();
    let mut conns = state.connections.write().await;
    let empty = conns
        .get_mut(&user_id)
        .map(|m| {
            m.remove(&session_id);
            m.is_empty()
        })
        .unwrap_or(false);
    if empty {
        conns.remove(&user_id);
        println!("User {} has been disconnected", user_id)
    }
}
