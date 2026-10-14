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
    let row: Option<(Uuid,)> =
        sqlx::query_as("SELECT user_id FROM sessions WHERE token = $1 AND expires_at > now()")
            .bind(&query.token)
            .fetch_optional(&state.db)
            .await
            .unwrap_or(None);

    let user_id = match row {
        Some((id,)) => id,
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };

    ws.on_upgrade(move |socket| handle_socket(socket, user_id, state))
}

async fn handle_socket(socker: WebSocket, user_id: Uuid, state: AppState) {
    let (mut ws_sender, mut ws_receiver) = socker.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();

    state.connections.write().await.insert(user_id, tx);
    println!("User {} has been connected by WS", user_id);

    let send_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if ws_sender.send(WsMessage::Text(msg.into())).await.is_err() {
                break;
            }
        }
    });

    while let Some(Ok(msg)) = ws_receiver.next().await {
        if let WsMessage::Text(text) = msg {
            println!("From {}: {}", user_id, text);
        }
    }

    send_task.abort();
    state.connections.write().await.remove(&user_id);
    println!("User {} has been disconnected", user_id)
}
