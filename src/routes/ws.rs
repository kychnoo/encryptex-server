use axum::{
    extract::{
        Query, State, WebSocketUpgrade,
        ws::{Message as WsMessage, WebSocket},
    },
    http::StatusCode,
    response::IntoResponse,
};
use chrono::{DateTime, Utc};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::{auth::hash_token, state::AppState};

#[derive(Deserialize)]
pub struct WsAuthQuery {
    token: String,
}

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    Query(query): Query<WsAuthQuery>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let row: Option<(Uuid, Uuid, DateTime<Utc>)> = sqlx::query_as(
        "SELECT id, user_id, expires_at FROM sessions WHERE token_hash = $1 AND expires_at > now()",
    )
    .bind(hash_token(&query.token))
    .fetch_optional(&state.db)
    .await
    .unwrap_or(None);

    let (user_id, session_id, expires_at) = match row {
        Some((id, user_id, expires_at)) => (user_id, id, expires_at),
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };

    ws.on_upgrade(move |socket| handle_socket(socket, user_id, session_id, expires_at, state))
}

async fn handle_socket(
    socker: WebSocket,
    user_id: Uuid,
    session_id: Uuid,
    initial_expires_at: DateTime<Utc>,
    state: AppState,
) {
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

    let mut expires_at = initial_expires_at;

    loop {
        let wait = (expires_at - Utc::now())
            .to_std()
            .unwrap_or(std::time::Duration::ZERO);

        tokio::select! {
            msg = ws_receiver.next() => match msg {
                Some(Ok(WsMessage::Text(t))) => println!("From {}: {}", user_id, t),
                Some(Ok(_)) => {},
                _ => break,
            },
            _ = &mut send_task => break,
            _ = tokio::time::sleep(wait) => {
                let row: Result<Option<(DateTime<Utc>,)>, _> = sqlx::query_as("SELECT expires_at FROM sessions WHERE id = $1")
                    .bind(session_id)
                    .fetch_optional(&state.db)
                    .await;

                match row {
                    Ok(Some((new_exp,))) if new_exp > Utc::now() => expires_at = new_exp,
                    _ => break,
                }
            }
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
