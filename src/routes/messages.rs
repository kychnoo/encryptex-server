use axum::{
    Json, debug_handler,
    extract::{Path, State},
    http::StatusCode,
};
use uuid::Uuid;

use crate::{
    auth::AuthUser,
    json::AppJson,
    models::message::{Message, SendMessage},
    state::AppState,
};

#[debug_handler]
pub async fn send_message(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(chat_id): Path<Uuid>,
    AppJson(payload): AppJson<SendMessage>,
) -> Result<Json<Message>, StatusCode> {
    let is_member: Option<(i32,)> =
        sqlx::query_as("SELECT 1 FROM chat_members WHERE chat_id = $1 AND user_id = $2")
            .bind(chat_id)
            .bind(auth.user_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if is_member.is_none() {
        return Err(StatusCode::FORBIDDEN);
    }

    let message_id = Uuid::now_v7();

    let message = sqlx::query_as::<_, Message>(
        "INSERT INTO messages (id, chat_id, sender_id, text) VALUES ($1, $2, $3, $4)
        RETURNING id, chat_id, sender_id, text, created_at",
    )
    .bind(message_id)
    .bind(chat_id)
    .bind(auth.user_id)
    .bind(&payload.text)
    .fetch_one(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let members: Vec<(Uuid,)> =
        sqlx::query_as("SELECT user_id FROM chat_members WHERE chat_id = $1")
            .bind(chat_id)
            .fetch_all(&state.db)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let payload_json = serde_json::to_string(&message).unwrap();
    let connections = state.connections.read().await;
    for (member_id,) in members {
        if let Some(sessions) = connections.get(&member_id) {
            for sender in sessions.values() {
                let _ = sender.send(payload_json.clone());
            }
        }
    }

    Ok(Json(message))
}

#[debug_handler]
pub async fn list_messages(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(chat_id): Path<Uuid>,
) -> Result<Json<Vec<Message>>, StatusCode> {
    let is_member: Option<(i32,)> =
        sqlx::query_as("SELECT 1 FROM chat_members WHERE chat_id = $1 AND user_id = $2")
            .bind(chat_id)
            .bind(auth.user_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if is_member.is_none() {
        return Err(StatusCode::FORBIDDEN);
    }

    let messages = sqlx::query_as::<_, Message>(
        "SELECT id, chat_id, sender_id, text, created_at FROM messages
        WHERE chat_id = $1 ORDER BY created_at ASC",
    )
    .bind(chat_id)
    .fetch_all(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(messages))
}
