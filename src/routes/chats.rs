use axum::{Json, extract::State, http::StatusCode};
use uuid::Uuid;

use crate::{
    auth::AuthUser,
    models::chat::{Chat, CreateChat},
    state::AppState,
};

/// Resolves the full member list for a new chat: the creator is always
/// included exactly once, explicit duplicates of the creator are skipped.
pub(crate) fn resolve_member_ids(creator: Uuid, requested: Vec<Uuid>) -> Vec<Uuid> {
    let mut ids = Vec::with_capacity(requested.len() + 1);
    ids.push(creator);
    ids.extend(requested.into_iter().filter(|id| *id != creator));
    ids
}

pub async fn create_chat(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(payload): Json<CreateChat>,
) -> Result<Json<Chat>, StatusCode> {
    let chat_id = Uuid::now_v7();

    let mut tx = state.db.begin().await.map_err(|e| {
        eprintln!("DB begin error: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let chat = sqlx::query_as::<_, Chat>(
        "INSERT INTO chats (id, is_group, name) VALUES ($1, $2, $3) RETURNING id, is_group, name, created_at",
    )
    .bind(chat_id)
    .bind(payload.is_group)
    .bind(&payload.name)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        eprintln!("Insert chat error: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    sqlx::query("INSERT INTO chat_members (chat_id, user_id) VALUES ($1, $2)")
        .bind(chat_id)
        .bind(auth.user_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            eprintln!("Insert member error: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    for member_id in resolve_member_ids(auth.user_id, payload.member_ids)
        .into_iter()
        .skip(1)
    {
        sqlx::query("INSERT INTO chat_members (chat_id, user_id) VALUES ($1, $2)")
            .bind(chat_id)
            .bind(member_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                eprintln!("Insert member error: {:?}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
    }

    tx.commit().await.map_err(|e| {
        eprintln!("DB commit error: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    Ok(Json(chat))
}

pub async fn list_my_chats(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<Chat>>, StatusCode> {
    let chats = sqlx::query_as::<_, Chat>(
        "SELECT chats.id, chats.is_group, chats.name, chats.created_at
        FROM chats
        JOIN chat_members ON chat_members.chat_id = chats.id
        WHERE chat_members.user_id = $1",
    )
    .bind(auth.user_id)
    .fetch_all(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(chats))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creator_is_added_when_no_members_requested() {
        let creator = Uuid::new_v4();
        assert_eq!(resolve_member_ids(creator, vec![]), vec![creator]);
    }

    #[test]
    fn creator_duplicates_are_skipped_but_others_kept() {
        let creator = Uuid::new_v4();
        let other = Uuid::new_v4();
        let resolved = resolve_member_ids(creator, vec![creator, other, creator]);
        assert_eq!(resolved, vec![creator, other]);
    }

    #[test]
    fn other_members_keep_request_order() {
        let creator = Uuid::new_v4();
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        assert_eq!(
            resolve_member_ids(creator, vec![first, second]),
            vec![creator, first, second]
        );
    }
}
