use axum::{Json, extract::State, http::StatusCode};
use uuid::Uuid;

use crate::{
    auth::{self, AuthUser},
    models::user::{CreateUser, User},
    state::AppState,
};

pub async fn create_user(
    State(state): State<AppState>,
    Json(payload): Json<CreateUser>,
) -> Result<Json<User>, StatusCode> {
    let id = Uuid::now_v7();
    let password_hash = auth::hash_password(&payload.password);
    let user = sqlx::query_as::<_, User>(
        "INSERT INTO users (id, username, password_hash) VALUES ($1, $2, $3) RETURNING id, username",
    )
    .bind(id)
    .bind(&payload.username)
    .bind(password_hash)
    .fetch_one(&state.db)
    .await
    .map_err(|_| { eprintln!("Error on insert a new user in DB."); StatusCode::INTERNAL_SERVER_ERROR })?;

    Ok(Json(user))
}

pub async fn list_users(State(state): State<AppState>) -> Result<Json<Vec<User>>, StatusCode> {
    let users = sqlx::query_as::<_, User>("SELECT id, username FROM users")
        .fetch_all(&state.db)
        .await
        .map_err(|_| {
            println!("Error on select users from DB.");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(users))
}

pub async fn me(State(state): State<AppState>, auth: AuthUser) -> Result<Json<User>, StatusCode> {
    let user = sqlx::query_as::<_, User>("SELECT id, username FROM users WHERE id = $1")
        .bind(auth.user_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| axum::http::StatusCode::NOT_FOUND)?;

    Ok(Json(user))
}
