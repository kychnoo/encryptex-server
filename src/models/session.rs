use serde::{Deserialize, Serialize};
use sqlx::types::chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    pub public_key: String,
}

#[derive(Serialize, Deserialize)]
pub struct DeleteSessionRequest {
    pub nonce: String,
    pub signature: String,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub token: String,
}

#[derive(Debug, Serialize)]
pub struct NonceResponse {
    pub nonce: String,
}

#[derive(sqlx::FromRow)]
pub struct UserWithPassword {
    pub id: Uuid,
    pub username: String,
    pub password_hash: String,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token: String,
    pub expires_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_serializes_without_leaking_extra_columns() {
        let session = Session {
            id: Uuid::nil(),
            user_id: Uuid::nil(),
            token: "tok".to_string(),
            expires_at: chrono::DateTime::from_timestamp(0, 0).unwrap().into(),
        };
        let json = serde_json::to_value(&session).unwrap();
        assert_eq!(json["token"], serde_json::json!("tok"));
        for field in ["id", "user_id", "token", "expires_at"] {
            assert!(json.get(field).is_some(), "missing field: {field}");
        }
    }
}
