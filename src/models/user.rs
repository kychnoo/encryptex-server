use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
pub struct CreateUser {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct User {
    pub id: Uuid,
    pub username: String,
}

#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    pub old_password: String,
    pub new_password: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_user_deserializes() {
        let payload: CreateUser =
            serde_json::from_value(serde_json::json!({"username": "alice", "password": "s3cret"}))
                .unwrap();
        assert_eq!(payload.username, "alice");
        assert_eq!(payload.password, "s3cret");
    }

    #[test]
    fn create_user_rejects_missing_fields() {
        for incomplete in [
            serde_json::json!({"username": "alice"}),
            serde_json::json!({"password": "s3cret"}),
            serde_json::json!({}),
        ] {
            assert!(serde_json::from_value::<CreateUser>(incomplete).is_err());
        }
    }

    #[test]
    fn user_serialization_exposes_only_id_and_username() {
        let user = User {
            id: Uuid::nil(),
            username: "alice".to_string(),
        };
        let json = serde_json::to_value(&user).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "id": Uuid::nil(),
                "username": "alice",
            }),
            "User JSON must not leak password hashes or other internals"
        );
    }
}
