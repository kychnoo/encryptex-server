use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct Chat {
    pub id: Uuid,
    pub is_group: bool,
    pub name: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Deserialize)]
pub struct CreateChat {
    pub member_ids: Vec<Uuid>,
    pub is_group: bool,
    pub name: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_direct_chat_deserializes() {
        let other = Uuid::new_v4();
        let payload: CreateChat = serde_json::from_value(serde_json::json!({
            "member_ids": [other],
            "is_group": false,
            "name": null,
        }))
        .unwrap();
        assert_eq!(payload.member_ids, vec![other]);
        assert!(!payload.is_group);
        assert_eq!(payload.name, None);
    }

    #[test]
    fn create_group_chat_with_name_deserializes() {
        let payload: CreateChat = serde_json::from_value(serde_json::json!({
            "member_ids": [],
            "is_group": true,
            "name": "team",
        }))
        .unwrap();
        assert!(payload.is_group);
        assert_eq!(payload.name.as_deref(), Some("team"));
    }

    #[test]
    fn create_chat_rejects_missing_fields() {
        for incomplete in [
            serde_json::json!({"is_group": false}),
            serde_json::json!({"member_ids": []}),
            serde_json::json!({}),
        ] {
            assert!(serde_json::from_value::<CreateChat>(incomplete).is_err());
        }
    }

    #[test]
    fn chat_serializes_all_fields() {
        let id = Uuid::new_v4();
        let chat = Chat {
            id,
            is_group: true,
            name: Some("team".to_string()),
            created_at: chrono::DateTime::from_timestamp(0, 0).unwrap().into(),
        };
        let json = serde_json::to_value(&chat).unwrap();
        assert_eq!(json["id"], serde_json::json!(id));
        assert_eq!(json["is_group"], serde_json::json!(true));
        assert_eq!(json["name"], serde_json::json!("team"));
        assert!(json.get("created_at").is_some());
    }
}
