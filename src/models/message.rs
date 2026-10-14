use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct Message {
    pub id: Uuid,
    pub chat_id: Uuid,
    pub sender_id: Uuid,
    pub text: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Deserialize)]
pub struct SendMessage {
    pub text: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_message_deserializes() {
        let payload: SendMessage =
            serde_json::from_value(serde_json::json!({"text": "hello"})).unwrap();
        assert_eq!(payload.text, "hello");
    }

    #[test]
    fn send_message_rejects_missing_text() {
        assert!(serde_json::from_value::<SendMessage>(serde_json::json!({})).is_err());
    }

    #[test]
    fn message_serializes_all_fields() {
        let message = Message {
            id: Uuid::nil(),
            chat_id: Uuid::nil(),
            sender_id: Uuid::nil(),
            text: "hi".to_string(),
            created_at: chrono::DateTime::from_timestamp(0, 0).unwrap().into(),
        };
        let json = serde_json::to_value(&message).unwrap();
        assert_eq!(json["text"], serde_json::json!("hi"));
        for field in ["id", "chat_id", "sender_id", "text", "created_at"] {
            assert!(json.get(field).is_some(), "missing field: {field}");
        }
    }
}
