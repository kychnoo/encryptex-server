use argon2::{
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
    password_hash::{SaltString, rand_core::OsRng},
};
use axum::{
    extract::FromRequestParts,
    http::{StatusCode, header},
};
use chrono::Utc;
use uuid::Uuid;

use crate::state::AppState;

#[derive(Debug)]
pub struct AuthUser {
    pub user_id: Uuid,
    pub token: String,
    pub session_id: Uuid,
}

/// Extracts the raw token from an `Authorization` header value.
///
/// Returns `None` unless the value uses the exact `Bearer <token>` scheme.
pub fn extract_bearer_token(header_value: &str) -> Option<&str> {
    header_value.strip_prefix("Bearer ")
}

pub fn hash_password(password: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    argon2
        .hash_password(password.as_bytes(), &salt)
        .expect("Error hashing password")
        .to_string()
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    let parsed_hash = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

impl FromRequestParts<AppState> for AuthUser {
    type Rejection = StatusCode;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let header_value = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .ok_or(StatusCode::UNAUTHORIZED)?;

        let token = extract_bearer_token(header_value).ok_or(StatusCode::UNAUTHORIZED)?;

        let row: Option<(Uuid, Uuid, chrono::DateTime<Utc>)> =
            sqlx::query_as("SELECT id, user_id, expires_at FROM sessions WHERE token = $1")
                .bind(token)
                .fetch_optional(&state.db)
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let (id, user_id, expires_at) = row.ok_or(StatusCode::UNAUTHORIZED)?;
        if expires_at < Utc::now() {
            return Err(StatusCode::UNAUTHORIZED);
        }

        sqlx::query("UPDATE sessions SET last_used_at = now() WHERE token = $1")
            .bind(token)
            .execute(&state.db)
            .await
            .ok();

        Ok(AuthUser {
            user_id,
            token: token.to_string(),
            session_id: id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_hash_verifies_correct_password() {
        let hash = hash_password("super_secure_password_123");
        assert!(verify_password("super_secure_password_123", &hash));
    }

    #[test]
    fn password_hash_rejects_wrong_password() {
        let hash = hash_password("super_secure_password_123");
        assert!(!verify_password("wrong_password", &hash));
        assert!(!verify_password("", &hash));
        assert!(!verify_password("super_secure_password_124", &hash));
    }

    #[test]
    fn password_hash_uses_random_salt() {
        let first = hash_password("same_password");
        let second = hash_password("same_password");
        assert_ne!(
            first, second,
            "identical passwords must produce different hashes"
        );
        assert!(verify_password("same_password", &first));
        assert!(verify_password("same_password", &second));
    }

    #[test]
    fn password_hash_format_is_argon2() {
        let hash = hash_password("password");
        assert!(
            hash.starts_with("$argon2"),
            "unexpected hash format: {hash}"
        );
    }

    #[test]
    fn verify_password_rejects_malformed_hashes_without_panicking() {
        for malformed in ["", "not-a-hash", "$argon2id$v=19$m=19456", "   "] {
            assert!(
                !verify_password("anything", malformed),
                "malformed hash should not verify: {malformed:?}"
            );
        }
    }

    #[test]
    fn password_hash_supports_unicode_and_empty_passwords() {
        for password in ["", "пароль_с_юникодом_🔐", &"x".repeat(256)] {
            let hash = hash_password(password);
            assert!(verify_password(password, &hash));
        }
    }

    #[test]
    fn bearer_extraction_accepts_valid_header() {
        assert_eq!(extract_bearer_token("Bearer abc123"), Some("abc123"));
    }

    #[test]
    fn bearer_extraction_rejects_other_schemes_and_malformed_values() {
        assert_eq!(extract_bearer_token(""), None);
        assert_eq!(extract_bearer_token("abc123"), None);
        assert_eq!(extract_bearer_token("bearer abc123"), None);
        assert_eq!(extract_bearer_token("Bearerabc123"), None);
        assert_eq!(extract_bearer_token("Basic YWJj"), None);
        // Empty token after a valid prefix is the caller's concern (DB lookup fails),
        // but the prefix parsing itself succeeds.
        assert_eq!(extract_bearer_token("Bearer "), Some(""));
    }
}
