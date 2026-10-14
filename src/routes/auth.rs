use std::net::SocketAddr;

use axum::{
    Json,
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, StatusCode},
};
use base64::{
    Engine, alphabet,
    engine::{GeneralPurpose, general_purpose},
};
use chrono::{Duration, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rand::{RngExt, distr::Alphanumeric};
use uuid::Uuid;

use crate::{
    auth::{self, AuthUser},
    models::session::{
        DeleteSessionRequest, LoginRequest, LoginResponse, NonceResponse, Session, UserWithPassword,
    },
    state::AppState,
};

pub async fn login(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, StatusCode> {
    let user = sqlx::query_as::<_, UserWithPassword>(
        "SELECT id, username, password_hash FROM users WHERE username = $1",
    )
    .bind(&payload.username)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .ok_or(StatusCode::UNAUTHORIZED)?;

    if !auth::verify_password(&payload.password, &user.password_hash) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let token = generate_token();

    let session_id = Uuid::now_v7();
    let expires_at = Utc::now() + Duration::days(30);
    let ip = addr.ip().to_string();

    let device_info = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown");

    sqlx::query("INSERT INTO sessions (id, user_id, token, device_info, ip_address, public_key, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7)")
        .bind(session_id)
        .bind(user.id)
        .bind(&token)
        .bind(device_info)
        .bind(ip)
        .bind(&payload.public_key)
        .bind(expires_at)
        .execute(&state.db)
        .await
        .map_err(|e| { eprintln!("{}", e); StatusCode::INTERNAL_SERVER_ERROR })?;

    Ok(Json(LoginResponse { token }))
}

pub async fn list_sessions(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<Session>>, StatusCode> {
    let sessions = sqlx::query_as::<_, Session>(
        "SELECT id, user_id, token, expires_at FROM sessions WHERE user_id = $1",
    )
    .bind(auth.user_id)
    .fetch_all(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(sessions))
}

pub async fn delete_session(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(session_id): Path<Uuid>,
    Json(payload): Json<DeleteSessionRequest>,
) -> Result<StatusCode, StatusCode> {
    let current_key: Option<(String,)> =
        sqlx::query_as("SELECT public_key FROM sessions WHERE user_id = $1 AND token = $2")
            .bind(auth.user_id)
            .bind(&auth.token)
            .fetch_optional(&state.db)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let (public_key_pem,) = current_key.ok_or(StatusCode::UNAUTHORIZED)?;

    let consumed = sqlx::query(
        "DELETE FROM nonces WHERE nonce = $1 AND session_id = $2 AND expires_at > now()",
    )
    .bind(&payload.nonce)
    .bind(auth.session_id)
    .execute(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if consumed.rows_affected() != 1 {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let message = delete_session_message(&session_id, &payload.nonce);
    verify_nonce_signature(&public_key_pem, &message, &payload.signature)?;

    let result = sqlx::query("DELETE FROM sessions WHERE id = $1 AND user_id = $2")
        .bind(session_id)
        .bind(auth.user_id)
        .execute(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if result.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }

    Ok(StatusCode::NO_CONTENT)
}

pub(crate) fn generate_token() -> String {
    rand::rng()
        .sample_iter(&Alphanumeric)
        .take(64)
        .map(char::from)
        .collect()
}

pub(crate) fn generate_nonce() -> String {
    rand::rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}

pub(crate) fn parse_public_key(pem: &str) -> Result<VerifyingKey, Box<dyn std::error::Error>> {
    use ed25519_dalek::pkcs8::DecodePublicKey;
    Ok(VerifyingKey::from_public_key_pem(pem)?)
}

pub(crate) fn delete_session_message(session_id: &Uuid, nonce: &str) -> String {
    format!("delete-session:{session_id}:{nonce}")
}

pub(crate) fn verify_nonce_signature(
    public_key_pem: &str,
    message: &str,
    signature_b64: &str,
) -> Result<(), StatusCode> {
    let verifying_key =
        parse_public_key(public_key_pem).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let signature_bytes = GeneralPurpose::new(&alphabet::STANDARD, general_purpose::PAD)
        .decode(signature_b64)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let signature = Signature::from_slice(&signature_bytes).map_err(|_| StatusCode::BAD_REQUEST)?;

    verifying_key
        .verify(message.as_bytes(), &signature)
        .map_err(|_| StatusCode::UNAUTHORIZED)
}

pub async fn get_nonce(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<NonceResponse>, StatusCode> {
    let nonce = generate_nonce();

    sqlx::query("INSERT INTO nonces (nonce, session_id, expires_at) VALUES ($1, $2, now() + interval '60 seconds')")
        .bind(&nonce)
        .bind(auth.session_id)
        .execute(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(NonceResponse { nonce }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey, pkcs8::EncodePublicKey};

    /// Deterministic key so tests don't depend on RNG compatibility.
    fn test_signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn public_key_pem(signing: &SigningKey) -> String {
        // NB: pkcs8::LineEnding is unavailable with the enabled feature set,
        // so wrap the SPKI DER in PEM manually.
        let der = signing
            .verifying_key()
            .to_public_key_der()
            .expect("key must serialize to DER");
        let b64 = general_purpose::STANDARD.encode(der.as_bytes());
        let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(chunk).unwrap());
            pem.push('\n');
        }
        pem.push_str("-----END PUBLIC KEY-----\n");
        pem
    }

    fn sign_b64(signing: &SigningKey, message: &str) -> String {
        general_purpose::STANDARD.encode(signing.sign(message.as_bytes()).to_bytes())
    }

    fn bound_message(session_id: &Uuid, nonce: &str) -> String {
        delete_session_message(session_id, nonce)
    }

    #[test]
    fn test_password_hashing() {
        let password = "super_secure_password_123";
        let hashed = auth::hash_password(password);
        assert!(auth::verify_password(password, &hashed));
        assert!(!auth::verify_password("wrong_password", &hashed));
    }

    #[test]
    fn generated_tokens_are_unique_alphanumeric_64_chars() {
        let first = generate_token();
        let second = generate_token();
        for token in [&first, &second] {
            assert_eq!(token.len(), 64);
            assert!(token.chars().all(|c| c.is_ascii_alphanumeric()));
        }
        assert_ne!(first, second);
    }

    #[test]
    fn generated_nonces_are_unique_alphanumeric_32_chars() {
        let first = generate_nonce();
        let second = generate_nonce();
        for nonce in [&first, &second] {
            assert_eq!(nonce.len(), 32);
            assert!(nonce.chars().all(|c| c.is_ascii_alphanumeric()));
        }
        assert_ne!(first, second);
    }

    #[test]
    fn parse_public_key_roundtrip() {
        let signing = test_signing_key(42);
        let pem = public_key_pem(&signing);
        assert!(pem.contains("PUBLIC KEY"));
        let parsed = parse_public_key(&pem).expect("valid PEM must parse");
        assert_eq!(parsed, signing.verifying_key());
    }

    #[test]
    fn parse_public_key_rejects_garbage() {
        for bad in [
            "",
            "not a key",
            "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----",
        ] {
            assert!(parse_public_key(bad).is_err(), "should fail: {bad:?}");
        }
    }

    #[test]
    fn valid_signature_verifies() {
        let signing = test_signing_key(7);
        let session_id = Uuid::new_v4();
        let message = bound_message(&session_id, "test-nonce-123");
        let signature = sign_b64(&signing, &message);
        assert!(verify_nonce_signature(&public_key_pem(&signing), &message, &signature).is_ok());
    }

    #[test]
    fn delete_session_message_format_is_pinned() {
        let session_id = Uuid::nil();
        let nonce = "abc123";
        assert_eq!(
            delete_session_message(&session_id, &nonce),
            format!("delete-session:{session_id}:{nonce}")
        )
    }

    #[test]
    fn tampered_nonce_fails_verification() {
        let signing = test_signing_key(7);
        let session_id = Uuid::new_v4();
        let signature = sign_b64(&signing, &bound_message(&session_id, "original-nonce"));
        let err = verify_nonce_signature(
            &public_key_pem(&signing),
            &bound_message(&session_id, "tampered-nonce"),
            &signature,
        )
        .unwrap_err();
        assert_eq!(err, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn signature_cannot_move_to_another_session() {
        let signing = test_signing_key(7);
        let pem = public_key_pem(&signing);
        let nonce = "shared-nonce";
        let signature = sign_b64(&signing, &bound_message(&Uuid::new_v4(), nonce));
        let err = verify_nonce_signature(&pem, &bound_message(&Uuid::new_v4(), nonce), &signature)
            .unwrap_err();
        assert_eq!(err, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn bare_nonce_signature_is_rejected_for_bound_message() {
        let signing = test_signing_key(7);
        let session_id = Uuid::new_v4();
        let nonce = "some-nonce";
        let legacy_signature = sign_b64(&signing, nonce);
        let err = verify_nonce_signature(
            &public_key_pem(&signing),
            &bound_message(&session_id, nonce),
            &legacy_signature,
        )
        .unwrap_err();

        assert_eq!(err, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn signature_from_other_key_fails_verification() {
        let signing = test_signing_key(7);
        let other = test_signing_key(9);
        let session_id = Uuid::new_v4();
        let message = bound_message(&session_id, "some-nonce");
        let signature = sign_b64(&other, &message);
        let err =
            verify_nonce_signature(&public_key_pem(&signing), &message, &signature).unwrap_err();
        assert_eq!(err, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn malformed_signature_is_bad_request() {
        let signing = test_signing_key(7);
        let pem = public_key_pem(&signing);
        // Not base64 at all.
        assert_eq!(
            verify_nonce_signature(&pem, "nonce", "!!!not-base64!!!").unwrap_err(),
            StatusCode::BAD_REQUEST
        );
        // Valid base64 but wrong length for an ed25519 signature (needs 64 bytes).
        let short = general_purpose::STANDARD.encode([1u8, 2, 3]);
        assert_eq!(
            verify_nonce_signature(&pem, "nonce", &short).unwrap_err(),
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn invalid_public_key_is_server_error() {
        let signing = test_signing_key(7);
        let signature = sign_b64(&signing, "nonce");
        assert_eq!(
            verify_nonce_signature("definitely-not-pem", "nonce", &signature).unwrap_err(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn login_request_requires_all_fields() {
        let json = serde_json::json!({"username": "u", "password": "p", "public_key": "k"});
        let parsed: LoginRequest = serde_json::from_value(json).expect("full payload parses");
        assert_eq!(parsed.username, "u");

        for incomplete in [
            serde_json::json!({"username": "u", "password": "p"}),
            serde_json::json!({"username": "u"}),
            serde_json::json!({}),
        ] {
            assert!(
                serde_json::from_value::<LoginRequest>(incomplete).is_err(),
                "missing fields must fail"
            );
        }
    }

    #[test]
    fn delete_session_request_roundtrip() {
        let payload = DeleteSessionRequest {
            nonce: "n".to_string(),
            signature: "s".to_string(),
        };
        let json = serde_json::to_value(&payload).unwrap();
        let parsed: DeleteSessionRequest = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.nonce, "n");
        assert_eq!(parsed.signature, "s");
    }

    #[test]
    fn login_and_nonce_responses_serialize() {
        let login = serde_json::to_value(LoginResponse {
            token: "tok".to_string(),
        })
        .unwrap();
        assert_eq!(login, serde_json::json!({"token": "tok"}));

        let nonce = serde_json::to_value(NonceResponse {
            nonce: "n".to_string(),
        })
        .unwrap();
        assert_eq!(nonce, serde_json::json!({"nonce": "n"}));
    }
}
