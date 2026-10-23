use std::{net::SocketAddr, sync::LazyLock};

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
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    auth::{self, AuthUser},
    error::{ApiError, ErrorResult, api_error, internal_error},
    json::AppJson,
    models::{
        session::{
            DeleteSessionRequest, LoginRequest, LoginResponse, NonceResponse, RefreshRequest,
            RefreshResponse, Session, UserWithPassword,
        },
        user::ChangePasswordRequest,
    },
    state::AppState,
};

static DUMMY_HASH: LazyLock<String> = LazyLock::new(|| auth::hash_password("dummy-password"));

const MAX_FAILURES: i64 = 5;
const SESSION_TTL_HOURS: i64 = 72;

async fn is_locked_out(db: &PgPool, username: &str) -> Result<bool, ApiError> {
    sqlx::query("DELETE FROM login_failures WHERE created_at < now() - interval '15 minutes'")
        .execute(db)
        .await
        .map_err(internal_error)?;

    let (n,): (i64,) = sqlx::query_as("SELECT count(*) FROM login_failures WHERE username = $1")
        .bind(username)
        .fetch_one(db)
        .await
        .map_err(internal_error)?;

    Ok(n >= MAX_FAILURES)
}

async fn record_failure(db: &PgPool, username: &str) {
    let res = sqlx::query("INSERT INTO login_failures (id, username) VALUES ($1, $2)")
        .bind(Uuid::now_v7())
        .bind(username)
        .execute(db)
        .await;

    if let Err(e) = res {
        eprint!("record_failure: {e:?}");
    }
}

async fn find_and_verify(
    db: &PgPool,
    username: &str,
    password: &str,
) -> Result<Option<UserWithPassword>, ApiError> {
    let user = sqlx::query_as::<_, UserWithPassword>(
        "SELECT id, username, password_hash FROM users WHERE username = $1",
    )
    .bind(username)
    .fetch_optional(db)
    .await
    .map_err(internal_error)?;

    let hash = user
        .as_ref()
        .map(|u| u.password_hash.clone())
        .unwrap_or_else(|| DUMMY_HASH.clone());
    let password = password.to_owned();
    let ok = tokio::task::spawn_blocking(move || auth::verify_password(&password, &hash))
        .await
        .unwrap_or(false);

    Ok(user.filter(|_| ok))
}

pub async fn login(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    AppJson(payload): AppJson<LoginRequest>,
) -> Result<Json<LoginResponse>, (StatusCode, ErrorResult)> {
    if is_locked_out(&state.db, &payload.username).await? {
        return Err(api_error(
            StatusCode::TOO_MANY_REQUESTS,
            "too_many_attempts",
            "Too many failed attempts, try again later",
        ));
    }

    let Some(user) = find_and_verify(&state.db, &payload.username, &payload.password).await? else {
        record_failure(&state.db, &payload.username).await;
        return Err(api_error(
            StatusCode::UNAUTHORIZED,
            "invalid_credentials",
            "Invalid authorization credentials",
        ));
    };

    let token = generate_token();
    let device_info = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown");

    let session_id = Uuid::now_v7();

    sqlx::query("INSERT INTO sessions (id, user_id, token, device_info, ip_address, public_key, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7)")
        .bind(session_id)
        .bind(user.id)
        .bind(&token)
        .bind(device_info)
        .bind(addr.ip().to_string())
        .bind(&payload.public_key)
        .bind(Utc::now() + Duration::hours(SESSION_TTL_HOURS))
        .execute(&state.db)
        .await
        .map_err(internal_error)?;

    if let Err(e) = sqlx::query("UPDATE sessions SET is_master = true WHERE id = $1 AND NOT EXISTS (SELECT 1 FROM sessions WHERE user_id = $2 AND is_master)")
        .bind(session_id)
        .bind(user.id)
        .execute(&state.db)
        .await
    {
        eprintln!("Master assign: {e:?}")
    }

    sqlx::query("DELETE FROM login_failures WHERE username = $1")
        .bind(&payload.username)
        .execute(&state.db)
        .await
        .map_err(internal_error)?;

    Ok(Json(LoginResponse {
        token: token,
        expires_at: Utc::now() + Duration::hours(SESSION_TTL_HOURS),
    }))
}

pub async fn list_sessions(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<Session>>, ApiError> {
    let sessions = sqlx::query_as::<_, Session>(
        "SELECT id, user_id, token, expires_at FROM sessions WHERE user_id = $1",
    )
    .bind(auth.user_id)
    .fetch_all(&state.db)
    .await
    .map_err(internal_error)?;

    Ok(Json(sessions))
}

pub async fn refresh(
    State(state): State<AppState>,
    auth: AuthUser,
    AppJson(payload): AppJson<RefreshRequest>,
) -> Result<Json<RefreshResponse>, ApiError> {
    let message = refresh_message(&payload.nonce);
    verify_device_signature(
        &state.db,
        auth.session_id,
        &payload.nonce,
        &message,
        &payload.signature,
    )
    .await?;

    let token = generate_token();
    let expires_at = Utc::now() + Duration::hours(SESSION_TTL_HOURS);

    let updated = sqlx::query(
        "UPDATE sessions
        SET prev_token = token,
            prev_token_valid_until = now() + interval '2 minutes',
            token = $1,
            expires_at = $2
        WHERE id = $3 AND expires_at > now()",
    )
    .bind(&token)
    .bind(expires_at)
    .bind(auth.session_id)
    .execute(&state.db)
    .await
    .map_err(internal_error)?;

    if updated.rows_affected() == 0 {
        return Err(api_error(
            StatusCode::UNAUTHORIZED,
            "token_expired",
            "Token is expired and cannot be refreshed",
        ));
    }

    Ok(Json(RefreshResponse { token, expires_at }))
}

pub async fn verify_device_signature(
    db: &PgPool,
    session_id: Uuid,
    nonce: &str,
    message: &str,
    signature_b64: &str,
) -> Result<(), ApiError> {
    let consumed = sqlx::query(
        "DELETE FROM nonces WHERE nonce = $1 AND session_id = $2 AND expires_at > now()",
    )
    .bind(nonce)
    .bind(session_id)
    .execute(db)
    .await
    .map_err(internal_error)?;

    if consumed.rows_affected() != 1 {
        return Err(api_error(
            StatusCode::UNAUTHORIZED,
            "invalid_nonce",
            "Invalid or expired nonce",
        ));
    }

    let (pem,): (Option<String>,) = sqlx::query_as("SELECT public_key FROM sessions WHERE id = $1")
        .bind(session_id)
        .fetch_one(db)
        .await
        .map_err(internal_error)?;

    let pem =
        pem.ok_or_else(|| api_error(StatusCode::UNAUTHORIZED, "key_not_found", "Key not found"))?;

    verify_nonce_signature(&pem, message, signature_b64)
}

pub async fn delete_session(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(session_id): Path<Uuid>,
    AppJson(payload): AppJson<DeleteSessionRequest>,
) -> Result<StatusCode, ApiError> {
    let message = delete_session_message(&session_id, &payload.nonce);

    if session_id != auth.session_id {
        let (is_master,): (bool,) = sqlx::query_as("SELECT is_master FROM sessions WHERE id = $1")
            .bind(auth.session_id)
            .fetch_one(&state.db)
            .await
            .map_err(internal_error)?;

        if !is_master {
            return Err(api_error(
                StatusCode::FORBIDDEN,
                "master_required",
                "Only the master session can revoke other sessions",
            ));
        }
    }

    verify_device_signature(
        &state.db,
        auth.session_id,
        &payload.nonce,
        &message,
        &payload.signature,
    )
    .await?;

    let result = sqlx::query("DELETE FROM sessions WHERE id = $1 AND user_id = $2")
        .bind(session_id)
        .bind(auth.user_id)
        .execute(&state.db)
        .await
        .map_err(internal_error)?;

    if result.rows_affected() == 0 {
        return Err(api_error(
            StatusCode::NOT_FOUND,
            "session_not_found",
            "Session not found",
        ));
    }

    if let Some(sessions) = state.connections.write().await.get_mut(&auth.user_id) {
        sessions.remove(&session_id);
    }

    Ok(StatusCode::NO_CONTENT)
}

pub async fn change_password(
    State(state): State<AppState>,
    auth: AuthUser,
    AppJson(payload): AppJson<ChangePasswordRequest>,
) -> Result<StatusCode, ApiError> {
    if payload.new_password.len() < 6 {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "weak_password",
            "Password must be at least 6 characters",
        ));
    }

    let (username,): (String,) = sqlx::query_as("SELECT username FROM users WHERE id = $1")
        .bind(auth.user_id)
        .fetch_one(&state.db)
        .await
        .map_err(internal_error)?;

    if is_locked_out(&state.db, &username).await? {
        return Err(api_error(
            StatusCode::TOO_MANY_REQUESTS,
            "too_many_attempts",
            "Too many failed attempts, try again later",
        ));
    }

    if find_and_verify(&state.db, &username, &payload.old_password)
        .await?
        .is_none()
    {
        record_failure(&state.db, &username).await;
        return Err(api_error(
            StatusCode::UNAUTHORIZED,
            "invalid_credentials",
            "Invalid authorization credentials",
        ));
    }

    let new_password = payload.new_password;
    let new_hash = tokio::task::spawn_blocking(move || auth::hash_password(&new_password))
        .await
        .map_err(internal_error)?;

    let mut tx = state.db.begin().await.map_err(internal_error)?;

    sqlx::query("UPDATE users SET password_hash = $1 WHERE id = $2")
        .bind(&new_hash)
        .bind(auth.user_id)
        .execute(&mut *tx)
        .await
        .map_err(internal_error)?;

    sqlx::query("DELETE FROM sessions WHERE user_id = $1 AND id != $2")
        .bind(&auth.user_id)
        .bind(auth.session_id)
        .execute(&mut *tx)
        .await
        .map_err(internal_error)?;

    sqlx::query("UPDATE sessions SET is_master = true WHERE id = $1")
        .bind(auth.session_id)
        .execute(&mut *tx)
        .await
        .map_err(internal_error)?;

    tx.commit().await.map_err(internal_error)?;

    if let Some(conns) = state.connections.write().await.get_mut(&auth.user_id) {
        conns.retain(|sid, _| *sid == auth.session_id);
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

pub(crate) fn refresh_message(nonce: &str) -> String {
    format!("refresh-session:{nonce}")
}

pub(crate) fn verify_nonce_signature(
    public_key_pem: &str,
    message: &str,
    signature_b64: &str,
) -> Result<(), ApiError> {
    let verifying_key = parse_public_key(public_key_pem).map_err(internal_error)?;
    let signature_bytes = GeneralPurpose::new(&alphabet::STANDARD, general_purpose::PAD)
        .decode(signature_b64)
        .map_err(|_| {
            api_error(
                StatusCode::BAD_REQUEST,
                "bad_verify_nonce_signature",
                "Error verifying the nonce signature",
            )
        })?;
    let signature = Signature::from_slice(&signature_bytes).map_err(|_| {
        api_error(
            StatusCode::BAD_REQUEST,
            "bad_verify_nonce_signature",
            "Error verifying the nonce signature",
        )
    })?;

    verifying_key
        .verify(message.as_bytes(), &signature)
        .map_err(|_| {
            api_error(
                StatusCode::UNAUTHORIZED,
                "key_not_verified",
                "Key not verified",
            )
        })
}

pub async fn get_nonce(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<NonceResponse>, ApiError> {
    let nonce = generate_nonce();

    sqlx::query("INSERT INTO nonces (nonce, session_id, expires_at) VALUES ($1, $2, now() + interval '60 seconds')")
        .bind(&nonce)
        .bind(auth.session_id)
        .execute(&state.db)
        .await
        .map_err(internal_error)?;

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
    fn refresh_message_format_is_pinned() {
        let nonce = "abc123";
        assert_eq!(refresh_message(&nonce), format!("refresh-session:{nonce}"))
    }

    #[test]
    fn refresh_messages_differ_from_delete_messages() {
        let session_id = Uuid::new_v4();
        assert_ne!(
            refresh_message("n"),
            delete_session_message(&session_id, "n"),
            "authorization scopes must not be cross-forgeable"
        );
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
        assert_eq!(
            err,
            api_error(
                StatusCode::UNAUTHORIZED,
                "key_not_verified",
                "Key not verified",
            )
        );
    }

    #[test]
    fn signature_cannot_move_to_another_session() {
        let signing = test_signing_key(7);
        let pem = public_key_pem(&signing);
        let nonce = "shared-nonce";
        let signature = sign_b64(&signing, &bound_message(&Uuid::new_v4(), nonce));
        let err = verify_nonce_signature(&pem, &bound_message(&Uuid::new_v4(), nonce), &signature)
            .unwrap_err();
        assert_eq!(
            err,
            api_error(
                StatusCode::UNAUTHORIZED,
                "key_not_verified",
                "Key not verified",
            )
        );
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

        assert_eq!(
            err,
            api_error(
                StatusCode::UNAUTHORIZED,
                "key_not_verified",
                "Key not verified",
            )
        );
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
        assert_eq!(
            err,
            api_error(
                StatusCode::UNAUTHORIZED,
                "key_not_verified",
                "Key not verified",
            )
        );
    }

    #[test]
    fn malformed_signature_is_bad_request() {
        let signing = test_signing_key(7);
        let pem = public_key_pem(&signing);
        // Not base64 at all.
        assert_eq!(
            verify_nonce_signature(&pem, "nonce", "!!!not-base64!!!").unwrap_err(),
            api_error(
                StatusCode::BAD_REQUEST,
                "bad_verify_nonce_signature",
                "Error verifying the nonce signature",
            )
        );
        // Valid base64 but wrong length for an ed25519 signature (needs 64 bytes).
        let short = general_purpose::STANDARD.encode([1u8, 2, 3]);
        assert_eq!(
            verify_nonce_signature(&pem, "nonce", &short).unwrap_err(),
            api_error(
                StatusCode::BAD_REQUEST,
                "bad_verify_nonce_signature",
                "Error verifying the nonce signature",
            )
        );
    }

    #[test]
    fn invalid_public_key_is_server_error() {
        let signing = test_signing_key(7);
        let signature = sign_b64(&signing, "nonce");
        assert_eq!(
            verify_nonce_signature("definitely-not-pem", "nonce", &signature)
                .unwrap_err()
                .0,
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
    fn refresh_request_requires_all_fields() {
        let payload = RefreshRequest {
            nonce: "nonce-1".to_string(),
            signature: "sig".to_string(),
        };
        let json = serde_json::to_value(&payload).unwrap();
        let parsed: RefreshRequest = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.nonce, "nonce-1");

        for incomplete in [
            serde_json::json!({"nonce": "nonce-1"}),
            serde_json::json!({}),
        ] {
            assert!(
                serde_json::from_value::<RefreshRequest>(incomplete).is_err(),
                "missing fields must fail"
            );
        }
    }

    #[test]
    fn auth_responses_serialize_with_expiry() {
        let expiration_date = Utc::now() + Duration::hours(SESSION_TTL_HOURS);
        let login = serde_json::to_value(LoginResponse {
            token: "tok".to_string(),
            expires_at: expiration_date,
        })
        .unwrap();
        assert_eq!(
            login,
            serde_json::json!({"token": "tok", "expires_at": &expiration_date})
        );

        let refresh = serde_json::to_value(RefreshResponse {
            token: "new-tok".to_string(),
            expires_at: expiration_date,
        })
        .unwrap();
        assert_eq!(
            refresh,
            serde_json::json!({"token": "new-tok", "expires_at": &expiration_date})
        );

        let nonce = serde_json::to_value(NonceResponse {
            nonce: "n".to_string(),
        })
        .unwrap();
        assert_eq!(nonce, serde_json::json!({"nonce": "n"}));
    }
}
