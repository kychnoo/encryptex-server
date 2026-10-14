//! End-to-end tests that drive the real Axum handlers against SQL database.
//!
//! Each test gracefully skips (passes with a notice) when `DATABASE_URL` is
//! unreachable, so `cargo test` stays green without local infrastructure.
//! Run Database (if you use docker: `docker compose up -d database_name(example: postgres)`) to execute them fully.

use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};

use axum::{
    Json,
    extract::{ConnectInfo, FromRequestParts, Path, State},
    http::{HeaderMap, StatusCode},
};
use base64::{Engine, engine::general_purpose};
use ed25519_dalek::{Signer, SigningKey, pkcs8::EncodePublicKey};
use sqlx::postgres::PgPoolOptions;
use tokio::sync::{RwLock, mpsc};
use uuid::Uuid;

use crate::{
    auth::AuthUser,
    models::{
        chat::CreateChat,
        message::SendMessage,
        session::{DeleteSessionRequest, LoginRequest},
        user::CreateUser,
    },
    routes::{
        auth::{delete_session, delete_session_message, get_nonce, list_sessions, login},
        chats::{create_chat, list_my_chats},
        messages::{list_messages, send_message},
        users::{create_user, me},
    },
    state::AppState,
};

fn skip_notice(test: &str) {
    eprintln!("skipping {test}: Postgres unreachable (set DATABASE_URL and run migrations)");
}

async fn test_state() -> Option<AppState> {
    dotenvy::dotenv().ok();
    let url = std::env::var("DATABASE_URL").ok()?;
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&url)
        .await
        .ok()?;
    sqlx::migrate!().run(&pool).await.ok()?;
    Some(AppState {
        db: pool,
        connections: Arc::new(RwLock::new(HashMap::new())),
    })
}

struct TestUser {
    id: Uuid,
    token: String,
    session_id: Uuid,
}

fn auth_of(user: &TestUser) -> AuthUser {
    AuthUser {
        user_id: user.id,
        token: user.token.clone(),
        session_id: user.session_id,
    }
}

fn test_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::USER_AGENT,
        "integration-test".parse().unwrap(),
    );
    headers
}

fn test_addr() -> ConnectInfo<SocketAddr> {
    ConnectInfo("127.0.0.1:5000".parse().unwrap())
}

async fn session_id_for(state: &AppState, token: &str) -> Uuid {
    sqlx::query_scalar("SELECT id FROM sessions WHERE token = $1")
        .bind(token)
        .fetch_one(&state.db)
        .await
        .expect("session must exist for issued token")
}

async fn register_and_login(state: &AppState, prefix: &str, public_key: &str) -> TestUser {
    let username = format!("{prefix}_{}", Uuid::new_v4().simple());
    let password = "password-123".to_string();

    let Json(created) = create_user(
        State(state.clone()),
        Json(CreateUser {
            username: username.clone(),
            password: password.clone(),
        }),
    )
    .await
    .expect("Create user must succeed");

    login_with_key(state, created.id, &username, &password, public_key).await
}

async fn login_with_key(
    state: &AppState,
    user_id: Uuid,
    username: &str,
    password: &str,
    public_key: &str,
) -> TestUser {
    let Json(session) = login(
        State(state.clone()),
        test_addr(),
        test_headers(),
        Json(LoginRequest {
            username: username.to_string(),
            password: password.to_string(),
            public_key: public_key.to_string(),
        }),
    )
    .await
    .expect("login must succeed");
    let session_id = session_id_for(state, &session.token).await;

    TestUser {
        id: user_id,
        token: session.token,
        session_id,
    }
}

async fn cleanup(state: &AppState, ids: &[Uuid]) {
    for id in ids {
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(id)
            .execute(&state.db)
            .await
            .ok();
    }
}

fn parts_with_auth(token: Option<&str>) -> axum::http::request::Parts {
    let mut builder = axum::http::Request::builder().uri("/");
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    builder.body(()).unwrap().into_parts().0
}

fn signing_key(seed: u8) -> SigningKey {
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

fn sign_message(signing: &SigningKey, message: &str) -> String {
    general_purpose::STANDARD.encode(signing.sign(message.as_bytes()).to_bytes())
}

fn sign_delete_session(signing: &SigningKey, session_id: &Uuid, nonce: &str) -> String {
    sign_message(signing, &delete_session_message(session_id, nonce))
}

#[tokio::test]
async fn register_login_me_flow() {
    let Some(state) = test_state().await else {
        skip_notice("register_login_me_flow");
        return;
    };

    let username = format!("flow_{}", Uuid::new_v4().simple());
    let Json(created) = create_user(
        State(state.clone()),
        Json(CreateUser {
            username: username.clone(),
            password: "password-123".to_string(),
        }),
    )
    .await
    .expect("Create user must succeed");
    assert_eq!(created.username, username);

    let user = login_with_key(
        &state,
        created.id,
        &username,
        "password-123",
        "second-device-key",
    )
    .await;
    assert!(!user.token.is_empty());

    let Json(profile) = me(State(state.clone()), auth_of(&user))
        .await
        .expect("me must succeed");
    assert_eq!(profile.id, created.id);
    assert_eq!(profile.username, username);

    cleanup(&state, &[created.id]).await;
}

#[tokio::test]
async fn login_rejects_bad_credentials() {
    let Some(state) = test_state().await else {
        skip_notice("login_rejects_bad_credentials");
        return;
    };

    let username = format!("badcreds_{}", Uuid::new_v4().simple());
    let Json(created) = create_user(
        State(state.clone()),
        Json(CreateUser {
            username: username.clone(),
            password: "right-password".to_string(),
        }),
    )
    .await
    .expect("Create user must succeed");

    // Wrong password.
    let result = login(
        State(state.clone()),
        test_addr(),
        test_headers(),
        Json(LoginRequest {
            username: username.clone(),
            password: "wrong-password".to_string(),
            public_key: "k".to_string(),
        }),
    )
    .await;
    assert_eq!(result.unwrap_err(), StatusCode::UNAUTHORIZED);

    // Unknown user.
    let result = login(
        State(state.clone()),
        test_addr(),
        test_headers(),
        Json(LoginRequest {
            username: format!("ghost_{}", Uuid::new_v4().simple()),
            password: "whatever".to_string(),
            public_key: "k".to_string(),
        }),
    )
    .await;
    assert_eq!(result.unwrap_err(), StatusCode::UNAUTHORIZED);

    cleanup(&state, &[created.id]).await;
}

#[tokio::test]
async fn auth_extractor_enforces_bearer_session() {
    let Some(state) = test_state().await else {
        skip_notice("auth_extractor_enforces_bearer_session");
        return;
    };

    // No header at all.
    let mut parts = parts_with_auth(None);
    assert_eq!(
        AuthUser::from_request_parts(&mut parts, &state)
            .await
            .unwrap_err(),
        StatusCode::UNAUTHORIZED
    );

    // Unknown token.
    let mut parts = parts_with_auth(Some("no-such-token"));
    assert_eq!(
        AuthUser::from_request_parts(&mut parts, &state)
            .await
            .unwrap_err(),
        StatusCode::UNAUTHORIZED
    );

    let user = register_and_login(&state, "extractor", "device-key").await;

    // Valid token resolves to the right user.
    let mut parts = parts_with_auth(Some(&user.token));
    let auth = AuthUser::from_request_parts(&mut parts, &state)
        .await
        .expect("valid token must authenticate");
    assert_eq!(auth.user_id, user.id);
    assert_eq!(auth.token, user.token);
    assert_eq!(auth.session_id, user.session_id);

    // Expired sessions are rejected even with a correct token format.
    let expired_token = format!("expired_{}", Uuid::new_v4().simple());
    sqlx::query(
        "INSERT INTO sessions (id, user_id, token, expires_at)
         VALUES ($1, $2, $3, now() - interval '1 hour')",
    )
    .bind(Uuid::now_v7())
    .bind(user.id)
    .bind(&expired_token)
    .execute(&state.db)
    .await
    .expect("expired session fixture must insert");

    let mut parts = parts_with_auth(Some(&expired_token));
    assert_eq!(
        AuthUser::from_request_parts(&mut parts, &state)
            .await
            .unwrap_err(),
        StatusCode::UNAUTHORIZED
    );

    cleanup(&state, &[user.id]).await;
}

#[tokio::test]
async fn chat_and_message_flow() {
    let Some(state) = test_state().await else {
        skip_notice("chat_and_message_flow");
        return;
    };

    let alice = register_and_login(&state, "alice", "key-a").await;
    let bob = register_and_login(&state, "bob", "key-b").await;
    let outsider = register_and_login(&state, "mallory", "key-m").await;

    // Alice creates a direct chat with Bob.
    let Json(chat) = create_chat(
        State(state.clone()),
        auth_of(&alice),
        Json(CreateChat {
            member_ids: vec![bob.id],
            is_group: false,
            name: None,
        }),
    )
    .await
    .expect("chat creation must succeed");

    // Both members see it; the outsider does not.
    let Json(alice_chats) = list_my_chats(State(state.clone()), auth_of(&alice))
        .await
        .unwrap();
    let Json(bob_chats) = list_my_chats(State(state.clone()), auth_of(&bob))
        .await
        .unwrap();
    let Json(outsider_chats) = list_my_chats(State(state.clone()), auth_of(&outsider))
        .await
        .unwrap();
    assert!(alice_chats.iter().any(|c| c.id == chat.id));
    assert!(bob_chats.iter().any(|c| c.id == chat.id));
    assert!(outsider_chats.iter().all(|c| c.id != chat.id));

    // Exchange two messages and check ordering + authorship.
    for text in ["hello bob", "hi alice"] {
        let sender = if text.starts_with("hello") {
            &alice
        } else {
            &bob
        };
        let Json(sent) = send_message(
            State(state.clone()),
            auth_of(sender),
            Path(chat.id),
            Json(SendMessage {
                text: text.to_string(),
            }),
        )
        .await
        .expect("member must be able to send");
        assert_eq!(sent.text, text);
    }

    let Json(messages) = list_messages(State(state.clone()), auth_of(&alice), Path(chat.id))
        .await
        .unwrap();
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0].text, "hello bob");
    assert_eq!(messages[0].sender_id, alice.id);
    assert_eq!(messages[1].text, "hi alice");
    assert_eq!(messages[1].sender_id, bob.id);

    // Outsider can neither read nor write.
    assert_eq!(
        list_messages(State(state.clone()), auth_of(&outsider), Path(chat.id))
            .await
            .unwrap_err(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        send_message(
            State(state.clone()),
            auth_of(&outsider),
            Path(chat.id),
            Json(SendMessage {
                text: "sneaky".to_string(),
            }),
        )
        .await
        .unwrap_err(),
        StatusCode::FORBIDDEN
    );

    cleanup(&state, &[alice.id, bob.id, outsider.id]).await;
}

#[tokio::test]
async fn create_chat_auto_adds_creator_and_skips_self_duplicates() {
    let Some(state) = test_state().await else {
        skip_notice("create_chat_auto_adds_creator_and_skips_self_duplicates");
        return;
    };

    let alice = register_and_login(&state, "selfchat", "key").await;

    // Even when the creator lists themselves twice, they end up with one membership.
    let Json(chat) = create_chat(
        State(state.clone()),
        auth_of(&alice),
        Json(CreateChat {
            member_ids: vec![alice.id, alice.id],
            is_group: false,
            name: None,
        }),
    )
    .await
    .unwrap();

    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM chat_members WHERE chat_id = $1")
        .bind(chat.id)
        .fetch_one(&state.db)
        .await
        .unwrap();
    assert_eq!(count.0, 1);

    cleanup(&state, &[alice.id]).await;
}

#[tokio::test]
async fn send_message_broadcasts_to_ws_members() {
    let Some(state) = test_state().await else {
        skip_notice("send_message_broadcasts_to_ws_members");
        return;
    };

    let alice = register_and_login(&state, "wsalice", "key-a").await;
    let bob = register_and_login(&state, "wsbob", "key-b").await;

    let Json(chat) = create_chat(
        State(state.clone()),
        auth_of(&alice),
        Json(CreateChat {
            member_ids: vec![bob.id],
            is_group: false,
            name: None,
        }),
    )
    .await
    .unwrap();

    // Simulate Bob's live WebSocket connection.
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    state.connections.write().await.insert(bob.id, tx);

    let Json(sent) = send_message(
        State(state.clone()),
        auth_of(&alice),
        Path(chat.id),
        Json(SendMessage {
            text: "hello via ws".to_string(),
        }),
    )
    .await
    .unwrap();
    assert_eq!(sent.text, "hello via ws");

    let received = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("ws push must arrive promptly")
        .expect("channel must stay open");
    let payload: serde_json::Value = serde_json::from_str(&received).unwrap();
    assert_eq!(payload["text"], "hello via ws");
    assert_eq!(payload["chat_id"], chat.id.to_string());
    assert_eq!(payload["sender_id"], alice.id.to_string());

    state.connections.write().await.remove(&bob.id);
    cleanup(&state, &[alice.id, bob.id]).await;
}

#[tokio::test]
async fn sessions_list_and_signed_delete() {
    let Some(state) = test_state().await else {
        skip_notice("sessions_list_and_signed_delete");
        return;
    };

    let signing = signing_key(11);
    let pem = public_key_pem(&signing);
    let username = format!("sess_{}", Uuid::new_v4().simple());

    // Register, then open two real sessions sharing one device key.
    let Json(created) = create_user(
        State(state.clone()),
        Json(CreateUser {
            username: username.clone(),
            password: "password-123".to_string(),
        }),
    )
    .await
    .expect("Create user must succeed");
    let first = login_with_key(&state, created.id, &username, "password-123", &pem).await;
    let second = login_with_key(&state, created.id, &username, "password-123", &pem).await;

    let Json(sessions) = list_sessions(State(state.clone()), auth_of(&first))
        .await
        .unwrap();
    assert!(
        sessions.len() >= 2,
        "expected at least two sessions, got {}",
        sessions.len()
    );

    // An invented nonce that the server never issued is rejected,
    // even with a correctly-formed signature over it.
    let invented = format!("invented_{}", Uuid::new_v4().simple());
    let invented_err = delete_session(
        State(state.clone()),
        auth_of(&first),
        Path(second.session_id),
        Json(DeleteSessionRequest {
            nonce: invented.clone(),
            signature: sign_delete_session(&signing, &second.session_id, &invented),
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(invented_err, StatusCode::UNAUTHORIZED);

    // A nonce issued to one session cannot be spent from another session.
    // (Both sessions are still alive here so the nonce insert succeeds.)
    let Json(foreign_nonce) = get_nonce(State(state.clone()), auth_of(&second))
        .await
        .unwrap();
    let cross_session_err = delete_session(
        State(state.clone()),
        auth_of(&first),
        Path(first.session_id),
        Json(DeleteSessionRequest {
            nonce: foreign_nonce.nonce.clone(),
            signature: sign_delete_session(&signing, &first.session_id, &foreign_nonce.nonce),
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(cross_session_err, StatusCode::UNAUTHORIZED);

    // Signed delete of the second session succeeds (nonce issued to the
    // caller's own session, signature bound to the target session).
    let Json(nonce) = get_nonce(State(state.clone()), auth_of(&first))
        .await
        .unwrap();
    let status = delete_session(
        State(state.clone()),
        auth_of(&first),
        Path(second.session_id),
        Json(DeleteSessionRequest {
            nonce: nonce.nonce.clone(),
            signature: sign_delete_session(&signing, &second.session_id, &nonce.nonce),
        }),
    )
    .await
    .unwrap();
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Replaying the same nonce is rejected (single-use).
    let replay = delete_session(
        State(state.clone()),
        auth_of(&first),
        Path(second.session_id),
        Json(DeleteSessionRequest {
            nonce: nonce.nonce.clone(),
            signature: sign_delete_session(&signing, &second.session_id, &nonce.nonce),
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(replay, StatusCode::UNAUTHORIZED);

    // A signature from a different key is rejected.
    let Json(fresh) = get_nonce(State(state.clone()), auth_of(&first))
        .await
        .unwrap();
    let forged = sign_delete_session(&signing_key(77), &first.session_id, &fresh.nonce);
    let forged_err = delete_session(
        State(state.clone()),
        auth_of(&first),
        Path(first.session_id),
        Json(DeleteSessionRequest {
            nonce: fresh.nonce,
            signature: forged,
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(forged_err, StatusCode::UNAUTHORIZED);

    // Deleting a missing session reports NOT_FOUND (with a fresh valid signature).
    let Json(last) = get_nonce(State(state.clone()), auth_of(&first))
        .await
        .unwrap();
    let missing_id = Uuid::now_v7();
    let missing_err = delete_session(
        State(state.clone()),
        auth_of(&first),
        Path(missing_id),
        Json(DeleteSessionRequest {
            nonce: last.nonce.clone(),
            signature: sign_delete_session(&signing, &missing_id, &last.nonce),
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(missing_err, StatusCode::NOT_FOUND);

    cleanup(&state, &[created.id]).await;
}

#[tokio::test]
async fn get_nonce_issues_server_bound_single_use_nonce() {
    let Some(state) = test_state().await else {
        skip_notice("get_nonce_issues_server_bound_single_use_nonce");
        return;
    };

    let user = register_and_login(&state, "nonceuser", "device-key").await;

    let Json(issued) = get_nonce(State(state.clone()), auth_of(&user))
        .await
        .unwrap();
    assert_eq!(issued.nonce.len(), 32);
    assert!(issued.nonce.chars().all(|c| c.is_ascii_alphanumeric()));

    // The nonce is persisted and bound to the caller's session.
    let owner: (Uuid,) = sqlx::query_as("SELECT session_id FROM nonces WHERE nonce = $1")
        .bind(&issued.nonce)
        .fetch_one(&state.db)
        .await
        .expect("issued nonce must be stored");
    assert_eq!(owner.0, user.session_id);

    cleanup(&state, &[user.id]).await;
}

#[tokio::test]
async fn users_cannot_delete_foreign_sessions() {
    let Some(state) = test_state().await else {
        skip_notice("users_cannot_delete_foreign_sessions");
        return;
    };

    let victim_signing = signing_key(21);
    let victim = register_and_login(&state, "victim", &public_key_pem(&victim_signing)).await;
    let attacker_signing = signing_key(22);
    let attacker = register_and_login(&state, "attacker", &public_key_pem(&attacker_signing)).await;

    let victim_session_id: (Uuid,) = sqlx::query_as("SELECT id FROM sessions WHERE token = $1")
        .bind(&victim.token)
        .fetch_one(&state.db)
        .await
        .unwrap();

    let Json(nonce) = get_nonce(State(state.clone()), auth_of(&attacker))
        .await
        .unwrap();
    let err = delete_session(
        State(state.clone()),
        auth_of(&attacker),
        Path(victim_session_id.0),
        Json(DeleteSessionRequest {
            nonce: nonce.nonce.clone(),
            signature: sign_delete_session(&attacker_signing, &victim_session_id.0, &nonce.nonce),
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(err, StatusCode::NOT_FOUND);

    cleanup(&state, &[victim.id, attacker.id]).await;
}
