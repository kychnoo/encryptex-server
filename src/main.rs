mod auth;
mod error;
mod json;
mod models;
mod routes;
mod state;

#[cfg(test)]
mod integration_tests;

use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use axum::{
    Router,
    routing::{delete, get, post},
};
use sqlx::{PgPool, postgres::PgPoolOptions};
use tokio::sync::RwLock;
use tower_governor::{GovernorLayer, governor::GovernorConfigBuilder};

use crate::{
    routes::{
        auth::{change_password, delete_session, get_nonce, list_sessions, login, refresh},
        chats::{create_chat, list_my_chats},
        messages::{list_messages, send_message},
        users::{create_user, list_users, me},
        ws::ws_handler,
    },
    state::AppState,
};

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL not setted");
    let server_port = std::env::var("SERVER_PORT").expect("SERVER_PORT not setted");

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Error on connecting to DB");
    let cleanup_pool = pool.clone();

    let state = AppState {
        db: pool,
        connections: Arc::new(RwLock::new(HashMap::new())),
    };

    let governor_conf = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(6)
            .burst_size(5)
            .finish()
            .unwrap(),
    );
    let limiter = GovernorLayer::new(governor_conf);

    let app = Router::new()
        .route(
            "/users",
            post(create_user).layer(limiter.clone()).get(list_users),
        )
        .route("/login", post(login).layer(limiter.clone()))
        .route("/refresh", post(refresh))
        .route("/password", post(change_password))
        .route("/me", get(me))
        .route("/chats", post(create_chat).get(list_my_chats))
        .route(
            "/chats/{chat_id}/messages",
            post(send_message).get(list_messages),
        )
        .route("/ws", get(ws_handler))
        .route("/sessions", get(list_sessions))
        .route("/sessions/{id}", delete(delete_session))
        .route("/nonce", get(get_nonce))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{server_port}"))
        .await
        .unwrap();

    spawn_cleanup(cleanup_pool);

    println!("Server listen on http://localhost:{server_port}");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}

fn spawn_cleanup(db: PgPool) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(300));
        loop {
            tick.tick().await;
            for q in [
                "DELETE FROM nonces WHERE expires_at < now()",
                "DELETE FROM sessions WHERE expires_at < now()",
                "DELETE FROM login_failures WHERE created_at < now() - interval '15 minutes'",
            ] {
                if let Err(e) = sqlx::query(q).execute(&db).await {
                    eprintln!("Cleanup: {e:?}");
                }
            }
        }
    });
}
