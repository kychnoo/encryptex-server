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
use sqlx::postgres::PgPoolOptions;
use tokio::sync::RwLock;
use tower_governor::{GovernorLayer, governor::GovernorConfigBuilder};

use crate::{
    routes::{
        auth::{delete_session, get_nonce, list_sessions, login},
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

    println!("Server listen on http://localhost:{server_port}");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}
