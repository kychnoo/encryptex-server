use std::{collections::HashMap, sync::Arc};

use sqlx::PgPool;
use tokio::sync::{RwLock, mpsc};
use uuid::Uuid;

pub type WsSender = mpsc::UnboundedSender<String>;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub connections: Arc<RwLock<HashMap<Uuid, WsSender>>>,
}
