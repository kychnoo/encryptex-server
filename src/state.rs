use std::{collections::HashMap, sync::Arc};

use sqlx::PgPool;
use tokio::sync::{RwLock, mpsc};
use uuid::Uuid;

pub type WsSender = mpsc::UnboundedSender<String>;

pub type Connections = Arc<RwLock<HashMap<Uuid, HashMap<Uuid, WsSender>>>>;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub connections: Connections,
}
