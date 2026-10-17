use axum::{http::StatusCode, response::IntoResponse};
use serde::Serialize;

#[derive(Debug, Serialize, PartialEq)]
pub struct ErrorResult {
    pub status: String,
    pub message: String,
}

impl IntoResponse for ErrorResult {
    fn into_response(self) -> axum::response::Response {
        axum::Json(self).into_response()
    }
}

pub type ApiError = (StatusCode, ErrorResult);

pub fn api_error(status: StatusCode, code: &str, msg: &str) -> ApiError {
    (
        status,
        ErrorResult {
            status: code.into(),
            message: msg.into(),
        },
    )
}

pub fn internal_error(e: impl std::fmt::Debug) -> ApiError {
    eprintln!("internal error: {e:?}");
    api_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal_error",
        "Internal server error",
    )
}
