use axum::{
    extract::{Path, Query},
    http::{HeaderMap, StatusCode, Uri, header::{HOST, LOCATION}},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::response::ErasedJson;
use garde::Validate;
use serde::Deserialize;

use crate::{data::ErrorDetail, valid::Garde};

pub async fn redirect(Path(n): Path<i32>) -> Response {
    match n {
        ..=0 => (StatusCode::BAD_REQUEST, bad_redirect_request()).into_response(),
        1 => (StatusCode::FOUND, Redirect::to("/get")).into_response(),
        2.. => (StatusCode::FOUND, Redirect::to(&format!("/redirect/{}", n - 1))).into_response(),
    }
}

fn bad_redirect_request() -> ErasedJson {
    ErasedJson::pretty(ErrorDetail::new(400, "Bad Request", "redirect count must be > 0".to_string()))
}

pub async fn relative_redirect(Path(n): Path<i32>) -> Response {
    match n {
        ..=0 => (StatusCode::BAD_REQUEST, bad_redirect_request()).into_response(),
        1 => (StatusCode::FOUND, Redirect::to("/get")).into_response(),
        2.. => (StatusCode::FOUND, [(LOCATION, format!("./{}", n - 1))]).into_response(),
    }
}

pub async fn absolute_redirect(Path(n): Path<i32>, uri: Uri, headers: HeaderMap, _req: axum::extract::Request) -> Response {
    let host = headers.get(HOST).and_then(|v| v.to_str().ok()).unwrap_or("localhost");
    match n {
        ..=0 => (StatusCode::BAD_REQUEST, bad_redirect_request()).into_response(),
        1 => (StatusCode::FOUND, Redirect::to("/get")).into_response(),
        2.. => (
            StatusCode::FOUND,
            Redirect::to(&format!(
                "{}://{host}/absolute-redirect/{}",
                uri.scheme_str().unwrap_or("http"),
                n - 1
            )),
        )
            .into_response(),
    }
}

#[derive(Debug, Deserialize, Validate)]
pub struct Params {
    #[garde(length(min = 0))]
    url: String,
    #[garde(range(min = 100, max = 999))]
    status_code: Option<u16>,
}

pub async fn redirect_to(Garde(Query(p)): Garde<Query<Params>>) -> Response {
    let Params { url, status_code } = p;
    let status_code = status_code.unwrap_or(302);
    (
        StatusCode::from_u16(status_code)
            .ok()
            .filter(StatusCode::is_redirection)
            .unwrap_or(StatusCode::FOUND),
        Redirect::to(&url),
    )
        .into_response()
}
