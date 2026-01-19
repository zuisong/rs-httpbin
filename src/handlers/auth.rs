use axum::{
    extract::Path,
    http::{
        HeaderMap,
        StatusCode,
        header::{AUTHORIZATION, CONTENT_TYPE, WWW_AUTHENTICATE, HeaderValue},
    },
    response::{IntoResponse, Response},
    Json,
    http::Method,
};
use axum_extra::{
    TypedHeader,
    headers::{Authorization, authorization::Basic},
    response::ErasedJson,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;

use crate::data::ErrorDetail;

// Basic Auth
#[derive(Serialize, Deserialize)]
struct BasicAuth {
    pub authorized: bool,
    pub user: String,
}

#[derive(Deserialize)]
pub struct BasicAuthParam {
    user: String,
    passwd: String,
}

pub async fn basic_auth(
    Path(BasicAuthParam { user, passwd }): Path<BasicAuthParam>,
    basic_auth: Option<TypedHeader<Authorization<Basic>>>,
) -> impl IntoResponse {
    let authorized = match &basic_auth {
        None => false,
        Some(auth) => auth.username() == user && auth.password() == passwd,
    };
    let body = ErasedJson::pretty(BasicAuth {
        authorized,
        user: basic_auth.map(|it| it.username().to_string()).unwrap_or_default(),
    });
    if authorized {
        (StatusCode::OK, body).into_response()
    } else {
        (
            StatusCode::UNAUTHORIZED,
            [(WWW_AUTHENTICATE, HeaderValue::from_static(r#"Basic realm="Fake Realm""#))],
            body,
        )
            .into_response()
    }
}

pub async fn hidden_basic_auth(
    Path(BasicAuthParam { user, passwd }): Path<BasicAuthParam>,
    basic_auth: Option<TypedHeader<Authorization<Basic>>>,
) -> impl IntoResponse {
    let authorized = match basic_auth {
        None => false,
        Some(auth) => auth.username() == user && auth.password() == passwd,
    };

    if authorized {
        (
            StatusCode::OK,
            ErasedJson::pretty(BasicAuth {
                authorized,
                user: if authorized { user } else { Default::default() },
            }),
        )
            .into_response()
    } else {
        (StatusCode::NOT_FOUND, ErasedJson::pretty(ErrorDetail::new(404, "Not Found", ""))).into_response()
    }
}

// Digest Auth
pub async fn digest_auth_handler(
    Path((qop, user, passwd, algorithm)): Path<(String, String, String, String)>,
    headers: HeaderMap,
    method: Method,
) -> Response {
    // 生成一个固定的 realm 和 nonce
    let realm = "rs-httpbin";
    let nonce = "deadbeef";
    let opaque = "cafebabe";
    let auth_header = headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok());
    if let Some(auth) = auth_header
        && let Some(resp) = parse_and_verify_digest(auth, &user, &passwd, realm, &qop, &algorithm, nonce, opaque, method.as_str())
        && resp
    {
        return (
            StatusCode::OK,
            [(CONTENT_TYPE, "application/json")],
            Json(json!({
                "authenticated": true,
                "user": user,
                "qop": qop,
                "algorithm": algorithm
            })),
        )
            .into_response();
    }
    let value = format!(r#"Digest realm="{realm}",qop="{qop}",nonce="{nonce}",opaque="{opaque}",algorithm="{algorithm}""#);
    (
        StatusCode::UNAUTHORIZED,
        [(WWW_AUTHENTICATE, value)],
        Json(json!({"authenticated": false, "user": user})),
    )
        .into_response()
}

// 简单的 Digest 验证，仅做演示用途
#[allow(clippy::too_many_arguments)]
fn parse_and_verify_digest(
    header: &str,
    user: &str,
    passwd: &str,
    realm: &str,
    qop: &str,
    algorithm: &str,
    nonce: &str,
    _opaque: &str,
    method: &str,
) -> Option<bool> {
    if !algorithm.eq_ignore_ascii_case("MD5") {
        return Some(false);
    }
    let header = header.strip_prefix("Digest ")?;
    let mut map = BTreeMap::new();
    for part in header.split(',') {
        let part = part.trim();
        if let Some((k, v)) = part.split_once('=') {
            let key = k.trim();
            let val = v.trim().trim_matches('"');
            map.insert(key, val);
        }
    }

    let u = map.get("username")?;
    if *u != user {
        return Some(false);
    }
    let r = map.get("realm")?;
    if *r != realm {
        return Some(false);
    }
    let n = map.get("nonce")?;
    if *n != nonce {
        return Some(false);
    }
    let uri = map.get("uri")?;
    let response = map.get("response")?;

    // HA1 = MD5(username:realm:password)
    let ha1 = format!("{:x}", md5::compute(format!(r#"{}:{}:{}"#,
        user,
        realm,
        passwd,
    )));
    // HA2 = MD5(method:digestURI)
    let ha2 = format!("{:x}", md5::compute(format!(r#"{}:{}"#,
        method,
        uri,
    )));

    // Response = MD5(HA1:nonce:nc:cnonce:qop:HA2)
    let nc = map.get("nc").copied().unwrap_or("");
    let cnonce = map.get("cnonce").copied().unwrap_or("");

    // If qop is present (auth), verify it matches
    // The server param 'qop' is what we expect.
    let computed = if qop.eq_ignore_ascii_case("auth") {
        format!("{:x}", md5::compute(format!(r#"{}:{}:{}:{}:{}:{}"#,
            ha1,
            nonce,
            nc,
            cnonce,
            qop,
            ha2,
        )))
    } else {
        // legacy RFC 2069 (no qop)
        // Response = MD5(HA1:nonce:HA2)
        format!("{:x}", md5::compute(format!(r#"{}:{}:{}"#,
            ha1,
            nonce,
            ha2,
        )))
    };

    Some(computed == *response)
}

pub async fn digest_auth_no_algo_handler(
    Path((qop, user, passwd)): Path<(String, String, String)>,
    headers: HeaderMap,
    method: Method,
) -> impl IntoResponse {
    let realm = "rs-httpbin";
    let nonce = "deadbeef";
    let opaque = "cafebabe";
    let algorithm = "MD5"; // 默认算法
    let auth_header = headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok());
    if let Some(auth) = auth_header
        && let Some(resp) = parse_and_verify_digest(auth, &user, &passwd, realm, &qop, algorithm, nonce, opaque, method.as_str())
        && resp
    {
        return (
            StatusCode::OK,
            [(CONTENT_TYPE, "application/json")],
            Json(json!({
                "authenticated": true,
                "user": user,
                "qop": qop,
                "algorithm": algorithm
            })),
        )
            .into_response();
    }
    let value = format!("Digest realm=\"{realm}\",qop=\"{qop}\",nonce=\"{nonce}\",opaque=\"{opaque}\",algorithm=\"{algorithm}\"");
    (
        StatusCode::UNAUTHORIZED,
        [(WWW_AUTHENTICATE, &value)],
        Json(json!({"authenticated": false, "user": user})),
    )
        .into_response()
}
