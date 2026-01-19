use axum::{
    body::Body,
    http::{
        Request, StatusCode,
        header::{AUTHORIZATION, CONTENT_TYPE, WWW_AUTHENTICATE},
    },
};
use tower::ServiceExt;

use super::*;
use crate::tests::ext::BodyExt; // for `oneshot`

#[tokio::test]
async fn test_digest_auth_unauthorized() {
    let app = app();
    let uri = "/digest-auth/auth/testuser/testpass/MD5";
    let req = Request::builder().uri(uri).body(Body::empty()).unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let www = resp.headers().get(WWW_AUTHENTICATE).unwrap().to_str().unwrap();
    assert!(www.contains("Digest realm=\"rs-httpbin\""));
}

#[tokio::test]
async fn test_digest_auth_success() {
    let app = app();
    let uri = "/digest-auth/auth/testuser/testpass/MD5";

    let user = "testuser";
    let realm = "rs-httpbin";
    let passwd = "testpass";
    let nonce = "deadbeef";
    let method = "GET";
    let qop = "auth";
    let nc = "00000001";
    let cnonce = "123456";

    // HA1 = MD5(username:realm:password)
    let ha1 = format!("{:x}", md5::compute(format!("{}:{}:{}", user, realm, passwd)));
    // HA2 = MD5(method:digestURI)
    let ha2 = format!("{:x}", md5::compute(format!("{}:{}", method, uri)));
    // Response = MD5(HA1:nonce:nc:cnonce:qop:HA2)
    let response_hash = format!("{:x}", md5::compute(format!("{}:{}:{}:{}:{}:{}", ha1, nonce, nc, cnonce, qop, ha2)));

    // 构造一个简单的 Authorization 头
    let auth = format!(
        "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", qop={}, nc={}, cnonce=\"{}\", response=\"{}\", opaque=\"cafebabe\"",
        user, realm, nonce, uri, qop, nc, cnonce, response_hash
    );

    let req = Request::builder().uri(uri).header(AUTHORIZATION, auth).body(Body::empty()).unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp.headers().get(CONTENT_TYPE).unwrap().to_str().unwrap();
    assert!(ct.contains("application/json"));
    let body = (resp.body()).await;
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("\"authenticated\":true"));
    assert!(text.contains("testuser"));
}

#[tokio::test]
async fn test_digest_auth_no_algo_unauthorized() {
    let app = app();
    let uri = "/digest-auth/auth/testuser/testpass";
    let req = Request::builder().uri(uri).body(Body::empty()).unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let www = resp.headers().get(WWW_AUTHENTICATE).unwrap().to_str().unwrap();
    assert!(www.contains("Digest realm=\"rs-httpbin\""));
}

#[tokio::test]
async fn test_digest_auth_no_algo_success() {
    let app = app();
    let uri = "/digest-auth/auth/testuser/testpass";

    let user = "testuser";
    let realm = "rs-httpbin";
    let passwd = "testpass";
    let nonce = "deadbeef";
    let method = "GET";
    let qop = "auth";
    let nc = "00000001";
    let cnonce = "123456";

    // HA1 = MD5(username:realm:password)
    let ha1 = format!("{:x}", md5::compute(format!("{}:{}:{}", user, realm, passwd)));
    // HA2 = MD5(method:digestURI)
    let ha2 = format!("{:x}", md5::compute(format!("{}:{}", method, uri)));
    // Response = MD5(HA1:nonce:nc:cnonce:qop:HA2)
    let response_hash = format!("{:x}", md5::compute(format!("{}:{}:{}:{}:{}:{}", ha1, nonce, nc, cnonce, qop, ha2)));

    let auth = format!(
        "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", qop={}, nc={}, cnonce=\"{}\", response=\"{}\", opaque=\"cafebabe\"",
        user, realm, nonce, uri, qop, nc, cnonce, response_hash
    );

    let req = Request::builder().uri(uri).header(AUTHORIZATION, auth).body(Body::empty()).unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp.headers().get(CONTENT_TYPE).unwrap().to_str().unwrap();
    assert!(ct.contains("application/json"));
    let body = (resp.body()).await;
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("\"authenticated\":true"));
    assert!(text.contains("testuser"));
}
