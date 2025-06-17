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
    // 构造一个简单的 Authorization 头
    let auth = "Digest username=\"testuser\", realm=\"rs-httpbin\", nonce=\"deadbeef\", uri=\"/digest-auth/auth/testuser/testpass/MD5\", response=\"dummy\"";
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
    let auth = "Digest username=\"testuser\", realm=\"rs-httpbin\", nonce=\"deadbeef\", uri=\"/digest-auth/auth/testuser/testpass\", response=\"dummy\"";
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
