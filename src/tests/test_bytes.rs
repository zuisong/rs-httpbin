use axum::{
    body::Body,
    http::{Request, StatusCode, header::CONTENT_TYPE},
};
use tower::ServiceExt;

use super::*;
use crate::tests::ext::BodyExt; // for `oneshot`

#[tokio::test]
async fn test_bytes_n_basic() {
    let app = app();
    let n = 16;
    let response = app
        .oneshot(Request::builder().uri(format!("/bytes/{n}")).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let headers = response.headers();
    assert_eq!(headers.get(CONTENT_TYPE).unwrap(), "application/octet-stream");
    let body = response.body().await;
    assert_eq!(body.len(), n as usize);
}

#[tokio::test]
async fn test_bytes_n_with_seed() {
    let app = app();
    let n = 8;
    let seed = 42;
    let response1 = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/bytes/{n}?seed={seed}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let response2 = app
        .oneshot(
            Request::builder()
                .uri(format!("/bytes/{n}?seed={seed}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body1 = (response1.body()).await;
    let body2 = (response2.body()).await;
    assert_eq!(body1, body2, "Same seed should produce same bytes");
}
