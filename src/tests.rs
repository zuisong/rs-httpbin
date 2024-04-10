use std::{collections::HashMap, future::Future, pin::Pin};

use axum::{
    body::Body,
    extract::connect_info::MockConnectInfo,
    http::{self, Request, StatusCode},
};
use axum_client_ip::SecureClientIpSource;
use http_body_util::BodyExt as _;
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tower::{MakeService, Service, ServiceExt};

#[cfg(test)]
use super::*;

pub trait _BodyExt {
    fn body(self) -> Pin<Box<dyn Future<Output = Vec<u8>> + Send>>;
    fn body_as_string(self) -> Pin<Box<dyn Future<Output = String> + Send>>;
}

impl<T> _BodyExt for T
where
    T: http_body::Body + Send + 'static,
    T::Data: Send,
    T::Error: std::fmt::Debug,
{
    fn body(self) -> Pin<Box<dyn Future<Output = Vec<u8>> + Send>> {
        let fut = async { self.collect().await.unwrap().to_bytes().to_vec() };
        Box::pin(fut)
    }

    fn body_as_string(self) -> Pin<Box<dyn Future<Output = String> + Send>> {
        let fut = async { String::from_utf8(self.body().await).unwrap() };
        Box::pin(fut)
    }
}

#[tokio::test]
async fn hello_world() {
    let app = app();

    let response = app
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().body_as_string().await;
    assert!(body.contains("rs-httpbin"));
}

#[tokio::test]
async fn json() {
    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/json")
                .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                .body(Body::from(
                    serde_json::to_vec(&json!([1, 2, 3, 4])).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        body,
        serde_json::from_str::<Value>(include_str!("../assets/sample.json")).unwrap()
    );
}

#[tokio::test]
async fn not_found() {
    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/does-not-exist")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = response.body_as_string().await;
    assert!(body.is_empty());
}

// #[tokio::test]
// async fn multiple_request() {
//     let mut app = app().into_service();
//     let request = Request::get("/get").body(Body::empty()).unwrap();
//     let response = ServiceExt::<Request<Body>>::ready(&mut app)
//         .await
//         .unwrap()
//         .call(request)
//         .await
//         .unwrap();
//
//     println!("{}", response.body_as_string().await)
//     // assert_eq!(response.status(), StatusCode::OK);
//
//     // let request = Request::get("/").body(Body::empty()).unwrap();
//     // let response = ServiceExt::<Request<Body>>::ready(&mut app)
//     //     .await
//     //     .unwrap()
//     //     .call(request)
//     //     .await
//     //     .unwrap();
//     // assert_eq!(response.status(), StatusCode::OK);
// }
//
// #[tokio::test]
// async fn with_into_make_service_with_connect_info() {
//     let mut app = app()
//         .layer(SecureClientIpSource::ConnectInfo.into_extension())
//         .into_service();
//
//     let request = Request::builder().uri("/ip").body(Body::empty()).unwrap();
//     let response = app.ready().await.unwrap().call(request).await.unwrap();
//     assert_eq!(response.status(), StatusCode::OK);
// }
