use std::str::FromStr;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use hyper_util::client::legacy::Client;
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tower::ServiceExt;

#[cfg(test)]
use super::*;
use crate::tests::ext::BodyExt as _;

pub mod ext {
    use std::{future::Future, pin::Pin};

    use http_body_util::BodyExt as _;
    use serde_json::Value;

    pub trait BodyExt {
        fn body(self) -> Pin<Box<dyn Future<Output = Vec<u8>> + Send>>;
        fn body_as_string(self) -> Pin<Box<dyn Future<Output = String> + Send>>;
        fn body_as_json(self) -> Pin<Box<dyn Future<Output = Value> + Send>>;
    }

    impl<T> BodyExt for T
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

        fn body_as_json(self) -> Pin<Box<dyn Future<Output = Value> + Send>> {
            let fut = async { serde_json::from_slice(&self.body().await).unwrap() };
            Box::pin(fut)
        }
    }
}
#[tokio::test]
async fn index() {
    let app = app();

    let response = app
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().body_as_string().await;
    assert!(body.contains("rs-httpbin"));
}

mod image_test {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    use yare::parameterized;

    use super::*;

    #[parameterized(
        jpeg = { "jpeg" },
        png = { "png" },
        svg = { "svg" },
        webp = { "webp" },
    )]
    #[test_macro(tokio::test)]
    async fn image_type(type_: &str) {
        let app = app();

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/image/{type_}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.headers().get(CONTENT_TYPE);
        assert_eq!(body, (HeaderValue::try_from(format!("image/{type_}")).ok()).as_ref());
    }
}

#[tokio::test()]
async fn json() {
    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/json")
                .header(CONTENT_TYPE, APPLICATION_JSON.as_ref())
                .body(Body::from(serde_json::to_vec(&json!([1, 2, 3, 4])).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.body_as_json().await;
    assert_eq!(body, Value::from_str(include_str!("../assets/sample.json")).unwrap());
}

#[tokio::test]
async fn not_found() {
    let app = app();

    let response = app
        .oneshot(Request::builder().uri("/does-not-exist").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = response.body_as_string().await;
    assert!(body.is_empty());
}

#[tokio::test]
async fn the_real_deal() {
    let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app().into_make_service_with_connect_info::<SocketAddr>())
            .await
            .unwrap();
    });

    let client = Client::builder(hyper_util::rt::TokioExecutor::new()).build_http();

    let response = client
        .request(
            Request::builder()
                .uri(format!("http://{addr}/ip"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = response.body_as_json().await;
    assert_eq!(
        body,
        serde_json::json! {
            {"origin": "127.0.0.1"}
        }
    );
}
