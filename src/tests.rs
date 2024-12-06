use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use base64::prelude::BASE64_STANDARD;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use serde_json::json;
use tokio::net::TcpListener;
use tower::ServiceExt;

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
        T: axum::body::HttpBody + Send + 'static,
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
    let response = app()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().body_as_string().await;
    assert!(body.contains("rs-httpbin"));
}

#[test_case::test_case("jpeg")]
#[test_case::test_case("png")]
#[test_case::test_case("svg")]
#[test_case::test_case("webp")]
#[test_case::test_case("jxl")]
#[test_case::test_case("avif")]
#[tokio::test]
async fn image_type(type_: &'static str) {
    let response = app()
        .oneshot(Request::builder().uri(format!("/image/{type_}")).body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.headers().get(CONTENT_TYPE);
    assert_eq!(body, (HeaderValue::try_from(format!("image/{type_}")).ok()).as_ref());
}

#[test_case::test_case("./assets/sample.json", "/json")]
#[test_case::test_case("./assets/sample.xml", "/xml")]
#[test_case::test_case("./assets/sample.html", "/html")]
#[test_case::test_case("./assets/forms_post.html", "/forms/post")]
#[tokio::test]
pub async fn data(body_file: &str, path: &str) {
    let response = app()
        .oneshot(Request::builder().method(Method::GET).uri(path).body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.body_as_string().await;
    assert_eq!(body, std::fs::read_to_string(body_file).unwrap());
}

#[tokio::test]
async fn not_found() {
    let response = app()
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

    let client = Client::builder(TokioExecutor::new()).build_http();

    let response = client
        .request(Request::builder().uri(format!("http://{addr}/ip")).body(Body::empty()).unwrap())
        .await
        .unwrap();

    let body = response.body_as_json().await;
    assert_eq!(body, json! {
        {"origin": "127.0.0.1"}
    });
}

#[tokio::test]
async fn basic_auth() {
    let response = app()
        .oneshot(Request::builder().uri("/basic-auth/a/b").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.body_as_json().await,
        json!({
            "authorized": false,
            "user": ""
        })
    );

    let response = app()
        .oneshot(
            Request::builder()
                .uri("/basic-auth/a/b")
                .header("Authorization", format!("Basic {}", BASE64_STANDARD.encode("a1:a").as_str()))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.body_as_json().await,
        json!({
            "authorized": false,
            "user": "a1"
        })
    );

    let response = app()
        .oneshot(
            Request::builder()
                .uri("/basic-auth/a/b")
                .header("Authorization", format!("Basic {}", BASE64_STANDARD.encode("a:b").as_str()))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.body_as_json().await,
        json!({
            "authorized": true,
            "user": "a"
        })
    );
}

#[tokio::test]
async fn anything() {
    let response = app()
        .oneshot(
            Request::builder()
                .uri("/anything")
                .method("POST")
                .header("X-Real-Ip", "1.2.3.4")
                .header("content-type", ContentType::form_url_encoded().to_string())
                .body(http_body_util::Full::from("a=1&b=1&b=2&b=1"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.body_as_json().await;
    println!("{:#?}", &body);
    assert_eq!(body["origin"], json!("1.2.3.4"));
    assert_eq!(body["form"], json!(  {"a":"1", "b":["1","2","1"]}   ));
    assert_eq!(
        body,
        json!(
        {
          "args": {},
          "data": "a=1&b=1&b=2&b=1",
          "files": {},
          "form": {
            "a": "1",
            "b": [
              "1",
              "2",
              "1"
            ]
          },
          "headers": {
            "content-type": "application/x-www-form-urlencoded",
            "x-real-ip": "1.2.3.4"
          },
          "json": null,
          "method": "POST",
          "origin": "1.2.3.4",
          "uri": "/anything"
        }
            )
    )
}
#[tokio::test]
async fn test_anything_multipart() {
    let boundary = "AaB03x";
    let body = format! {r#"--{boundary}
Content-Disposition: form-data; name="a"

1
--{boundary}
Content-Disposition: form-data; name="b"; filename="file1.txt"
Content-Type: text/plain

file1 content
--{boundary}
Content-Disposition: form-data; name="c"

3
--{boundary}--"#}
    .replace("\n", "\r\n");
    let response = app()
        .oneshot(
            Request::builder()
                .uri("/anything")
                .method("POST")
                .header("X-Real-Ip", "1.2.3.4")
                .header("Content-Type", format!(r#"multipart/form-data; boundary={boundary}"#))
                .body(http_body_util::Full::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.body_as_json().await;
    println!("{:#?}", &body);
    assert_eq!(body["origin"], json!("1.2.3.4"));
    assert_eq!(body["form"], json!({"a": "1", "c": "3"}));
    assert_eq!(body["files"]["b"], json!("file1 content"));
}

#[tokio::test]
async fn test_zstd() {
    let response = app()
        .oneshot(
            Request::builder()
                .uri("/zstd")
                .method("GET")
                .header("X-Real-Ip", "1.2.3.4")
                .header("Content-Type", "application/json")
                .body(http_body_util::Full::default())
                .unwrap(),
        )
        .await
        .unwrap();
    // assert_eq!(response.status(), StatusCode::OK);
    println!("{}", response.body_as_string().await);
}
