use std::{future::IntoFuture as _, net::Ipv4Addr};

use anyhow::{Ok, Result};
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use base64::prelude::BASE64_STANDARD;
use futures_util::SinkExt as _;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use serde_json::json;
use tokio::net::TcpListener;
use tokio_stream::StreamExt as _;
use tower::ServiceExt as _;

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
async fn index() -> Result<()> {
    let response = app().oneshot(Request::builder().uri("/").body(Body::empty())?).await?;

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().body_as_string().await;
    assert!(body.contains("rs-httpbin"));
    Ok(())
}

#[test_case::test_case("jpeg")]
#[test_case::test_case("png")]
#[test_case::test_case("svg")]
#[test_case::test_case("webp")]
#[test_case::test_case("jxl")]
#[test_case::test_case("avif")]
#[tokio::test]
async fn image_type(type_: &'static str) -> Result<()> {
    let response = app()
        .oneshot(Request::builder().uri(format!("/image/{type_}")).body(Body::empty())?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.headers().get(CONTENT_TYPE);
    assert_eq!(body, (HeaderValue::try_from(format!("image/{type_}")).ok()).as_ref());
    Ok(())
}

#[tokio::test]
async fn image() -> Result<()> {
    let image_types = vec!["jpeg", "png", "svg", "webp", "jxl", "avif"];

    for &image_type in &image_types {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/image")
                    .header("Accept", format!("image/{image_type}"))
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::OK);

        let content_type = response.headers().get(CONTENT_TYPE).unwrap();
        assert_eq!(content_type.to_str()?, format!("image/{image_type}"));
    }
    Ok(())
}

#[tokio::test]
async fn image_types() -> Result<()> {
    let image_types = vec!["jpeg", "png", "svg", "webp", "jxl", "avif"];

    for &image_type in &image_types {
        let response = app()
            .oneshot(Request::builder().uri(format!("/image/{image_type}")).body(Body::empty())?)
            .await?;

        assert_eq!(response.status(), StatusCode::OK);

        let content_type = response.headers().get(CONTENT_TYPE).unwrap();
        assert_eq!(content_type.to_str()?, format!("image/{image_type}"));
    }
    Ok(())
}

#[test_case::test_case("./assets/sample.json", "/json")]
#[test_case::test_case("./assets/sample.xml", "/xml")]
#[test_case::test_case("./assets/sample.html", "/html")]
#[test_case::test_case("./assets/forms_post.html", "/forms/post")]
#[tokio::test]
pub async fn data(body_file: &str, path: &str) -> Result<()> {
    let response = app()
        .oneshot(Request::builder().method(Method::GET).uri(path).body(Body::empty())?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.body_as_string().await;
    assert_eq!(body, std::fs::read_to_string(body_file)?);
    Ok(())
}

#[tokio::test]
async fn not_found() -> Result<()> {
    let response = app()
        .oneshot(Request::builder().uri("/does-not-exist").body(Body::empty())?)
        .await?;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = response.body_as_string().await;
    assert!(body.is_empty());
    Ok(())
}

#[tokio::test]
async fn the_real_deal() -> Result<()> {
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))).await?;
    let addr = listener.local_addr()?;

    tokio::spawn(async move {
        start_server(listener).await;
    });

    let client = Client::builder(TokioExecutor::new()).build_http();

    let response = client
        .request(Request::builder().uri(format!("http://{addr}/ip")).body(Body::empty())?)
        .await?;

    let body = response.body_as_json().await;
    assert_eq!(
        body,
        json! {
            {"origin": "127.0.0.1"}
        }
    );
    Ok(())
}

#[tokio::test]
async fn basic_auth() -> Result<()> {
    let response = app()
        .oneshot(Request::builder().uri("/basic-auth/a/b").body(Body::empty())?)
        .await?;

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
                .body(Body::empty())?,
        )
        .await?;

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
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.body_as_json().await,
        json!({
            "authorized": true,
            "user": "a"
        })
    );
    Ok(())
}

#[tokio::test]
async fn hidden_basic_auth() -> Result<()> {
    let response = app()
        .oneshot(Request::builder().uri("/hidden-basic-auth/a/b").body(Body::empty())?)
        .await?;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response.body_as_json().await,
        json!({
            "error": "Not Found",
            "status_code": 404,
        })
    );

    let response = app()
        .oneshot(
            Request::builder()
                .uri("/hidden-basic-auth/a/b")
                .header("Authorization", format!("Basic {}", BASE64_STANDARD.encode("a1:a").as_str()))
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response.body_as_json().await,
        json!({
         "error": "Not Found",
            "status_code": 404,
        })
    );

    let response = app()
        .oneshot(
            Request::builder()
                .uri("/hidden-basic-auth/a/b")
                .header("Authorization", format!("Basic {}", BASE64_STANDARD.encode("a:b").as_str()))
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.body_as_json().await,
        json!({
            "authorized": true,
            "user": "a"
        })
    );
    Ok(())
}

#[tokio::test]
async fn anything() -> Result<()> {
    let response = app()
        .oneshot(
            Request::builder()
                .uri("/anything?a=1&a=2&b=3")
                .method("POST")
                .header("X-Real-Ip", "1.2.3.4")
                .header("content-type", ContentType::form_url_encoded().to_string())
                .body(http_body_util::Full::from("a=1&b=1&b=2&b=1"))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.body_as_json().await;
    println!("{:#?}", &body);
    assert_eq!(body["origin"], json!("1.2.3.4"));
    assert_eq!(body["form"], json!(  {"a":"1", "b":["1","2","1"]}   ));
    assert_eq!(
        body,
        json!(
        {
          "args": {
            "a": [
              "1",
              "2"
            ],
            "b": "3"
          },
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
          "uri": "/anything?a=1&a=2&b=3"
        }
            )
    );
    Ok(())
}

#[tokio::test]
async fn test_anything_multipart() -> Result<()> {
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
                .body(http_body_util::Full::from(body))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.body_as_json().await;
    println!("{:#?}", &body);
    assert_eq!(body["origin"], json!("1.2.3.4"));
    assert_eq!(body["form"], json!({"a": "1", "c": "3"}));
    assert_eq!(body["files"]["b"], json!("file1 content"));
    Ok(())
}

#[tokio::test]
async fn test_zstd() -> Result<()> {
    let response = app()
        .oneshot(
            Request::builder()
                .uri("/zstd")
                .method("GET")
                .header("X-Real-Ip", "1.2.3.4")
                .header("Content-Type", "application/json")
                .body(http_body_util::Full::default())?,
        )
        .await?;
    // assert_eq!(response.status(), StatusCode::OK);
    println!("{}", response.body_as_string().await);
    Ok(())
}

#[tokio::test]
async fn user_agent() -> Result<()> {
    let response = app()
        .oneshot(
            Request::builder()
                .uri("/user-agent")
                .header("User-Agent", "TestAgent/1.0")
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.body_as_json().await;
    assert_eq!(
        body,
        json!({
            "user-agent": "TestAgent/1.0"
        })
    );
    Ok(())
}

#[tokio::test]
async fn headers() -> Result<()> {
    let response = app()
        .oneshot(
            Request::builder()
                .uri("/headers")
                .header("X-Custom-Header", "CustomValue")
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.body_as_json().await;
    assert_eq!(body["headers"]["x-custom-header"], json!("CustomValue"));
    Ok(())
}

#[tokio::test]
async fn cookies() -> Result<()> {
    let response = app()
        .oneshot(
            Request::builder()
                .uri("/cookies")
                .header("Cookie", "key1=value1; key2=value2")
                .body(Body::empty())?,
        )
        .await?;

    dbg!(&response);
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.body_as_json().await;
    assert_eq!(
        body,
        json!({
            "key1": "value1",
            "key2": "value2"
        })
    );
    Ok(())
}

#[tokio::test]
async fn cookies_set() -> Result<()> {
    let response = app()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/cookies/set?key1=value1&key2=value2")
                .body(Body::empty())?,
        )
        .await?;
    dbg!(&response);
    // assert_eq!(response.status(), StatusCode::FOUND);

    let cookies = response.headers().get_all("set-cookie").iter().collect::<Vec<_>>();
    assert!(cookies.iter().any(|cookie| cookie.to_str().unwrap().contains("key1=value1")));
    assert!(cookies.iter().any(|cookie| cookie.to_str().unwrap().contains("key2=value2")));
    Ok(())
}

#[tokio::test]
async fn cookies_del() -> Result<()> {
    let response = app()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/cookies/delete?key1=value1&key2=value2")
                .body(Body::empty())?,
        )
        .await?;
    dbg!(&response);
    // assert_eq!(response.status(), StatusCode::FOUND);

    let cookies = response.headers().get_all("set-cookie").iter().collect::<Vec<_>>();
    assert!(
        cookies
            .iter()
            .any(|cookie| cookie.to_str().unwrap().contains("key1=; HttpOnly; Max-Age=0"))
    );
    assert!(
        cookies
            .iter()
            .any(|cookie| cookie.to_str().unwrap().contains("key2=; HttpOnly; Max-Age=0"))
    );
    Ok(())
}

#[tokio::test]
async fn hostname() -> Result<()> {
    let response = app().oneshot(Request::builder().uri("/hostname").body(Body::empty())?).await?;

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.body_as_json().await;
    assert!(body["hostname"].is_string());
    Ok(())
}

#[tokio::test]
async fn uuid() -> Result<()> {
    let response = app().oneshot(Request::builder().uri("/uuid").body(Body::empty())?).await?;

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.body_as_json().await;
    assert!(body["uuid"].is_string());
    Ok(())
}

#[tokio::test]
async fn unstable() -> Result<()> {
    let response = app()
        .oneshot(Request::builder().uri("/unstable?failure_rate=0.0").body(Body::empty())?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);

    let response = app()
        .oneshot(Request::builder().uri("/unstable?failure_rate=1.0").body(Body::empty())?)
        .await?;

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let response = app()
        .oneshot(Request::builder().uri("/unstable?failure_rate=2").body(Body::empty())?)
        .await?;

    dbg!(&response);

    // assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(response.body_as_string().await.contains("not in range [0, 1]"));
    Ok(())
}

#[tokio::test]
async fn bearer() -> Result<()> {
    let response = app()
        .oneshot(
            Request::builder()
                .uri("/bearer")
                .header("Authorization", "Bearer test_token")
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.body_as_json().await;
    assert_eq!(body["authorized"], json!(true));
    assert_eq!(body["token"], json!("test_token"));
    Ok(())
}

#[tokio::test]
async fn redirect() -> Result<()> {
    let response = app().oneshot(Request::builder().uri("/redirect/1").body(Body::empty())?).await?;

    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(response.headers().get("location").unwrap(), "/get");
    Ok(())
}

#[tokio::test]
async fn redirect_to() -> Result<()> {
    let response = app()
        .oneshot(Request::builder().uri("/redirect-to?url=/get").body(Body::empty())?)
        .await?;

    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(response.headers().get("location").unwrap(), "/get");
    Ok(())
}

#[tokio::test]
async fn absolute_redirect() -> Result<()> {
    let response = app()
        .oneshot(
            Request::builder()
                .uri("/absolute-redirect/2")
                .method("GET")
                .header("host", "httpbin.org")
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::FOUND);
    assert!(response.headers().get("location").unwrap().to_str()?.starts_with("http"));
    Ok(())
}

#[tokio::test]
async fn base64_decode() -> Result<()> {
    let response = app()
        .oneshot(Request::builder().uri("/base64/SGVsbG8gd29ybGQ=").body(Body::empty())?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.body_as_string().await;
    assert_eq!(body, "Hello world");
    Ok(())
}

#[tokio::test]
async fn base64_encode() -> Result<()> {
    let response = app()
        .oneshot(Request::builder().uri("/base64/encode/HelloWorld").body(Body::empty())?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.body_as_string().await;
    assert_eq!(body, "SGVsbG9Xb3JsZA==");
    Ok(())
}

#[tokio::test]
async fn base64() -> Result<()> {
    let response = app()
        .oneshot(Request::builder().uri("/base64/SGVsbG8gd29ybGQ=").body(Body::empty())?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.body_as_string().await;
    assert_eq!(body, "Hello world");
    Ok(())
}

#[tokio::test]
async fn response_headers() -> Result<()> {
    let response = app()
        .oneshot(
            Request::builder()
                .uri("/response-headers?key1=value1&key2=value2&key1=value3")
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);

    let headers = response.headers();
    assert_eq!(headers.get_all("key1").iter().collect::<Vec<_>>(), vec!["value1", "value3"]);
    assert_eq!(headers.get("key2").unwrap(), "value2");
    Ok(())
}

#[tokio::test]
async fn links() -> Result<()> {
    let response = app().oneshot(Request::builder().uri("/links/11/11").body(Body::empty())?).await?;

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.body_as_string().await;
    for i in 0..=10 {
        assert!(body.contains(&format!("/links/11/{i}")));
    }
    Ok(())
}

#[tokio::test]
async fn sse() -> Result<()> {
    let response = app()
        .oneshot(Request::builder().uri("/sse?count=1&duration=1ms").body(Body::empty())?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.body_as_string().await;
    assert!(body.contains("data:"));
    Ok(())
}

#[tokio::test]
async fn robots_txt() -> Result<()> {
    let response = app().oneshot(Request::builder().uri("/robots.txt").body(Body::empty())?).await?;

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.body_as_string().await;
    assert!(body.contains("User-agent: *"));
    assert!(body.contains("Disallow: /deny"));
    Ok(())
}

#[tokio::test]
async fn encoding_utf8() -> Result<()> {
    let response = app().oneshot(Request::builder().uri("/encoding/utf8").body(Body::empty())?).await?;

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.body_as_string().await;
    assert!(body.contains("UTF-8"));
    Ok(())
}

#[tokio::test]
async fn relative_redirect() -> Result<()> {
    let response = app()
        .oneshot(Request::builder().uri("/relative-redirect/1").body(Body::empty())?)
        .await?;

    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(response.headers().get("location").unwrap(), ("/get"));
    Ok(())
}

#[tokio::test]
async fn websocket_echo() -> Result<()> {
    use tokio_tungstenite::tungstenite::protocol::Message;
    let listener = TcpListener::bind(SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0))).await?;
    let addr = listener.local_addr()?;
    tokio::spawn(axum::serve(listener, app().into_make_service_with_connect_info::<SocketAddr>()).into_future());

    let url = format!("ws://{addr}/websocket/echo");
    let (mut socket, _response) = tokio_tungstenite::connect_async(url).await.expect("Failed to connect");

    let msg = "Hello, WebSocket!";
    socket.send(Message::Text(msg.into())).await?;

    let response = socket.next().await.unwrap()?;
    assert_eq!(response.into_text()?, format!("echo --> {}", msg));
    socket.send(Message::Close(None)).await?;
    tokio::time::sleep(Duration::from_secs_f32(0.01)).await;
    Ok(())
}
