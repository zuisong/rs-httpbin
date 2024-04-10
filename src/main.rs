use std::net::SocketAddr;

use axum::extract::ConnectInfo;
use axum::http::header::CONTENT_TYPE;
use axum::http::{status, HeaderMap, HeaderValue};
use axum::response::{Html, IntoResponse, Response};
use axum::Json;
use axum::{routing::get, Router};
use comrak::Options;
use mime::{APPLICATION_JSON, IMAGE, TEXT_HTML, TEXT_XML};
use serde_json::json;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    let app = Router::new()
        .route("/", get(index))
        .route("/json", get(json))
        .route("/xml", get(xml))
        .route("/ip", get(ip))
        .route("/html", get(html))
        .route("/image", get(image))
        .route("/image/jpeg", get(jpeg))
        .route("/image/svg", get(svg))
        .route("/image/png", get(png))
        .route("/image/webp", get(webp))
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::new().allow_origin(Any).allow_methods(Any));
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}

async fn index() -> Html<String> {
    let md = include_str!("../README.md");
    let mut options = Options::default();
    options.extension.tasklist = true;
    Html(
        comrak::markdown_to_html(md, &options)
            + (r#"
<style>
  @media (prefers-color-scheme: dark) {
    html, img, video, iframe {
      filter: invert(1);
    }
    body {
      background-color: white;
    }
  }
</style>
    "#),
    )
}

async fn json() -> impl IntoResponse {
    (
        HeaderMap::from_iter([(
            CONTENT_TYPE,
            HeaderValue::from_static(APPLICATION_JSON.essence_str()),
        )]),
        include_str!("../assets/sample.json"),
    )
}

async fn xml() -> impl IntoResponse {
    (
        HeaderMap::from_iter([(
            CONTENT_TYPE,
            HeaderValue::from_static(TEXT_XML.essence_str()),
        )]),
        include_str!("../assets/sample.xml"),
    )
}

async fn html() -> impl IntoResponse {
    (
        HeaderMap::from_iter([(
            CONTENT_TYPE,
            HeaderValue::from_static(TEXT_HTML.essence_str()),
        )]),
        include_str!("../assets/sample.html"),
    )
}

async fn image(headers: HeaderMap) -> impl IntoResponse {
    let mime = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|v| mime::MimeIter::new(v));

    let unsupported_media_type = (
        status::StatusCode::UNSUPPORTED_MEDIA_TYPE,
        Json(json!(
        {
          "status_code": 415,
          "error": "Unsupported Media Type"
        })),
    )
        .into_response();

    if mime.is_none() {
        return unsupported_media_type;
    }

    let mime = mime.unwrap();

    for m in mime.filter_map(|m| m.ok()).filter(|it| it.type_() == IMAGE) {
        match m.subtype().as_str() {
            "jpeg" => return jpeg().await,
            "svg" => return svg().await,
            "png" => return png().await,
            "webp" => return webp().await,
            _ => continue,
        }
    }

    return unsupported_media_type;
}

async fn jpeg() -> Response {
    (
        HeaderMap::from_iter([(CONTENT_TYPE, HeaderValue::from_static("image/jpeg"))]),
        include_bytes!("../assets/jpeg.jpeg"),
    )
        .into_response()
}
async fn svg() -> Response {
    (
        HeaderMap::from_iter([(CONTENT_TYPE, HeaderValue::from_static("image/svg"))]),
        include_bytes!("../assets/svg.svg"),
    )
        .into_response()
}
async fn png() -> Response {
    (
        HeaderMap::from_iter([(CONTENT_TYPE, HeaderValue::from_static("image/png"))]),
        include_bytes!("../assets/png.png"),
    )
        .into_response()
}
async fn webp() -> Response {
    (
        HeaderMap::from_iter([(CONTENT_TYPE, HeaderValue::from_static("image/webp"))]),
        include_bytes!("../assets/webp.webp"),
    )
        .into_response()
}

async fn ip(ConnectInfo(addr): ConnectInfo<SocketAddr>) -> Response {
    let ip = addr.ip();
    Json(json!(
        {
            "origin": ip.to_string(),
        }
    ))
    .into_response()
}
