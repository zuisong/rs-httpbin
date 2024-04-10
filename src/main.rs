#[deny(unused_imports)]
use std::{collections::BTreeMap, net::SocketAddr};

use axum::{
    body::Bytes,
    http::{header::CONTENT_TYPE, status, HeaderMap, HeaderValue, Method, Uri},
    response::{Html, IntoResponse, Response},
    routing::{any, delete, get, head, options, patch, post, put, trace},
    Router,
};
use axum_client_ip::InsecureClientIp;
use axum_extra::{
    extract::Query,
    headers::{ContentType, UserAgent},
    response::ErasedJson,
    TypedHeader,
};
use base64::Engine;
use comrak::Options;
use data::{Http, Ip};
use mime::{APPLICATION_JSON, IMAGE, TEXT_HTML, TEXT_XML};
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};

mod data;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    let app = Router::new()
        .route("/", get(index))
        //
        .route("/delete", delete(anything))
        .route("/get", get(anything))
        .route("/head", head(anything))
        .route("/options", options(anything))
        .route("/patch", patch(anything))
        .route("/post", post(anything))
        .route("/put", put(anything))
        .route("/trace", trace(anything))
        //
        .route("/anything", any(anything))
        .route("/anything/*{id}", any(anything))
        //
        .route("/user-agent", any(user_agent))
        .route("/headers", any(headers))
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

async fn user_agent(user_agent: Option<TypedHeader<UserAgent>>) -> impl IntoResponse {
    ErasedJson::pretty(data::UserAgent {
        user_agent: user_agent
            .map(|h| h.0.to_string())
            .unwrap_or("".to_string()),
    })
}
async fn headers(header_map: HeaderMap) -> impl IntoResponse {
    ErasedJson::pretty(data::Headers {
        headers: get_headers(&header_map),
    })
}

fn get_headers(header_map: &HeaderMap) -> BTreeMap<String, Vec<String>> {
    let mut headers = BTreeMap::new();
    for key in header_map.keys() {
        let header_values: Vec<_> = header_map
            .get_all(key)
            .iter()
            .map(|v| {
                v.to_str()
                    .map(|v| v.to_string())
                    .unwrap_or_else(|err| err.to_string())
            })
            .collect();

        headers.insert(key.to_string(), header_values);
    }
    headers
}

async fn anything(
    method: Method,
    uri: Uri,
    Query(query): Query<BTreeMap<String, Vec<String>>>,
    header_map: HeaderMap,
    content_type: Option<TypedHeader<ContentType>>,
    InsecureClientIp(origin): InsecureClientIp,
    body: Bytes,
) -> Response {
    let headers = get_headers(&header_map);

    let body_string = match String::from_utf8(body.to_vec()) {
        Ok(body) => body,
        Err(_) => base64::engine::general_purpose::STANDARD.encode(&body),
    };

    let json = content_type.and_then(|TypedHeader(content_type)| {
        if content_type == ContentType::json() {
            serde_json::from_slice(&body).ok()
        } else {
            None
        }
    });

    ErasedJson::pretty(Http {
        method: method.to_string(),
        uri: uri.to_string(),
        headers,
        origin: origin.to_string(),
        args: query,
        data: body_string,
        json,
    })
    .into_response()
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
        .map(mime::MimeIter::new);

    let unsupported_media_type = status::StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();

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

    unsupported_media_type
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

async fn ip(InsecureClientIp(origin): InsecureClientIp) -> Response {
    ErasedJson::pretty(Ip {
        origin: origin.to_string(),
    })
    .into_response()
}
