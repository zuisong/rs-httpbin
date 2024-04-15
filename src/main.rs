use std::{
    collections::BTreeMap,
    net::SocketAddr,
    time::{Duration, UNIX_EPOCH},
};

use axum::{
    body::Bytes,
    extract::Path,
    http::{
        header::{ACCEPT_ENCODING, CONTENT_TYPE, LOCATION},
        status, HeaderMap, HeaderValue, Method, StatusCode, Uri,
    },
    response::{sse::Event, Html, IntoResponse, Response, Sse},
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
use base64::{engine::general_purpose::STANDARD, Engine};
use mime::{APPLICATION_JSON, IMAGE, TEXT_HTML, TEXT_PLAIN, TEXT_XML};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio_stream::StreamExt;
use tower_http::{
    compression::CompressionLayer,
    cors::{Any, CorsLayer},
    set_header::SetRequestHeaderLayer,
    trace::TraceLayer,
};
use tracing::Level;

mod data;
#[cfg(test)]
mod tests;

fn app() -> Router<()> {
    let mut router = Router::new()
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
        .route("/absolute-redirect/:n", any(redirect))
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
        .route("/base64/:value", any(base64_decode))
        .route("/base64/encode/:value", any(base64_encode))
        .route("/base64/decode/:value", any(base64_decode))
        .route("/forms/post", any(forms_post))
        .route("/sse", any(sse_handler))
        //keepme
        ;

    for format in ["gzip", "zstd", "br", "deflate"] {
        router = router.route(
            format!("/{format}").as_str(),
            get(anything).layer((
                SetRequestHeaderLayer::if_not_present(
                    ACCEPT_ENCODING,
                    HeaderValue::from_static(format),
                ),
                CompressionLayer::new(),
            )),
        );
    }

    router
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .try_init()
        .ok();

    let router: Router = app();
    let app = router.layer((
        TraceLayer::new_for_http()
            .make_span_with(tower_http::trace::DefaultMakeSpan::new().level(Level::INFO))
            .on_request(tower_http::trace::DefaultOnRequest::new().level(Level::INFO))
            .on_response(
                tower_http::trace::DefaultOnResponse::new()
                    .level(Level::INFO)
                    .include_headers(true),
            ),
        CorsLayer::new().allow_origin(Any).allow_methods(Any),
        // CompressionLayer::default(),
    ));
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("Listening on http://{}", listener.local_addr().unwrap());
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
        Err(_) => STANDARD.encode(&body),
    };

    let json = content_type.and_then(|TypedHeader(content_type)| {
        if content_type == ContentType::json() {
            serde_json::from_slice(&body).ok()
        } else {
            None
        }
    });

    ErasedJson::pretty(data::Http {
        method: method.to_string(),
        uri: uri.to_string(),
        headers,
        origin,
        args: query,
        data: body_string,
        json,
    })
    .into_response()
}

async fn index() -> Html<String> {
    let md = include_str!("../README.md");
    let mut options = comrak::Options::default();
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
        [(
            CONTENT_TYPE,
            HeaderValue::from_static(APPLICATION_JSON.essence_str()),
        )],
        include_str!("../assets/sample.json"),
    )
}

async fn xml() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static(TEXT_XML.essence_str()),
        )],
        include_str!("../assets/sample.xml"),
    )
}

async fn html() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static(TEXT_HTML.essence_str()),
        )],
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
        [(CONTENT_TYPE, HeaderValue::from_static("image/jpeg"))],
        include_bytes!("../assets/jpeg.jpeg"),
    )
        .into_response()
}

async fn svg() -> Response {
    (
        [(CONTENT_TYPE, HeaderValue::from_static("image/svg"))],
        include_bytes!("../assets/svg.svg"),
    )
        .into_response()
}

async fn png() -> Response {
    (
        [(CONTENT_TYPE, HeaderValue::from_static("image/png"))],
        include_bytes!("../assets/png.png"),
    )
        .into_response()
}

async fn webp() -> Response {
    (
        [(CONTENT_TYPE, HeaderValue::from_static("image/webp"))],
        include_bytes!("../assets/webp.webp"),
    )
        .into_response()
}

async fn ip(InsecureClientIp(origin): InsecureClientIp) -> impl IntoResponse {
    ErasedJson::pretty(data::Ip { origin }).into_response()
}

async fn redirect(Path(n): Path<usize>) -> Response {
    if n <= 0 {
        return (
            StatusCode::BAD_REQUEST,
            ErasedJson::pretty(json!({
                "status_code": 400,
                "error": "Bad Request",
                "detail": "redirect count must be > 0"
            })),
        )
            .into_response();
    }
    if n == 1 {
        return (StatusCode::FOUND, [(LOCATION, "/get")]).into_response();
    }
    return (
        StatusCode::FOUND,
        [(LOCATION, format!("/absolute-redirect/{}", n - 1))],
    )
        .into_response();
}

async fn base64_decode(Path(base64_data): Path<String>) -> impl IntoResponse {
    (
        [(CONTENT_TYPE, HeaderValue::from_static(TEXT_PLAIN.as_ref()))],
        STANDARD
            .decode(base64_data)
            .unwrap_or_else(|e| e.to_string().into_bytes()),
    )
}

async fn base64_encode(Path(data): Path<String>) -> impl IntoResponse {
    (
        [(CONTENT_TYPE, HeaderValue::from_static(TEXT_PLAIN.as_ref()))],
        STANDARD.encode(data),
    )
}

async fn forms_post() -> impl IntoResponse {
    Html(include_str!("../assets/forms_post.html"))
}

#[derive(Deserialize, Serialize, Default)]
struct SeeParam {
    pub count: Option<usize>,
    #[serde(with = "humantime_serde")]
    pub duration: Option<Duration>,
    #[serde(with = "humantime_serde")]
    pub delay: Option<Duration>,
}

async fn sse_handler(
    Query(SeeParam {
        delay,
        duration,
        count,
    }): Query<SeeParam>,
) -> Response {
    tokio::time::sleep(delay.unwrap_or(Duration::ZERO)).await;

    let stream = tokio_stream::iter(1..)
        .take(count.unwrap_or(10_usize))
        .map(|id| {
            let timestamp = UNIX_EPOCH.elapsed().unwrap_or_default().as_millis();
            Event::default()
                .data(serde_json::to_string(&data::SseData { id, timestamp }).unwrap_or_default())
                .event("ping")
                .try_into()
        })
        .throttle(duration.unwrap_or(Duration::from_secs(1)));

    Sse::new(stream).into_response()
}
