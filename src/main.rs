use std::{
    collections::BTreeMap,
    net::SocketAddr,
    time::{Duration, UNIX_EPOCH},
};

use ::base64::{engine::general_purpose::STANDARD, Engine};
use axum::{
    body::Bytes,
    extract::{Host, Path, Request},
    http::{
        header::{ACCEPT, ACCEPT_ENCODING, CONTENT_TYPE, LOCATION},
        HeaderMap, HeaderValue, Method, StatusCode, Uri,
    },
    response::{sse::Event, Html, IntoResponse, Redirect, Response, Sse},
    routing::{any, delete, get, head, options, patch, post, put, trace},
    Router,
};
use axum_client_ip::InsecureClientIp;
use axum_extra::{
    extract::{cookie, CookieJar, Query},
    headers::{ContentType, UserAgent},
    response::ErasedJson,
    TypedHeader,
};
use mime::{APPLICATION_JSON, IMAGE, TEXT_HTML_UTF_8, TEXT_PLAIN, TEXT_XML};
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
        .route("/absolute-redirect/:n", any(redirect::absolute_redirect))
        .route("/redirect/:n", any(redirect::redirect))
        .route("/relative-redirect/:n", any(redirect::relative_redirect))
        //
        .route("/user-agent", any(user_agent))
        .route("/headers", any(headers))
        .route("/json", get(resp_data::json))
        .route("/xml", get(resp_data::xml))
        .route("/html", get(resp_data::html))
        .route("/hostname", get(hostname))
        .route("/ip", get(ip))
        .route("/image", get(image::image))
        .route("/image/jpeg", get(image::jpeg))
        .route("/image/svg", get(image::svg))
        .route("/image/png", get(image::png))
        .route("/image/webp", get(image::webp))
        .route("/base64/:value", any(base64::base64_decode))
        .route("/base64/encode/:value", any(base64::base64_encode))
        .route("/base64/decode/:value", any(base64::base64_decode))
        .route("/forms/post", any(resp_data::forms_post))
        .route("/sse", any(sse_handler))
        .route("/cookies", any(cookies::cookies))
        .route("/cookies/set", any(cookies::cookies_set))
        .route("/cookies/delete", any(cookies::cookies_del))
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
        .with_max_level(Level::INFO)
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
mod cookies {
    use super::*;

    pub async fn cookies(jar: axum_extra::extract::cookie::CookieJar) -> impl IntoResponse {
        let m: BTreeMap<_, _> = jar.iter().map(|k| k.name_value()).collect();
        ErasedJson::pretty(m)
    }

    pub async fn cookies_set(Query(query): Query<BTreeMap<String, String>>) -> impl IntoResponse {
        let mut jar = CookieJar::new();
        for (k, v) in query.iter() {
            jar = jar.add(cookie::Cookie::new(k.clone(), v.clone()));
        }
        (StatusCode::FOUND, (jar, Redirect::to("/cookies"))).into_response()
    }

    pub async fn cookies_del(Query(query): Query<BTreeMap<String, String>>) -> impl IntoResponse {
        let mut jar = CookieJar::new();
        for (k, v) in query.iter() {
            jar = jar.add(
                cookie::Cookie::build((k.clone(), v.clone()))
                    .max_age(time::Duration::ZERO)
                    .expires(time::OffsetDateTime::now_utc())
                    .http_only(true)
                    .build(),
            );
        }
        (StatusCode::FOUND, (jar, Redirect::to("/cookies"))).into_response()
    }
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

#[derive(Deserialize, Serialize, Default)]
struct HostName {
    hostname: String,
}

async fn hostname() -> impl IntoResponse {
    let hostname = hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or("<< unknown hostname >>".to_string());

    ErasedJson::pretty(HostName { hostname })
}

mod resp_data {
    use super::*;

    pub(crate) async fn json() -> impl IntoResponse {
        (
            [(CONTENT_TYPE, (APPLICATION_JSON.essence_str()))],
            include_str!("../assets/sample.json"),
        )
    }

    pub(crate) async fn xml() -> impl IntoResponse {
        (
            [(CONTENT_TYPE, TEXT_XML.essence_str())],
            include_str!("../assets/sample.xml"),
        )
    }

    pub(crate) async fn html() -> impl IntoResponse {
        (
            [(CONTENT_TYPE, TEXT_HTML_UTF_8.essence_str())],
            include_str!("../assets/sample.html"),
        )
    }

    pub(crate) async fn forms_post() -> impl IntoResponse {
        (
            [(CONTENT_TYPE, TEXT_HTML_UTF_8.essence_str())],
            include_str!("../assets/forms_post.html"),
        )
    }
}

mod image {
    use super::*;

    pub(crate) async fn image(headers: HeaderMap) -> impl IntoResponse {
        let mime = headers
            .get(ACCEPT)
            .and_then(|v| v.to_str().ok())
            .map(mime::MimeIter::new);

        if let Some(mime) = mime {
            for m in mime.filter_map(|m| m.ok()).filter(|it| it.type_() == IMAGE) {
                match m.subtype().as_str() {
                    "jpeg" => return jpeg().await,
                    "svg" => return svg().await,
                    "png" => return png().await,
                    "webp" => return webp().await,
                    _ => continue,
                }
            }
        }

        StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response()
    }

    pub(crate) async fn jpeg() -> Response {
        (
            [(CONTENT_TYPE, ("image/jpeg"))],
            include_bytes!("../assets/jpeg.jpeg"),
        )
            .into_response()
    }

    pub(crate) async fn svg() -> Response {
        (
            [(CONTENT_TYPE, ("image/svg"))],
            include_bytes!("../assets/svg.svg"),
        )
            .into_response()
    }

    pub(crate) async fn png() -> Response {
        (
            [(CONTENT_TYPE, ("image/png"))],
            include_bytes!("../assets/png.png"),
        )
            .into_response()
    }

    pub(crate) async fn webp() -> Response {
        (
            [(CONTENT_TYPE, ("image/webp"))],
            include_bytes!("../assets/webp.webp"),
        )
            .into_response()
    }
}
async fn ip(InsecureClientIp(origin): InsecureClientIp) -> impl IntoResponse {
    ErasedJson::pretty(data::Ip { origin }).into_response()
}
mod redirect {
    use super::*;

    pub(crate) async fn redirect(Path(n): Path<i32>) -> Response {
        match n {
            ..=0 => (StatusCode::BAD_REQUEST, bad_redirect_request()).into_response(),
            1 => (StatusCode::FOUND, [(LOCATION, "/get")]).into_response(),
            2.. => (
                StatusCode::FOUND,
                [(LOCATION, format!("/redirect/{}", n - 1))],
            )
                .into_response(),
        }
    }

    fn bad_redirect_request() -> ErasedJson {
        ErasedJson::pretty(json!({
            "status_code": 400,
            "error": "Bad Request",
            "detail": "redirect count must be > 0"
        }))
    }
    pub(crate) async fn relative_redirect(Path(n): Path<i32>) -> Response {
        match n {
            ..=0 => (StatusCode::BAD_REQUEST, bad_redirect_request()).into_response(),
            1 => (StatusCode::FOUND, [(LOCATION, "/get")]).into_response(),
            2.. => (StatusCode::FOUND, [(LOCATION, format!("./{}", n - 1))]).into_response(),
        }
    }
    pub(crate) async fn absolute_redirect(
        Path(n): Path<i32>,
        uri: Uri,
        Host(host): Host,
        _req: Request,
    ) -> Response {
        match n {
            ..=0 => (StatusCode::BAD_REQUEST, bad_redirect_request()).into_response(),
            1 => (StatusCode::FOUND, [(LOCATION, "/get")]).into_response(),
            2.. => (
                StatusCode::FOUND,
                [(
                    LOCATION,
                    format!(
                        "{}://{}/absolute-redirect/{}",
                        uri.scheme_str().unwrap_or("http"),
                        host,
                        n - 1
                    ),
                )],
            )
                .into_response(),
        }
    }
}

mod base64 {
    use super::*;

    pub(crate) async fn base64_decode(Path(base64_data): Path<String>) -> impl IntoResponse {
        (
            [(CONTENT_TYPE, (TEXT_PLAIN.as_ref()))],
            STANDARD
                .decode(base64_data)
                .unwrap_or_else(|e| e.to_string().into_bytes()),
        )
    }

    pub(crate) async fn base64_encode(Path(data): Path<String>) -> impl IntoResponse {
        (
            [(CONTENT_TYPE, (TEXT_PLAIN.as_ref()))],
            STANDARD.encode(data),
        )
    }
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
            #[allow(clippy::useless_conversion)]
            Event::default()
                .data(serde_json::to_string(&data::SseData { id, timestamp }).unwrap_or_default())
                .event("ping")
                .try_into()
        })
        .throttle(duration.unwrap_or(Duration::from_secs(1)));

    Sse::new(stream).into_response()
}
