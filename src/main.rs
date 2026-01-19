use std::{
    collections::BTreeMap,
    net::{Ipv4Addr, SocketAddr},
    str::FromStr,
    time::{Duration, Instant},
};

use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::{DefaultBodyLimit, MatchedPath, Path, Request},
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri, header::*},
    middleware,
    response::{AppendHeaders, Html, IntoResponse, Redirect, Response, Sse, sse::Event},
    routing::*,
};
use axum_client_ip::InsecureClientIp;
use axum_extra::{
    TypedHeader,
    extract::{CookieJar, Query, cookie},
    headers::{
        Authorization, ContentType, HeaderMapExt, Range, UserAgent,
        authorization::Bearer,
    },
    response::ErasedJson,
};
use base64::{Engine, prelude::BASE64_STANDARD};
use futures_util::stream;
use garde::Validate;
use mime::{APPLICATION_JSON, IMAGE, TEXT_HTML_UTF_8, TEXT_PLAIN, TEXT_PLAIN_UTF_8, TEXT_XML};
use serde::{Deserialize, Serialize};
use tokio::time::sleep;
use tower::ServiceBuilder;
use tower_http::{
    ServiceBuilderExt, compression::CompressionLayer, cors::CorsLayer, request_id::MakeRequestUuid, set_header::SetRequestHeaderLayer,
    trace::TraceLayer,
};
use tracing::{debug_span, info};
use tracing_subscriber::{EnvFilter, fmt::layer, layer::SubscriberExt, util::SubscriberInitExt};
use uuid::Uuid;

use crate::{
    data::{ErrorDetail, Headers, Http, Queries},
    valid::Garde,
};
use serde_json::json;

mod data;
mod handlers;
use handlers::auth;
use handlers::redirect;

mod valid;
mod ws_chat;
mod ws_echo;

#[cfg(test)]
mod tests;

fn app() -> Router<()> {
    let mut router = Router::new()
        .route("/", get(index))
        .merge(
            Router::new()
                .route("/delete", delete(anything))
                .route("/get", get(anything))
                .route("/head", head(anything))
                .route("/options", options(anything))
                .route("/patch", patch(anything))
                .route("/post", post(anything))
                .route("/put", put(anything))
                .route("/trace", trace(anything)),
        )
        .merge(
            Router::new()
                .route("/anything", any(anything))
                .route("/anything/{*path}", any(anything)),
        )
        .merge(
            Router::new()
                .route("/absolute-redirect/{n}", any(redirect::absolute_redirect))
                .route("/redirect/{n}", any(redirect::redirect))
                .route("/relative-redirect/{n}", any(redirect::relative_redirect))
                .route("/redirect-to", any(redirect::redirect_to)),
        )
        .merge(
            Router::new()
                .route("/basic-auth/{user}/{passwd}", any(auth::basic_auth))
                .route("/hidden-basic-auth/{user}/{passwd}", any(auth::hidden_basic_auth)),
        )
        .merge(
            Router::new()
                .route("/user-agent", any(user_agent))
                .route("/headers", any(headers))
                .route("/json", get(resp_data::json))
                .route("/xml", get(resp_data::xml))
                .route("/forms/post", any(resp_data::forms_post))
                .route("/html", get(resp_data::html))
                .route("/hostname", get(hostname))
                .route("/uuid", any(uuid))
                .route("/response-headers", any(response_headers))
                .route("/ip", any(ip))
                .route("/bearer", any(bearer)),
        )
        .merge(
            Router::new()
                .route("/image", any(image::image))
                .route("/image/jpeg", any(image::jpeg))
                .route("/image/svg", any(image::svg))
                .route("/image/png", any(image::png))
                .route("/image/webp", any(image::webp))
                .route("/image/avif", any(image::avif))
                .route("/image/jxl", any(image::jxl)),
        )
        //
        .merge(
            Router::new()
                .route("/base64/{value}", any(base_64::base64_decode))
                .route("/base64/encode/{value}", any(base_64::base64_encode))
                .route("/base64/decode/{value}", any(base_64::base64_decode)),
        )
        .route("/sse", any(sse::sse_handler))
        .merge(
            Router::new()
                .route("/cookies", any(cookies::cookies))
                .route("/cookies/set", any(cookies::cookies_set))
                .route("/cookies/delete", any(cookies::cookies_del)),
        )
        .route("/encoding/utf8", any(utf8))
        .route("/robots.txt", any(robots_txt))
        .merge(
            Router::new()
                .route("/links/{total}", any(links::links))
                .route("/links/{total}/{page}", any(links::links)),
        )
        .route("/unstable", get(unstable))
        .route(
            "/delay/{n}",
            any(anything).layer({
                async fn delay(Path(delays): Path<u16>, request: Request, next: middleware::Next) -> impl IntoResponse {
                    let before = Instant::now();
                    tokio::time::sleep(Duration::from_secs(delays.min(10).into())).await;
                    let resp = next.run(request).await;
                    let after = Instant::now();
                    (
                        AppendHeaders([("Server-Timing", format!("delay;dur={}", (after - before).as_millis()))]),
                        resp,
                    )
                }
                middleware::from_fn(delay)
            }),
        )
        .route("/websocket/echo", any(ws_echo::ws_echo_handler))
        .merge(
            Router::new()
                .route("/websocket/chat", any(ws_chat::ws_handler))
                .with_state(ws_chat::AppState::new()),
        )
        .route(
            "/socket-io/chat",
            any(|| async { Html(include_str!("../assets/socketio-chat.html")) }),
        )
        .route("/cache", any(cache))
        .route("/cache/{n}", any(cache_n))
        .route("/deny", any(deny))
        .merge(
            Router::new()
                .route("/openapi.json", get(|| async { include_str!("../openapi.json") }))
                .route("/swagger-ui", get(|| async { Html(swagger_ui::swagger_ui_html("/openapi.json")) })),
        )
        // 新增 /status/:code 路由
        .route("/status/{code}", any(status_code_handler))
        .route("/bytes/{n}", get(bytes_n))
        .route("/dump/request", any(dump_request))
        .route("/digest-auth/{qop}/{user}/{passwd}/{algorithm}", any(auth::digest_auth_handler))
        .route("/digest-auth/{qop}/{user}/{passwd}", any(auth::digest_auth_no_algo_handler))
        .route("/drip", get(drip_handler))
        .route("/etag/{etag}", any(etag_handler))
        .route("/range/{n}", get(range_handler))
        .route("/stream/{n}", get(stream_handler))
        .route("/stream-bytes/{n}", get(stream_bytes_handler));

    for format in ["gzip", "zstd", "br", "deflate"] {
        router = router.route(
            format!("/{format}").as_str(),
            get(anything).layer(
                ServiceBuilder::default()
                    .layer(SetRequestHeaderLayer::overriding(ACCEPT_ENCODING, HeaderValue::from_static(format)))
                    .layer(CompressionLayer::new()),
            ),
        );
    }

    // router.merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", api))

    let service = ServiceBuilder::default()
        .compression()
        .set_x_request_id(MakeRequestUuid)
        .propagate_x_request_id()
        .layer(TraceLayer::new_for_http().make_span_with(|request: &Request<Body>| {
            let request_id = request.headers()["x-request-id"].to_str().ok();
            let matched_path = request.extensions().get::<MatchedPath>().map(MatchedPath::as_str);
            let method = request.method().as_str();
            debug_span!("request_id", method, matched_path, request_id,)
        }))
        .layer(CorsLayer::very_permissive())
        .layer({
            async fn delay(request: Request, next: middleware::Next) -> impl IntoResponse {
                let before = Instant::now();
                let resp = next.run(request).await;
                let after = Instant::now();
                (
                    AppendHeaders([("Server-Timing", format!("total;dur={}", (after - before).as_millis()))]),
                    resp,
                )
            }
            middleware::from_fn(delay)
        })
        .layer(DefaultBodyLimit::max(1024 * 1024 * 100));

    router.layer(service)
}

mod axum_client_ip;
mod swagger_ui;

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "DEBUG".into()))
        .with(layer().json())
        .init();
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::UNSPECIFIED, 3000)).await.unwrap();
    start_server(listener).await;
}

pub(crate) async fn start_server(listener: tokio::net::TcpListener) {
    let app = app();
    eprintln!("Listening on http://{}", listener.local_addr().unwrap());
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .unwrap();
}

async fn user_agent(user_agent: Option<TypedHeader<UserAgent>>) -> impl IntoResponse {
    ErasedJson::pretty(data::UserAgent {
        user_agent: user_agent.map(|TypedHeader(h)| h.to_string()).unwrap_or_default(),
    })
}

async fn headers(header_map: HeaderMap) -> impl IntoResponse {
    ErasedJson::pretty(get_headers(&header_map))
}

#[derive(Debug, Validate, Deserialize)]
struct UnstableQueryParam {
    #[garde(range(min = 0.0, max = 2.0))]
    pub failure_rate: Option<f32>,
}

async fn unstable(Garde(Query(query)): Garde<Query<UnstableQueryParam>>) -> Response {
    let failure_rate = match query.failure_rate {
        None => 0.5,
        Some(failure_rate @ 0.0..=1.0) => failure_rate,
        _ => {
            return ErasedJson::pretty(ErrorDetail::new(
                400,
                "Bad Request",
                format!(
                    "invalid failure rate: {} not in range [0, 1]",
                    query.failure_rate.map_or("None".to_string(), |it| f32::to_string(&it))
                ),
            ))
            .into_response();
        }
    };

    if fastrand::f32() <= failure_rate {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    ().into_response()
}



fn get_headers(header_map: &HeaderMap) -> Headers {
    let mut headers = Headers::default();

    for (k, v) in header_map {
        let v = String::from_utf8_lossy(v.as_bytes()).to_string();
        let values = headers.entry(k.as_str().to_string()).or_default();
        values.push(v);
    }

    headers
}

mod cookies {
    use super::*;

    pub async fn cookies(jar: CookieJar) -> impl IntoResponse {
        let m: BTreeMap<_, _> = jar.iter().map(|k| k.name_value()).collect();
        ErasedJson::pretty(m)
    }

    pub async fn cookies_set(Query(query): Query<BTreeMap<String, Vec<String>>>) -> impl IntoResponse {
        let mut jar = CookieJar::new();
        for (k, mut v) in query {
            let v = v.swap_remove(v.len() - 1);
            jar = jar.add(cookie::Cookie::new(k, v));
        }
        (StatusCode::FOUND, (jar, Redirect::to("/cookies"))).into_response()
    }

    pub async fn cookies_del(Query(query): Query<BTreeMap<String, Vec<String>>>, mut jar: CookieJar) -> impl IntoResponse {
        for (k, _) in query {
            jar = jar.remove(cookie::Cookie::from(k));
        }
        (StatusCode::FOUND, (jar, Redirect::to("/cookies")))
    }
}

async fn anything(
    method: Method,
    uri: Uri,
    Query(query): Query<Vec<(String, Vec<String>)>>,
    header_map: HeaderMap,
    content_type: Option<TypedHeader<ContentType>>,
    InsecureClientIp(origin): InsecureClientIp,
    body: Bytes,
) -> Response {
    let headers = get_headers(&header_map);

    let mut queries = Queries::default();
    for (k, v) in query {
        let vec = queries.entry(k).or_default();
        vec.extend(v);
    }

    let body_string = match std::str::from_utf8(&body) {
        Ok(body) => body.into(),
        Err(_) => BASE64_STANDARD.encode(&body),
    };

    let Http {
        mut form,
        mut files,
        mut json,
        ..
    } = Default::default();
    if let Some(TypedHeader(c)) = content_type {
        let mime: mime::Mime = c.into();
        match (mime.type_(), mime.subtype()) {
            (mime::APPLICATION, mime::JSON) => json = serde_json::from_slice(&body).ok(),
            (mime::APPLICATION, mime::WWW_FORM_URLENCODED) => {
                let f = form_urlencoded::parse(&body);
                for (k, v) in f {
                    form.entry(k.to_string()).or_default().push(v.to_string());
                }
            }
            (mime::MULTIPART, mime::FORM_DATA) => {
                let content_type = headers
                    .headers
                    .get(CONTENT_TYPE.as_str())
                    .and_then(|it| it.first())
                    .map(|s| s.as_str())
                    .unwrap_or_default();
                let boundary = multer::parse_boundary(content_type).ok();
                if let Some(boundary) = boundary {
                    let mut m = multer::Multipart::new(Body::from(body).into_data_stream(), boundary);
                    // println!("{?}", m);

                    while let Some((_idx, field)) = m.next_field_with_idx().await.unwrap_or_default() {
                        // println!("{?}",&field);
                        match (field.file_name(), field.name()) {
                            (None, Some(name)) => form
                                .entry(name.to_string())
                                .or_default()
                                .push(field.text().await.unwrap_or_default()),
                            (Some(_f), Some(name)) => {
                                let vec = files.entry(name.into()).or_default();
                                let field_val = field.bytes().await.unwrap_or_default();
                                let string = match std::str::from_utf8(&field_val) {
                                    Ok(body) => body.into(),
                                    Err(_) => BASE64_STANDARD.encode(&field_val),
                                };
                                vec.push(string);
                            }
                            (_, _) => {}
                        }
                    }
                }
            }
            (_, _) => {}
        }
    }

    ErasedJson::pretty(Http {
        method: method.to_string(),
        uri: uri.to_string(),
        headers,
        origin: origin.into(),
        args: queries,
        data: body_string,
        json,
        form,
        files,
    })
    .into_response()
}

async fn index() -> Html<String> {
    let md = include_str!("../README.md");
    Html(
        markdown::to_html_with_options(md, &markdown::Options::gfm()).unwrap_or_default()
            // language=html
            + indoc::indoc!(r#"
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
    let hostname = whoami::hostname().unwrap_or("<< unknown hostname >>".to_string());

    ErasedJson::pretty(HostName { hostname })
}

async fn utf8() -> impl IntoResponse {
    Html(include_str!("../assets/utf8.html"))
}

#[derive(Deserialize, Serialize, Default)]
struct UuidResponse {
    uuid: String,
}

async fn uuid() -> impl IntoResponse {
    ErasedJson::pretty(UuidResponse {
        uuid: Uuid::new_v4().to_string(),
    })
}

async fn response_headers(Query(query): Query<BTreeMap<String, Vec<String>>>) -> impl IntoResponse {
    let mut headers = HeaderMap::new();

    for (k, v) in query.iter().flat_map(|(k, v)| v.iter().map(move |v| (k, v))) {
        if let (Ok(k), Ok(v)) = (HeaderName::from_str(k), HeaderValue::from_str(v)) {
            headers.append(k, v);
        }
    }

    (headers, ErasedJson::pretty(query))
}

async fn robots_txt() -> impl IntoResponse {
    into_response(TEXT_PLAIN_UTF_8, include_str!("../assets/robots.txt"))
}

#[inline]
fn into_response(content_type: impl AsRef<str>, body: impl IntoResponse) -> Response {
    ([(CONTENT_TYPE, content_type.as_ref())], body).into_response()
}

mod resp_data {
    use super::*;
    pub async fn json() -> impl IntoResponse {
        into_response(APPLICATION_JSON, include_str!("../assets/sample.json"))
    }
    pub async fn xml() -> impl IntoResponse {
        into_response(TEXT_XML, include_str!("../assets/sample.xml"))
    }
    pub async fn html() -> impl IntoResponse {
        into_response(TEXT_HTML_UTF_8, include_str!("../assets/sample.html"))
    }
    pub async fn forms_post() -> impl IntoResponse {
        into_response(TEXT_HTML_UTF_8, include_str!("../assets/forms_post.html"))
    }
}

mod image {
    use super::*;

    pub async fn image(headers: HeaderMap) -> impl IntoResponse {
        let mime = headers.get(ACCEPT).and_then(|v| v.to_str().ok()).map(mime::MimeIter::new);

        if let Some(mime) = mime {
            for m in mime.filter_map(|m| m.ok()).filter(|it| it.type_() == IMAGE) {
                return match m.subtype().as_str() {
                    "jpeg" => jpeg().await,
                    "svg" => svg().await,
                    "png" => png().await,
                    "webp" => webp().await,
                    "avif" => avif().await,
                    "jxl" => jxl().await,
                    _ => continue,
                };
            }
        }

        StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response()
    }

    pub async fn jpeg() -> Response {
        into_response("image/jpeg", include_bytes!("../assets/jpeg.jpeg"))
    }
    pub async fn svg() -> Response {
        into_response("image/svg", include_bytes!("../assets/svg.svg"))
    }
    pub async fn png() -> Response {
        into_response("image/png", include_bytes!("../assets/png.png"))
    }
    pub async fn webp() -> Response {
        into_response("image/webp", include_bytes!("../assets/webp.webp"))
    }
    pub async fn jxl() -> Response {
        into_response("image/jxl", include_bytes!("../assets/jxl.jxl"))
    }
    pub async fn avif() -> Response {
        into_response("image/avif", include_bytes!("../assets/avif.avif"))
    }
}

async fn ip(InsecureClientIp(origin): InsecureClientIp) -> impl IntoResponse {
    ErasedJson::pretty(data::Ip { origin })
}

async fn cache(headers: HeaderMap) -> impl IntoResponse {
    // 检查请求头中是否包含 If-Modified-Since 或 If-None-Match
    if headers.contains_key(IF_MODIFIED_SINCE) || headers.contains_key(IF_NONE_MATCH) {
        // 如果包含这些头部，返回 304 Not Modified
        StatusCode::NOT_MODIFIED.into_response()
    } else {
        // 否则返回 200 OK
        StatusCode::OK.into_response()
    }
}

async fn cache_n(Path(n): Path<u32>) -> impl IntoResponse {
    let value = format!("public, max-age={n}");
    ([(CACHE_CONTROL, value)], StatusCode::OK)
}

async fn deny() -> impl IntoResponse {
    "YOU SHOULDN'T BE HERE"
}

#[derive(Serialize, Deserialize)]
pub struct BearerAuth {
    pub authorized: bool,
    pub token: String,
}

async fn bearer(header_map: HeaderMap) -> impl IntoResponse {
    let authorization = header_map.typed_get::<Authorization<Bearer>>();

    match authorization {
        None => ErasedJson::pretty(ErrorDetail::new(401, "Unauthorized", "")).into_response(),
        Some(token) => ErasedJson::pretty(BearerAuth {
            authorized: true,
            token: token.token().to_string(),
        })
        .into_response(),
    }
}



mod base_64 {
    use super::*;

    pub async fn base64_decode(Path(base64_data): Path<String>) -> impl IntoResponse {
        (
            [(CONTENT_TYPE, TEXT_PLAIN.as_ref())],
            BASE64_STANDARD.decode(base64_data).unwrap_or_else(|e| e.to_string().into_bytes()),
        )
    }

    pub async fn base64_encode(Path(data): Path<String>) -> impl IntoResponse {
        ([(CONTENT_TYPE, TEXT_PLAIN.as_ref())], BASE64_STANDARD.encode(data))
    }
}

mod sse {
    use jiff::SignedDuration;

    use super::*;

    #[derive(Deserialize)]
    pub struct SeeParam {
        pub count: Option<usize>,
        #[serde(default)]
        pub duration: Option<SignedDuration>,
        #[serde(default)]
        pub delay: Option<SignedDuration>,
    }

    pub async fn sse_handler(Query(SeeParam { delay, duration, count }): Query<SeeParam>) -> Response {
        use tokio_stream::StreamExt as _;
        tokio::time::sleep(delay.unwrap_or(SignedDuration::ZERO).unsigned_abs()).await;
        let sec = duration.unwrap_or(SignedDuration::from_secs(1)).unsigned_abs().as_secs_f32();
        let stream = tokio_stream::iter(1..)
            .take(count.unwrap_or(10_usize))
            .throttle(Duration::from_secs_f32(sec))
            .map(|id| {
                let timestamp = jiff::Timestamp::now().as_millisecond();
                #[allow(clippy::useless_conversion)]
                Event::default()
                    .data(serde_json::to_string(&data::SseData { id, timestamp }).unwrap_or_default())
                    .event("ping")
                    .try_into()
            });

        Sse::new(stream).into_response()
    }
}

mod links {

    use super::*;

    #[derive(Debug, Deserialize, Validate)]
    pub struct LinksParam {
        #[garde(range(min = 0, max = 256))]
        pub total: u32,
        #[garde(range(min = 0))]
        pub page: Option<u32>,
    }

    pub async fn links(Garde(Path(p)): Garde<Path<LinksParam>>) -> Response {
        let LinksParam { total, page } = p;

        let Some(cur) = page else {
            return Redirect::to(format!("/links/{total}/0").as_str()).into_response();
        };

        info!(cur, total);

        let mut env = minijinja::Environment::new();
        env.set_trim_blocks(true);
        env.set_lstrip_blocks(true);

        let html = env
            .render_str(
                // language=html
                indoc::indoc! {
r#"
        <html>
            <head>
                <title>Links</title>
            </head>
            <body>
            {% for idx in range(total) %}
                {% if idx == cur %}
                    {{idx}}
                {% else %}
                    <a href="/links/{{total}}/{{idx}}">{{idx}}</a>
                {% endif %}
            {% endfor %}
            </body>
        </html>
    "#},
                minijinja::context! {total, cur},
            )
            .unwrap_or_default();
        Html(html).into_response()
    }
}

// 新增 handler
async fn status_code_handler(Path(code): Path<u16>) -> Response {
    if let Ok(status) = StatusCode::from_u16(code) {
        return status.into_response();
    }
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!(
        {
            "status_code": 400,
            "error": "Bad Request",
            "detail": format!("invalid status code: {code} not in range [100, 999]")
        }
        )),
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
struct BytesQuery {
    seed: Option<u64>,
}

async fn bytes_n(Path(n): Path<u32>, Query(q): Query<BytesQuery>) -> impl IntoResponse {
    let n = n.min(1024 * 1024 * 10); // 限制在 1 到 10MB
    let mut buf = vec![0u8; n as usize];
    if let Some(seed) = q.seed {
        fastrand::Rng::with_seed(seed).fill(&mut buf);
    } else {
        fastrand::fill(&mut buf);
    }
    ([(CONTENT_TYPE, "application/octet-stream")], buf)
}

async fn dump_request(request: Request) -> impl IntoResponse {
    use std::fmt::Write;

    use axum::body::to_bytes;
    let (parts, body) = request.into_parts();
    let method = parts.method;
    let uri = parts.uri;
    let version = match parts.version {
        axum::http::Version::HTTP_09 => "HTTP/0.9",
        axum::http::Version::HTTP_10 => "HTTP/1.0",
        axum::http::Version::HTTP_11 => "HTTP/1.1",
        axum::http::Version::HTTP_2 => "HTTP/2.0",
        axum::http::Version::HTTP_3 => "HTTP/3.0",
        _ => "HTTP/1.1",
    };
    let mut req = String::new();
    // 请求行
    writeln!(&mut req, "{method} {uri} {version}").ok();
    // 请求头
    for (k, v) in &parts.headers {
        if let Ok(val) = v.to_str() {
            writeln!(&mut req, "{k}: {val}").ok();
        } else {
            writeln!(&mut req, "{k}: <binary>").ok();
        }
    }
    // 空行
    writeln!(&mut req).ok();
    // body
    let body_bytes = to_bytes(body, 10_000_000).await.unwrap_or_default(); // 限制最大请求体为 10MB
    if !body_bytes.is_empty() {
        if let Ok(body_str) = std::str::from_utf8(&body_bytes) {
            req.push_str(body_str);
        } else {
            req.push_str("<binary body>\n");
        }
    }
    ([(CONTENT_TYPE, "text/plain; charset=utf-8")], req)
}



#[derive(Debug, Deserialize)]
struct DripQuery {
    numbytes: Option<usize>,
    duration: Option<u64>,
    delay: Option<u64>,
    code: Option<u16>,
}

async fn drip_handler(Query(q): Query<DripQuery>) -> impl IntoResponse {
    use tokio_stream::StreamExt as _;

    let numbytes = q.numbytes.unwrap_or(10);
    let duration = q.duration.unwrap_or(1);
    let delay = q.delay.unwrap_or(0);
    let code = q.code.unwrap_or(200);

    sleep(Duration::from_secs(delay)).await;

    let chunk_size = (numbytes as u64 / duration).max(1) as usize;

    let stream = stream::iter(
        (0..numbytes)
            .step_by(chunk_size)
            .map(move |_| Ok::<_, std::io::Error>(Bytes::from_iter(vec![b'*'; chunk_size]))),
    )
    .throttle(Duration::from_secs(1));

    (
        StatusCode::from_u16(code).unwrap_or(StatusCode::OK),
        [(CONTENT_TYPE, "application/octet-stream")],
        axum::body::Body::from_stream(stream),
    )
}

async fn etag_handler(Path(etag): Path<String>, headers: HeaderMap) -> impl IntoResponse {
    let if_none_match = headers.get(IF_NONE_MATCH).and_then(|v| v.to_str().ok());
    let if_match = headers.get(IF_MATCH).and_then(|v| v.to_str().ok());

    if let Some(tag) = if_none_match
        && tag == etag
    {
        return StatusCode::NOT_MODIFIED.into_response();
    }

    if let Some(tag) = if_match
        && tag != etag
    {
        return StatusCode::PRECONDITION_FAILED.into_response();
    }

    ([(ETAG, etag.as_bytes())], Json(json!({ "etag": etag }))).into_response()
}

#[derive(Debug, Deserialize)]
struct RangeQuery {
    duration: Option<u64>,
    chunk_size: Option<usize>,
}

use std::ops::Bound;

async fn range_handler(Path(n): Path<u32>, range: Option<TypedHeader<Range>>, Query(q): Query<RangeQuery>) -> impl IntoResponse {
    let total = n as u64;
    let chunk_size = q.chunk_size.unwrap_or(4096).max(1);
    let _duration = q.duration.unwrap_or(1);

    if let Some(TypedHeader(range)) = range {
        if let Some((start_bound, end_bound)) = range.satisfiable_ranges(total).next() {
            let start = match start_bound {
                Bound::Included(v) => v,
                Bound::Excluded(v) => v + 1,
                Bound::Unbounded => 0,
            };
            let end = match end_bound {
                Bound::Included(v) => v,
                Bound::Excluded(v) => v - 1,
                Bound::Unbounded => total - 1,
            };

            let stream = stream::iter((start..=end).step_by(chunk_size).map(move |s| {
                let len = (chunk_size as u64).min(end - s + 1);
                Ok::<_, std::io::Error>(Bytes::from_iter(vec![b'a'; len as usize]))
            }));

            return (
                StatusCode::PARTIAL_CONTENT,
                [(CONTENT_RANGE, format!("bytes {}-{}/{}", start, end, total))],
                axum::body::Body::from_stream(stream),
            )
                .into_response();
        }
        return (StatusCode::RANGE_NOT_SATISFIABLE, [(CONTENT_RANGE, format!("bytes */{}", total))]).into_response();
    }

    let stream = stream::iter(
        (0..total)
            .step_by(chunk_size)
            .map(move |_| Ok::<_, std::io::Error>(Bytes::from_iter(vec![b'a'; chunk_size]))),
    );

    (
        StatusCode::OK,
        [(CONTENT_TYPE, "application/octet-stream")],
        axum::body::Body::from_stream(stream),
    )
        .into_response()
}

async fn stream_handler(Path(n): Path<u32>) -> impl IntoResponse {
    let n = n.min(100); // limit to max 100 lines
    let stream = stream::iter((0..n).map(|i| {
        Ok::<_, std::io::Error>(Bytes::from(format!(
            "line {}
",
            i
        )))
    }));

    ([(CONTENT_TYPE, "text/plain; charset=utf-8")], axum::body::Body::from_stream(stream))
}

#[derive(Debug, Deserialize)]
struct StreamBytesQuery {
    seed: Option<u64>,
    chunk_size: Option<usize>,
}

async fn stream_bytes_handler(Path(n): Path<u32>, Query(q): Query<StreamBytesQuery>) -> impl IntoResponse {
    let total = n as usize;
    let chunk_size = q.chunk_size.unwrap_or(1024).clamp(1,10240); // default 1KB, max 10KB per chunk

    let mut rng = if let Some(seed) = q.seed {
        fastrand::Rng::with_seed(seed)
    } else {
        fastrand::Rng::new()
    };

    let stream = stream::iter((0..total).step_by(chunk_size).map(move |start| {
        let end = (start + chunk_size).min(total);
        let mut buf = vec![0u8; end - start];
        rng.fill(&mut buf);
        Ok::<_, std::io::Error>(Bytes::from(buf))
    }));

    ([(CONTENT_TYPE, "application/octet-stream")], axum::body::Body::from_stream(stream))
}
