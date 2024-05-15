use std::{
    collections::BTreeMap,
    net::SocketAddr,
    str::FromStr,
    time::{Duration, UNIX_EPOCH},
};

use ::base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use axum::{
    body::{Body, Bytes},
    extract::{Host, Path, Request},
    http::{header::*, HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri},
    middleware,
    response::{sse::Event, Html, IntoResponse, Redirect, Response, Sse},
    routing::*,
    Router,
};
use axum_client_ip::InsecureClientIp;
use axum_extra::{
    extract::{cookie, CookieJar, Query},
    headers::{authorization::Basic, Authorization, ContentType, UserAgent},
    response::ErasedJson,
    TypedHeader,
};
use mime::{APPLICATION_JSON, IMAGE, TEXT_HTML_UTF_8, TEXT_PLAIN, TEXT_XML};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio_stream::StreamExt;
use tower_http::{
    compression::CompressionLayer,
    cors::CorsLayer,
    set_header::SetRequestHeaderLayer,
    trace::{DefaultOnRequest, DefaultOnResponse, TraceLayer},
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

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
        .route("/basic-auth/:user/:passwd", any(basic_auth::basic_auth))
        .route("/hidden-basic-auth/:user/:passwd", any(basic_auth::hidden_basic_auth))
        //
        .route("/user-agent", any(user_agent))
        .route("/headers", any(headers))
        .route("/json", get(resp_data::json))
        .route("/xml", get(resp_data::xml))
        .route("/html", get(resp_data::html))
        .route("/hostname", get(hostname))
        .route("/uuid", any(uuid))
        .route("/response-headers", any(response_headers))
        .route("/ip", any(ip))
        //
        .route("/image", any(image::image))
        .route("/image/jpeg", any(image::jpeg))
        .route("/image/svg", any(image::svg))
        .route("/image/png", any(image::png))
        .route("/image/webp", any(image::webp))
        .route("/image/avif", any(image::avif))
        .route("/image/jxl", any(image::jxl))
        //
        .route("/base64/:value", any(base64::base64_decode))
        .route("/base64/encode/:value", any(base64::base64_encode))
        .route("/base64/decode/:value", any(base64::base64_decode))
        .route("/forms/post", any(resp_data::forms_post))
        .route("/sse", any(sse::sse_handler))
        .route("/cookies", any(cookies::cookies))
        .route("/cookies/set", any(cookies::cookies_set))
        .route("/cookies/delete", any(cookies::cookies_del))
        .route("/encoding/utf8", any(utf8))
        .route("/robots.txt", any(robots_txt))
        .route("/links/:total", any(links::links))
        .route("/links/:total/:page", any(links::links))
        .route("/redirect-to", any(redirect::redirect_to))
        .route("/delay/:n", any(anything).layer({
            async fn delay(Path(delays): Path<u16>, request: Request, next: middleware::Next) -> impl IntoResponse {
                tokio::time::sleep(Duration::from_secs(delays.min(10).into())).await;
                next.run(request).await
            }
            middleware::from_fn(delay)
        }))

        //keep me
        ;

    for format in ["gzip", "zstd", "br", "deflate"] {
        router = router.route(
            format!("/{format}").as_str(),
            get(anything).layer(SetRequestHeaderLayer::overriding(
                ACCEPT_ENCODING,
                HeaderValue::from_static(format),
            )),
        );
    }

    router
}

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "DEBUG".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let router: Router = app();
    let app = router.layer((
        CompressionLayer::new(),
        TraceLayer::new_for_http()
            .make_span_with(|request: &Request<Body>| {
                let request_id = uuid::Uuid::new_v4();
                tracing::span!(
                    tracing::Level::DEBUG,
                    "request",
                    method = display(request.method()),
                    uri = display(request.uri()),
                    version = debug(request.version()),
                    request_id = display(request_id)
                )
            })
            .on_request(DefaultOnRequest::new().level(tracing::Level::INFO))
            .on_response(
                DefaultOnResponse::new()
                    .level(tracing::Level::INFO)
                    .include_headers(true),
            ),
        CorsLayer::permissive(),
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

mod basic_auth {
    use super::*;

    #[derive(Serialize, Deserialize)]
    struct BasicAuth {
        pub authorized: bool,
        pub user: String,
    }

    pub async fn basic_auth(
        Path((user, passwd)): Path<(String, String)>,
        basic_auth: Option<TypedHeader<Authorization<Basic>>>,
    ) -> impl IntoResponse {
        let (basic_auth_username, basic_auth_password) = match &basic_auth {
            None => (None, None),
            Some(auth) => (auth.username().into(), auth.password().into()),
        };
        let authorized = Some(passwd.as_str()) == basic_auth_password
            && Some(user.as_str()) == basic_auth_username;
        let body = ErasedJson::pretty(BasicAuth {
            authorized,
            user: basic_auth_username.unwrap_or("").to_string(),
        });
        if authorized {
            (StatusCode::OK, body).into_response()
        } else {
            (
                StatusCode::UNAUTHORIZED,
                [(
                    WWW_AUTHENTICATE,
                    HeaderValue::from_static(r#"Basic realm="Fake Realm""#),
                )],
                body,
            )
                .into_response()
        }
    }

    pub async fn hidden_basic_auth(
        Path((user, passwd)): Path<(String, String)>,
        basic_auth: Option<TypedHeader<Authorization<Basic>>>,
    ) -> impl IntoResponse {
        let (basic_auth_username, basic_auth_password) = match &basic_auth {
            None => (None, None),
            Some(auth) => (auth.username().into(), auth.password().into()),
        };
        let authorized = Some(passwd.as_str()) == basic_auth_password
            && Some(user.as_str()) == basic_auth_username;
        if authorized {
            (
                StatusCode::OK,
                ErasedJson::pretty(BasicAuth {
                    authorized,
                    user: basic_auth_username.unwrap_or("").to_string(),
                }),
            )
                .into_response()
        } else {
            (
                StatusCode::NOT_FOUND,
                ErasedJson::pretty(json!(
                    {
                        "status_code": 404,
                        "error": "Not Found"
                    }
                )),
            )
                .into_response()
        }
    }
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

    pub async fn cookies(jar: CookieJar) -> impl IntoResponse {
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
        Err(_) => BASE64.encode(&body),
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

async fn utf8() -> impl IntoResponse {
    Html(include_str!("../assets/utf8.html"))
}

async fn uuid() -> impl IntoResponse {
    ErasedJson::pretty(json!( { "uuid" : uuid::Uuid::new_v4().to_string(), }))
}

async fn response_headers(Query(query): Query<BTreeMap<String, Vec<String>>>) -> impl IntoResponse {
    let mut headers = HeaderMap::new();

    for (k, vals) in query.iter() {
        for v in vals {
            if let (Ok(k), Ok(v)) = (HeaderName::from_str(k), HeaderValue::from_str(v)) {
                headers.append(k, v);
            };
        }
    }

    (headers, ErasedJson::pretty(query))
}

async fn robots_txt() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static(mime::TEXT_PLAIN_UTF_8.as_ref()),
        )],
        include_str!("../assets/robots.txt"),
    )
}

mod resp_data {
    use super::*;

    pub(crate) async fn json() -> impl IntoResponse {
        (
            [(CONTENT_TYPE, APPLICATION_JSON.essence_str())],
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
                    "avif" => return avif().await,
                    "jxl" => return jxl().await,
                    _ => continue,
                }
            }
        }

        StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response()
    }

    pub(crate) async fn jpeg() -> Response {
        (
            [(CONTENT_TYPE, "image/jpeg")],
            include_bytes!("../assets/jpeg.jpeg"),
        )
            .into_response()
    }

    pub(crate) async fn svg() -> Response {
        (
            [(CONTENT_TYPE, "image/svg")],
            include_bytes!("../assets/svg.svg"),
        )
            .into_response()
    }

    pub(crate) async fn png() -> Response {
        (
            [(CONTENT_TYPE, "image/png")],
            include_bytes!("../assets/png.png"),
        )
            .into_response()
    }

    pub(crate) async fn webp() -> Response {
        (
            [(CONTENT_TYPE, "image/webp")],
            include_bytes!("../assets/webp.webp"),
        )
            .into_response()
    }
    pub(crate) async fn jxl() -> Response {
        (
            [(CONTENT_TYPE, "image/jxl")],
            include_bytes!("../assets/jxl.jxl"),
        )
            .into_response()
    }
    pub(crate) async fn avif() -> Response {
        (
            [(CONTENT_TYPE, "image/avif")],
            include_bytes!("../assets/avif.avif"),
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

    #[derive(Debug, Deserialize)]
    pub struct Params {
        url: String,
        status_code: Option<u16>,
    }

    pub async fn redirect_to(Query(Params { url, status_code }): Query<Params>) -> Response {
        let status_code = status_code.unwrap_or(302);
        (
            StatusCode::from_u16(status_code)
                .ok()
                .filter(StatusCode::is_redirection)
                .unwrap_or(StatusCode::FOUND),
            [(LOCATION, url)],
        )
            .into_response()
    }
}

mod base64 {
    use super::*;

    pub(crate) async fn base64_decode(Path(base64_data): Path<String>) -> impl IntoResponse {
        (
            [(CONTENT_TYPE, TEXT_PLAIN.as_ref())],
            BASE64
                .decode(base64_data)
                .unwrap_or_else(|e| e.to_string().into_bytes()),
        )
    }

    pub(crate) async fn base64_encode(Path(data): Path<String>) -> impl IntoResponse {
        ([(CONTENT_TYPE, TEXT_PLAIN.as_ref())], BASE64.encode(data))
    }
}

mod sse {
    use super::*;

    #[derive(Deserialize, Serialize, Default)]
    pub struct SeeParam {
        pub count: Option<usize>,
        #[serde(with = "humantime_serde")]
        pub duration: Option<Duration>,
        #[serde(with = "humantime_serde")]
        pub delay: Option<Duration>,
    }

    pub async fn sse_handler(
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
                    .data(
                        serde_json::to_string(&data::SseData { id, timestamp }).unwrap_or_default(),
                    )
                    .event("ping")
                    .try_into()
            })
            .throttle(duration.unwrap_or(Duration::from_secs(1)));

        Sse::new(stream).into_response()
    }
}
mod links {

    use super::*;

    #[derive(Debug, Deserialize)]
    pub struct LinksParam {
        pub total: u32,
        pub page: Option<u32>,
    }

    pub async fn links(Path(LinksParam { total, page }): Path<LinksParam>) -> Response {
        if page.is_none() {
            return Redirect::to(format!("/links/{}/0", total).as_str()).into_response();
        }
        let cur = page.unwrap();
        let total = std::cmp::min(total, 256);
        tracing::info!(cur, total);

        let mut env = minijinja::Environment::new();
        env.set_trim_blocks(true);
        env.set_lstrip_blocks(true);

        let html = env
            .render_str(
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
            .unwrap();
        Html(html).into_response()
    }
}
