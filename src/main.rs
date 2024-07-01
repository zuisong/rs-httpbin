use std::{
    collections::BTreeMap,
    default::Default,
    net::{Ipv4Addr, SocketAddr},
    str::FromStr,
    time::{Duration, UNIX_EPOCH},
};

use ::base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use axum::{
    body::{Body, Bytes},
    extract::{Host, MatchedPath, Path, Request},
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
use axum_garde::WithValidation;
use garde::Validate;
use mime::{APPLICATION_JSON, IMAGE, TEXT_HTML_UTF_8, TEXT_PLAIN, TEXT_XML};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio_stream::StreamExt;
use tower::ServiceBuilder;
use tower_http::{
    cors::CorsLayer, request_id::MakeRequestUuid, set_header::SetRequestHeaderLayer, trace::TraceLayer,
    ServiceBuilderExt,
};
use tracing::debug_span;
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
        .route("/unstable", get(unstable))
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
        .with(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "DEBUG".into()))
        .with(tracing_subscriber::fmt::layer().json())
        .init();

    let router = app();

    let service = ServiceBuilder::default()
        .set_x_request_id(MakeRequestUuid)
        .propagate_x_request_id()
        .compression()
        .layer(TraceLayer::new_for_http().make_span_with(|request: &Request<Body>| {
            let request_id = request.headers()["x-request-id"].to_str().ok();
            let matched_path = request.extensions().get::<MatchedPath>().map(MatchedPath::as_str);
            let method = request.method().as_str();
            debug_span!("request_id", method, matched_path, request_id,)
        }))
        .layer(CorsLayer::permissive());

    let app = router.layer(service);

    let listener = tokio::net::TcpListener::bind((Ipv4Addr::UNSPECIFIED, 3000))
        .await
        .unwrap();
    eprintln!("Listening on http://{}", listener.local_addr().unwrap());
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .unwrap();
}

async fn user_agent(user_agent: Option<TypedHeader<UserAgent>>) -> impl IntoResponse {
    ErasedJson::pretty(data::UserAgent {
        user_agent: user_agent.map(|h| h.0.to_string()).unwrap_or("".to_string()),
    })
}

async fn headers(header_map: HeaderMap) -> impl IntoResponse {
    ErasedJson::pretty(data::Headers {
        headers: get_headers(&header_map),
    })
}

#[derive(Debug, Validate, Deserialize)]
struct UnstableQueryParam {
    #[garde(range(min = 0.0, max = 1.0))]
    pub failure_rate: Option<f32>,
}

async fn unstable(WithValidation(query): WithValidation<Query<UnstableQueryParam>>) -> Response {
    let failure_rate = query.failure_rate.unwrap_or(0.5);
    if !matches!(failure_rate, 0.0..=1.0) {
        return ErasedJson::pretty(json!(
        {
            "status_code": 400,
            "error": "Bad Request",
            "detail": "invalid failure rate: %!d(<nil>) not in range [0, 1]"
        }
                ))
        .into_response();
    }

    if fastrand::f32() <= failure_rate {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    ().into_response()
}

mod basic_auth {
    use super::*;

    #[derive(Serialize, Deserialize)]
    struct BasicAuth {
        pub authorized: bool,
        pub user: String,
    }

    #[derive(Deserialize)]
    pub struct BasicAuthParam {
        user: String,
        passwd: String,
    }

    pub async fn basic_auth(
        Path(BasicAuthParam { user, passwd }): Path<BasicAuthParam>,
        basic_auth: Option<TypedHeader<Authorization<Basic>>>,
    ) -> impl IntoResponse {
        let authorized = match &basic_auth {
            None => false,
            Some(auth) => auth.username() == user && auth.password() == passwd,
        };
        let body = ErasedJson::pretty(BasicAuth {
            authorized,
            user: basic_auth.map(|it| it.username().to_string()).unwrap_or_default(),
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
        Path(BasicAuthParam { user, passwd }): Path<BasicAuthParam>,
        basic_auth: Option<TypedHeader<Authorization<Basic>>>,
    ) -> impl IntoResponse {
        let authorized = match basic_auth {
            None => false,
            Some(auth) => auth.username() == user && auth.password() == passwd,
        };

        if authorized {
            (
                StatusCode::OK,
                ErasedJson::pretty(BasicAuth {
                    authorized,
                    user: if authorized { user } else { Default::default() },
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
    let mut headers: BTreeMap<String, Vec<String>> = BTreeMap::new();

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
    Html(
        markdown::to_html_with_options(md, &markdown::Options::gfm()).unwrap()
            // language=html
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
        [(CONTENT_TYPE, HeaderValue::from_static(mime::TEXT_PLAIN_UTF_8.as_ref()))],
        include_str!("../assets/robots.txt"),
    )
}

mod resp_data {
    use super::*;

    macro_rules! define_data_response {
        ($name:ident, $path:expr, $content_type:expr) => {
            pub(crate) async fn $name() -> impl IntoResponse {
                let body = include_str!($path);
                ([(CONTENT_TYPE, $content_type)], body)
            }
        };
    }

    define_data_response!(json, "../assets/sample.json", APPLICATION_JSON.essence_str());
    define_data_response!(xml, "../assets/sample.xml", TEXT_XML.essence_str());
    define_data_response!(html, "../assets/sample.html", TEXT_HTML_UTF_8.essence_str());
    define_data_response!(forms_post, "../assets/forms_post.html", TEXT_HTML_UTF_8.essence_str());
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

    macro_rules! define_image_response {
        ($name:ident, $path:expr, $content_type:expr) => {
            pub(crate) async fn $name() -> Response {
                let bytes = include_bytes!($path);
                ([(CONTENT_TYPE, $content_type)], bytes).into_response()
            }
        };
    }

    define_image_response!(jpeg, "../assets/jpeg.jpeg", "image/jpeg");
    define_image_response!(svg, "../assets/svg.svg", "image/svg");
    define_image_response!(png, "../assets/png.png", "image/png");
    define_image_response!(webp, "../assets/webp.webp", "image/webp");
    define_image_response!(jxl, "../assets/jxl.jxl", "image/jxl");
    define_image_response!(avif, "../assets/avif.avif", "image/avif");
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
            2.. => (StatusCode::FOUND, [(LOCATION, format!("/redirect/{}", n - 1))]).into_response(),
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

    pub(crate) async fn absolute_redirect(Path(n): Path<i32>, uri: Uri, Host(host): Host, _req: Request) -> Response {
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

    #[derive(Debug, Deserialize, Validate)]
    pub struct Params {
        #[garde(length(min = 0))]
        url: String,
        #[garde(range(min = 100, max = 999))]
        status_code: Option<u16>,
    }

    pub async fn redirect_to(WithValidation(p): WithValidation<Query<Params>>) -> Response {
        let Params { url, status_code } = p.into_inner();
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

    pub async fn sse_handler(Query(SeeParam { delay, duration, count }): Query<SeeParam>) -> Response {
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

    pub async fn links(WithValidation(p): WithValidation<Path<LinksParam>>) -> Response {
        let LinksParam { total, page } = p.into_inner();

        if page.is_none() {
            return Redirect::to(format!("/links/{}/0", total).as_str()).into_response();
        }
        let cur = page.unwrap();
        tracing::info!(cur, total);

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
            .unwrap();
        Html(html).into_response()
    }
}
