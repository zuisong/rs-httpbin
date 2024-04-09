use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderMap, HeaderValue};
use axum::response::{Html, IntoResponse};
use axum::{routing::get, Router};
use comrak::Options;
use mime::APPLICATION_JSON;
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
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::new().allow_origin(Any).allow_methods(Any));
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();

    axum::serve(listener, app).await.unwrap();
}

async fn index() -> Html<String> {
    let md = include_str!("../README.md");
    Html(comrak::markdown_to_html(md, &Options::default()))
}

async fn json() -> impl IntoResponse {
    (
        HeaderMap::from_iter([(
            CONTENT_TYPE,
            HeaderValue::from_static(APPLICATION_JSON.essence_str()),
        )]),
        indoc::indoc! {r#"
            {
              "slideshow": {
                "author": "Yours Truly",
                "date": "date of publication",
                "slides": [
                  {
                    "title": "Wake up to WonderWidgets!",
                    "type": "all"
                  },
                  {
                    "items": [
                      "Why <em>WonderWidgets</em> are great",
                      "Who <em>buys</em> WonderWidgets"
                    ],
                    "title": "Overview",
                    "type": "all"
                  }
                ],
                "title": "Sample Slide Show"
              }
            }
            "#,
        },
    )
}
