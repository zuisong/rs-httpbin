use axum::response::Html;
use axum::{routing::get, Json, Router};
use comrak::Options;
use serde_json::Value;
use tower_http::trace::TraceLayer;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    let app = Router::new()
        .route("/", get(index))
        .route("/json", get(json))
        .layer(TraceLayer::new_for_http());
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();

    axum::serve(listener, app).await.unwrap();
}

async fn index() -> Html<String> {
    let md = include_str!("../README.md");
    Html(comrak::markdown_to_html(md, &Options::default()))
}

async fn json() -> Json<Value> {
    Json(serde_json::json! {
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

        })
}
