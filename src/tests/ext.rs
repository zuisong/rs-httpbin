use std::{future::Future, pin::Pin};

use http_body_util::BodyExt as _;
use serde_json::Value;

pub trait BodyExt {
    fn body(self) -> Pin<Box<dyn Future<Output = Vec<u8>> + Send>>;
    fn body_as_bytes(self) -> Pin<Box<dyn Future<Output = Vec<u8>> + Send>>;
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

    fn body_as_bytes(self) -> Pin<Box<dyn Future<Output = Vec<u8>> + Send>> {
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
