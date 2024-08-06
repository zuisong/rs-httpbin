use std::{collections::BTreeMap, net::IpAddr};

use serde::Serialize;

#[derive(Serialize)]
pub struct Headers {
    pub(crate) headers: BTreeMap<String, Vec<String>>,
}

#[derive(Serialize)]
pub struct Ip {
    pub origin: IpAddr,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct UserAgent {
    pub user_agent: String,
}

#[derive(Serialize)]
pub struct Http {
    pub method: String,
    pub uri: String,
    pub headers: BTreeMap<String, Vec<String>>,
    pub origin: IpAddr,
    pub args: BTreeMap<String, Vec<String>>,
    pub data: String,
    pub json: Option<serde_json::Value>,
    pub form: BTreeMap<String, Vec<String>>,
    pub files: BTreeMap<String, Vec<String>>,
}

#[derive(Serialize)]
pub struct SseData {
    pub id: i32,
    pub timestamp: u128,
}

#[derive(Serialize, Debug)]
pub struct ErrorDetail {
    status_code: i32,
    error: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    detail: String,
}

impl ErrorDetail {
    pub fn new(status_code: i32, error: impl ToString, detail: impl ToString) -> Self {
        ErrorDetail {
            status_code,
            error: error.to_string(),
            detail: detail.to_string(),
        }
    }
}
