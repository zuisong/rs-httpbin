use std::collections::HashMap;

use serde::Serialize;

#[derive(Serialize)]
pub struct Headers {
    pub(crate) headers: HashMap<String, Vec<String>>,
}

#[derive(Serialize)]
pub struct Ip {
    pub origin: String,
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
    pub headers: HashMap<String, Vec<String>>,
    pub origin: String,
    pub args: Option<HashMap<String, String>>,
    pub data: String,
    pub json: Option<serde_json::Value>,
    // todo
    // files
    // form
}