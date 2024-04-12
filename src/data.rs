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
    // todo
    // files
    // form
}
