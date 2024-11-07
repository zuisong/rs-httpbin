use std::{collections::BTreeMap, net::IpAddr};

use derive_more::{Deref, DerefMut};
use serde::{Deserialize, Serialize, Serializer};

#[derive(Serialize, Deserialize, Default, Deref, DerefMut)]
#[serde(transparent)]
pub struct MyVec<T>
where
    T: Default + Serialize,
{
    #[serde(serialize_with = "one_or_many")]
    inner: Vec<T>,
}

fn one_or_many<T, S>(t: &Vec<T>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: Default + Serialize,
{
    match t.len() {
        0 | 1 => s.serialize_some(&t.first()),
        2.. => s.serialize_some(&t),
    }
}

#[derive(Serialize, Default, Deref, DerefMut)]
pub struct Headers {
    pub(crate) headers: BTreeMap<String, MyVec<String>>,
}

#[derive(Serialize, Deserialize, Default, Deref, DerefMut)]
#[serde(transparent)]
pub struct Queries {
    pub inner: BTreeMap<String, MyVec<String>>,
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
#[derive(Serialize, Default)]
pub struct Http {
    pub method: String,
    pub uri: String,
    #[serde(flatten)]
    pub headers: Headers,
    pub origin: Option<IpAddr>,
    pub args: Queries,
    pub data: String,
    pub json: Option<serde_json::Value>,
    pub form: BTreeMap<String, MyVec<String>>,
    pub files: BTreeMap<String, MyVec<String>>,
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
