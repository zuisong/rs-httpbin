use std::{
    convert::Infallible,
    net::{IpAddr, SocketAddr},
};

use axum::{
    extract::{ConnectInfo, FromRequestParts},
    http::{Extensions, StatusCode, request::Parts},
};

pub(crate) type InfallibleRejection = (StatusCode, Infallible);

pub struct InsecureClientIp(pub IpAddr);

impl<S> FromRequestParts<S> for InsecureClientIp
where
    S: Sync,
{
    type Rejection = InfallibleRejection;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let s = client_ip::fly_client_ip(&parts.headers)
            .or(client_ip::x_real_ip(&parts.headers))
            .or(client_ip::cf_connecting_ip(&parts.headers))
            .or(client_ip::cloudfront_viewer_address(&parts.headers))
            .or(client_ip::true_client_ip(&parts.headers));
        if let Ok(ip) = s {
            Ok(InsecureClientIp(ip))
        } else {
            Ok(InsecureClientIp(maybe_connect_info(&parts.extensions).unwrap()))
        }
    }
}

fn maybe_connect_info(extensions: &Extensions) -> Option<IpAddr> {
    extensions.get::<ConnectInfo<SocketAddr>>().map(|ConnectInfo(addr)| addr.ip())
}
