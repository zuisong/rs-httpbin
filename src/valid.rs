use std::ops::Deref;

use axum::{
    extract::FromRequestParts,
    http::{StatusCode, request::Parts},
    response::{IntoResponse, Response},
};
use garde::Validate;

pub struct Garde<T>(pub T);

impl<S, T> FromRequestParts<S> for Garde<T>
where
    T: FromRequestParts<S> + Deref,
    T::Target: Validate<Context = ()>,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let inner = T::from_request_parts(parts, state).await.map_err(|e| e.into_response())?;

        if let Err(e) = inner.deref().validate() {
            return Err((StatusCode::BAD_REQUEST, e.to_string()).into_response());
        }

        Ok(Garde(inner))
    }
}
