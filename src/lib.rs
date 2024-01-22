//! # Easy authentication for [`axum`]
//!
//! Provide an easy-to-use, simple, file-based authentication
//! mechanism for [`axum`]-based web applications modeled after
//! [`htpasswd`](https://httpd.apache.org/docs/2.4/programs/htpasswd.html)
//! files.

use axum::http::{header, Request, Response, StatusCode};
use base64::{engine::general_purpose, Engine as _};
use http_body::Body;
use log::{debug, error};
use std::marker::PhantomData;
use std::str;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tower_http::validate_request::ValidateRequest;

/// File-based authentication provider backed by a plaintext file.
///
/// This is the most basic variant of a provider. It simply expects a file
/// consisting of plaintext user-password pairs, delimited by a colon.
pub struct FileAuth<ResBody> {
    known_users: Vec<String>,
    _ty: PhantomData<fn() -> ResBody>,
}

impl<ResBody> FileAuth<ResBody> {
    /// Create a new authentication engine.
    ///
    /// Build a new authentication engine to be used by
    /// axum. All authentications performed by this engine will be
    /// backed by the given `file`.
    ///
    /// To use it, insert it into your axum router *after* the routes
    /// you want to protect:
    ///
    /// ```rust
    /// use axum::Router;
    /// use axum_htpasswd::FileAuth;
    /// use tokio::fs::File;
    /// use tower_http::services::ServeDir;
    /// use tower_http::validate_request::ValidateRequestHeaderLayer;
    ///
    /// async fn build_router() -> Router {
    ///     let stuff = ServeDir::new("assets");
    ///     Router::new()
    ///         .route_service("/*path", stuff) // route to be protected
    ///         .route_layer(ValidateRequestHeaderLayer::custom(
    ///             FileAuth::new(&mut File::open("htpasswd").await.unwrap()).await
    ///         ))
    /// }
    /// ```
    pub async fn new(file: &mut File) -> Self {
        let mut users = Vec::new();
        let mut raw_data = String::new();
        let res = file.read_to_string(&mut raw_data).await;
        if res.is_err() {
            panic!("Unable to read user secret file!");
        }

        let it = raw_data.split_terminator("\n");
        it.for_each(|x| {
            if x.starts_with("#") {
                return;
            }
            debug!("Adding user-password combination {}", &x);
            users.push(general_purpose::STANDARD.encode(x));
        });

        FileAuth {
            known_users: users,
            _ty: PhantomData,
        }
    }

    fn authorized(&self, auth: &str) -> bool {
        let mut it = auth.split_whitespace();
        let scheme = it.next();
        let credentials = it.next();

        match scheme {
            Some(scheme) if scheme == "Basic" => (),
            _ => {
                error!("Received wrong or no authentication scheme. Rejecting authentication attempt...");
                return false;
            }
        }

        match credentials {
            Some(credentials) if self.known_users.contains(&credentials.to_string()) => {
                debug!(
                    "Found matching credentials for authentication attempt: {}",
                    str::from_utf8(&general_purpose::STANDARD.decode(&credentials).unwrap())
                        .unwrap()
                );
                return true;
            }
            _ => {
                error!("Did not find matching credentials for authentication attempt");
                return false;
            }
        }
    }
}

impl<B, ResBody> ValidateRequest<B> for FileAuth<ResBody>
where
    ResBody: Body + Default,
{
    fn validate(&mut self, request: &mut Request<B>) -> Result<(), Response<Self::ResponseBody>> {
        match request.headers().get(header::AUTHORIZATION) {
            Some(actual) if self.authorized(&actual.to_str().unwrap()) => Ok(()),
            _ => {
                let mut res = Response::new(ResBody::default());
                *res.status_mut() = StatusCode::UNAUTHORIZED;
                res.headers_mut()
                    .insert(header::WWW_AUTHENTICATE, "Basic".parse().unwrap());
                Err(res)
            }
        }
    }

    type ResponseBody = ResBody;
}

impl<ResBody> Clone for FileAuth<ResBody> {
    fn clone(&self) -> Self {
        Self {
            known_users: self.known_users.clone(),
            _ty: PhantomData,
        }
    }
}
