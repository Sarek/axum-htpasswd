//! # Easy authentication for [`axum`]
//!
//! Provide an easy-to-use, simple, file-based authentication
//! mechanism for [`axum`]-based web applications modeled after
//! [`htpasswd`](https://httpd.apache.org/docs/2.4/programs/htpasswd.html)
//! files.

use argon2::Argon2;
use password_hash::{PasswordHash, PasswordVerifier};
use axum::http::{header, Request, Response, StatusCode};
use base64::{engine::general_purpose, Engine as _};
use http_body::Body;
use log::{debug, error, info};
use std::collections::HashMap;
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
    known_users: HashMap<String, String>,
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
        let mut users = HashMap::new();
        let mut raw_data = String::new();
        let res = file.read_to_string(&mut raw_data).await;
        if res.is_err() {
            panic!("Unable to read user secret file!");
        }

        let it = raw_data.split_terminator('\n');
        it.for_each(|x| {
            if x.starts_with('#') {
                return;
            }
            match x.find(':') {
                Some(pos) => {
                    debug!("Adding credentials: Username: {}, Password(-Hash): {}", &x[0..pos - 1], &x[pos + 1..]);
                    users.insert(x[0..pos-1].to_owned(), x[pos+1..].to_owned());
                },
                None => {
                    debug!("Username-Password Delimiter not found, skipping line \"{}\"", &x);
                }
            }
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
            Some("Basic") => (),
            _ => {
                error!("Received wrong or no authentication scheme. Rejecting authentication attempt...");
                return false;
            }
        }

        if let Some(credentials) = credentials {
            if let Ok(credentials) = general_purpose::STANDARD.decode(credentials) {
                if let Ok(credentials) = String::from_utf8(credentials) {
                    if let Some(pos) = credentials.find(':') {
                        if let Some(saved_password) = self.known_users.get(&credentials[0..pos-1]) {
                            if check_password(&*saved_password, &credentials[pos+1..]) {
                                info!("Correct password supplied for user {}", &credentials[0..pos-1]);
                                return true;
                            } else {
                                error!("Failed login attempt for user {}", &credentials[0..pos-1]);
                            }
                        } else {
                            error!("Failed login attempt for unknown user {}", &credentials[0..pos-1]);
                        }
                    } else {
                        error!("Could not extract username and password from supplied credentials");
                    }
                } else {
                    error!("Could not convert decoded credentials to string");
                }
            } else {
                error!("Failed to decode provided credentials");
            }
        } else {
            error!("Failed to interpret provided authentication data");
        }

        false
    }

}

impl<B, ResBody> ValidateRequest<B> for FileAuth<ResBody>
where
    ResBody: Body + Default,
{
    fn validate(&mut self, request: &mut Request<B>) -> Result<(), Response<Self::ResponseBody>> {
        match request.headers().get(header::AUTHORIZATION) {
            Some(actual) if self.authorized(actual.to_str().unwrap()) => Ok(()),
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

    fn clone_from(&mut self, source: &Self) {
        *self = source.clone()
    }
}

fn check_password(saved: &str, passed: &str) -> bool {
    match PasswordHash::new(&saved) {
        Ok(pw_hash) => {
            // The PHC string could be parsed, we can attempt to verify the password hashes
            let algs: &[&dyn PasswordVerifier] = &[&Argon2::default()];

            match pw_hash.verify_password(algs, passed) {
                Ok(_) => true,
                Err(e) => {
                    debug!("Error while verifying password: {}", e.to_string());
                    false
                },
            }
        },
        Err(_) => {
            // The PHC string could not be parsed. Let's assume it's a plaintext password and
            // try to verify it.
            if saved == passed {
                true
            } else {
                false
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use axum::response::Response;
    use simple_logger::SimpleLogger;
    use std::io::{SeekFrom, Write};
    use tempfile::tempfile;
    use tokio::io::AsyncSeekExt;

    use super::*;

    fn setup_logging() {
        use std::sync::Once;

        static LOGGER: Once = Once::new();

        LOGGER.call_once(|| {
            SimpleLogger::new()
                .with_colors(true)
                .with_level(log::LevelFilter::Debug)
                .env()
                .with_utc_timestamps()
                .init()
                .unwrap()
        });
    }

    async fn setup_plaintext_creds(credentials: Vec<&str>) -> Result<File, std::io::Error> {
        let mut htpasswd = tempfile()?;
        for cred in credentials.into_iter() {
            writeln!(htpasswd, "{}", &cred)?;
        }
        let mut htpasswd = tokio::fs::File::from_std(htpasswd);
        let _ = htpasswd.seek(SeekFrom::Start(0)).await;
        Ok(htpasswd)
    }

    async fn setup_argon2_creds(credentials: HashMap<&str, &str>) -> Result<File, std::io::Error> {
        use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
        let mut htpasswd = tempfile()?;
        for cred in credentials.into_iter() {
            let salt = SaltString::generate(&mut OsRng);
            let argon2 = Argon2::default();

            if let Ok(hash) = argon2.hash_password(cred.1.as_bytes(), &salt) {
                writeln!(htpasswd, "{}:{}", &cred.0, &hash)?
            } else {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Failed to hash provided password"));
            }
        }
        let mut htpasswd = tokio::fs::File::from_std(htpasswd);
        let _ = htpasswd.seek(SeekFrom::Start(0)).await;
        Ok(htpasswd)
    }

    #[tokio::test]
    async fn test_new() -> Result<(), std::io::Error> {
        let mut htpasswd = setup_plaintext_creds(vec!["foo:bar"]).await.unwrap();

        FileAuth::<Response>::new(&mut htpasswd).await;
        Ok(())
    }

    #[tokio::test]
    async fn test_plain_text_auth() -> Result<(), std::io::Error> {
        setup_logging();

        let cred = "foo:bar";
        let mut htpasswd = setup_plaintext_creds(vec![cred]).await.unwrap();

        let uut = FileAuth::<Response>::new(&mut htpasswd).await;

        let cred = general_purpose::STANDARD.encode(cred);
        assert!(uut.authorized(&("Basic ".to_owned() + &cred)));
        Ok(())
    }

    #[tokio::test]
    async fn test_argon2_auth() -> Result<(), std::io::Error> {
        setup_logging();

        let cred = HashMap::from([("foo", "bar")]);
        let mut htpasswd = setup_argon2_creds(cred).await.unwrap();

        let uut = FileAuth::<Response>::new(&mut htpasswd).await;

        let cred = general_purpose::STANDARD.encode("foo:bar");
        assert!(uut.authorized(&("Basic ".to_owned() + &cred)));
        Ok(())
    }

    #[tokio::test]
    async fn test_plain_text_auth_fails() -> Result<(), std::io::Error> {
        setup_logging();

        let cred = "foo:bar";
        let wrong_cred = "foo:baz";
        let mut htpasswd = setup_plaintext_creds(vec![wrong_cred]).await.unwrap();

        let uut = FileAuth::<Response>::new(&mut htpasswd).await;

        let cred = general_purpose::STANDARD.encode(cred);
        assert!(!uut.authorized(&("Basic ".to_owned() + &cred)));
        Ok(())
    }

    #[tokio::test]
    async fn test_argon2_auth_fails() -> Result<(), std::io::Error> {
        setup_logging();

        let cred = HashMap::from([("foo", "bar")]);
        let mut htpasswd = setup_argon2_creds(cred).await.unwrap();

        let uut = FileAuth::<Response>::new(&mut htpasswd).await;

        let cred = general_purpose::STANDARD.encode("foo:baz");
        assert!(!uut.authorized(&("Basic ".to_owned() + &cred)));
        Ok(())
    }
}
