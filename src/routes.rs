//! Routes mounted into Rocket
use std::ops::Deref;

use hyper;
use rocket::{self, State, Route};
use rocket::http::Method::*;

use auth;
use cors;
use token::{Token, PrivateClaim, Configuration, RefreshToken, Keys};

/// A wrapper around `cors::Options` for options specific to the token retrival route
pub struct TokenGetterCorsOptions(cors::Options);
impl_deref!(TokenGetterCorsOptions, cors::Options);

const TOKEN_GETTER_METHODS: &[rocket::http::Method] = &[Get];
const TOKEN_GETTER_HEADERS: &'static [&'static str] = &["Authorization"];

impl TokenGetterCorsOptions {
    pub fn new(config: &Configuration) -> Self {
        TokenGetterCorsOptions(cors::Options {
                                   allowed_origins: config.allowed_origins.clone(),
                                   allowed_methods: TOKEN_GETTER_METHODS.iter().cloned().collect(),
                                   allowed_headers: TOKEN_GETTER_HEADERS
                                       .iter()
                                       .map(|s| s.to_string().into())
                                       .collect(),
                                   allow_credentials: true,
                                   ..Default::default()
                               })
    }
}

#[derive(FromForm, Default, Clone, Debug)]
struct AuthParam {
    service: String,
    scope: String,
    offline_token: Option<bool>,
}

impl AuthParam {
    /// Verify the params are correct for the authentication type, that is if the authorization is a bearer token,
    /// then an offline token cannot be requested.
    fn verify<S: hyper::header::Scheme + 'static>(&self,
                                                  authorization: &auth::Authorization<S>)
                                                  -> Result<(), ::Error> {
        if authorization.is_bearer() && self.offline_token.is_some() {
            Err(::Error::BadRequest("Offline token cannot be requested for when authenticating with a refresh token"
                                        .to_string()))?
        }
        Ok(())
    }
}

/// CORS pre-flight route for access token retrieval via initial authentication and refresh token
#[allow(unmounted_route)]
// mounted via `::launch()`
#[options("/?<_auth_param>")]
#[allow(needless_pass_by_value)]
fn token_getter_options(origin: Option<cors::Origin>,
                        method: cors::AccessControlRequestMethod,
                        headers: cors::AccessControlRequestHeaders,
                        options: State<TokenGetterCorsOptions>,
                        _auth_param: AuthParam)
                        -> Result<cors::Response<()>, cors::Error> {
    options.preflight(origin, &method, Some(&headers))
}

/// Access token retrieval via initial authentication route
#[allow(unmounted_route)]
// mounted via `::launch()`
#[get("/?<auth_param>", rank = 1)]
#[allow(needless_pass_by_value)]
fn token_getter(origin: Option<cors::Origin>,
                authorization: auth::Authorization<auth::Basic>,
                auth_param: AuthParam,
                configuration: State<Configuration>,
                cors_options: State<TokenGetterCorsOptions>,
                keys: State<Keys>,
                authenticator: State<Box<auth::BasicAuthenticator>>)
                -> Result<cors::Response<Token<PrivateClaim>>, ::Error> {

    auth_param.verify(&authorization)?;
    authenticator
        .prepare_authentication_response(&authorization, auth_param.offline_token.unwrap_or(false))
        .and_then(|result| {
            let token = Token::<PrivateClaim>::with_configuration(&configuration,
                                                                  &result.subject,
                                                                  &auth_param.service,
                                                                  Default::default(),
                                                                  result.payload.as_ref())?;
            let signing_key = &keys.signing;
            let token = token.encode(signing_key)?;

            let token = if configuration.refresh_token_enabled() && token.has_refresh_token() {
                let refresh_token_key = keys.encryption
                    .as_ref()
                    .expect("Refresh token was enabled but encryption key is missing");
                token
                    .encrypt_refresh_token(signing_key, refresh_token_key)?
            } else {
                token
            };

            Ok(cors_options.respond(token, origin)?)
        })
}

/// Access token retrieval via refresh token route
#[allow(unmounted_route)]
// mounted via `::launch()`
#[get("/?<auth_param>", rank = 2)]
#[allow(needless_pass_by_value)]
fn refresh_token(origin: Option<cors::Origin>,
                 authorization: auth::Authorization<auth::Bearer>,
                 auth_param: AuthParam,
                 configuration: State<Configuration>,
                 cors_options: State<TokenGetterCorsOptions>,
                 keys: State<Keys>,
                 authenticator: State<Box<auth::BasicAuthenticator>>)
                 -> Result<cors::Response<Token<PrivateClaim>>, ::Error> {

    if !configuration.refresh_token_enabled() {
        return Err(::Error::BadRequest("Refresh token is not enabled".to_string()));
    }
    let refresh_token_configuration = configuration.refresh_token();

    auth_param.verify(&authorization)?;
    let refresh_token = RefreshToken::new_encrypted(&authorization.token());
    let refresh_token = refresh_token
        .decrypt(&keys.signature_verification,
                 keys.decryption
                     .as_ref()
                     .expect("Refresh token was enabled but decryption key is missing"),
                 configuration.signature_algorithm.unwrap_or_default(),
                 refresh_token_configuration.cek_algorithm,
                 refresh_token_configuration.enc_algorithm)?;

    refresh_token
        .validate(&auth_param.service, &configuration, None)?;

    authenticator
        .prepare_refresh_response(refresh_token.payload()?)
        .and_then(|result| {
            let token = Token::<PrivateClaim>::with_configuration(&configuration,
                                                                  &result.subject,
                                                                  &auth_param.service,
                                                                  Default::default(),
                                                                  None)?;
            let token = token.encode(&keys.signing)?;
            Ok(cors_options.respond(token, origin)?)
        })
}

/// Route to catch missing Authorization
#[allow(unmounted_route)]
// mounted via `::launch()`
#[get("/?<_auth_param>", rank = 3)]
#[allow(needless_pass_by_value)]
fn bad_request(_auth_param: AuthParam, configuration: State<Configuration>) -> Result<(), ::Error> {
    auth::missing_authorization(&configuration.issuer.to_string())
}

/// A simple "Ping Pong" route to check the health of the server
#[allow(unmounted_route)]
// mounted via `::launch()`
#[allow(needless_pass_by_value)]
#[get("/ping")]
fn ping() -> &'static str {
    "Pong"
}

/// Return routes provided by rowdy
pub fn routes() -> Vec<Route> {
    routes![token_getter,
            token_getter_options,
            refresh_token,
            bad_request,
            ping]
}

#[cfg(test)]
mod tests {
    use std::time::Duration;
    use std::str::FromStr;

    use hyper;
    use jwt;
    use rocket::Rocket;
    use rocket::http::{Header, Status};
    use rocket::http::Method::*;
    use rocket::testing::MockRequest;
    use serde_json;

    use ByteSequence;
    use super::*;
    use token::{Secret, RefreshTokenConfiguration};

    fn ignite() -> Rocket {
        // Ignite rocket
        let allowed_origins = ["https://www.example.com"];
        let (allowed_origins, _) = ::cors::AllowedOrigins::new_from_str_list(&allowed_origins);
        let token_configuration = Configuration {
            issuer: FromStr::from_str("https://www.acme.com").unwrap(),
            allowed_origins: allowed_origins,
            audience: jwt::SingleOrMultiple::Single(not_err!(FromStr::from_str("https://www.example.com"))),
            signature_algorithm: Some(jwt::jwa::SignatureAlgorithm::HS512),
            secret: Secret::ByteSequence(ByteSequence::String("secret".to_string())),
            expiry_duration: Duration::from_secs(120),
            refresh_token: Some(RefreshTokenConfiguration {
                                    cek_algorithm: jwt::jwa::KeyManagementAlgorithm::A256GCMKW,
                                    enc_algorithm: jwt::jwa::ContentEncryptionAlgorithm::A256GCM,
                                    key: Secret::ByteSequence(ByteSequence::Bytes(vec![0; 256/8])),
                                    expiry_duration: Duration::from_secs(86400),
                                }),
        };
        let configuration = ::Configuration {
            token: token_configuration,
            basic_authenticator: ::auth::tests::MockAuthenticatorConfiguration {},
        };

        let rocket = not_err!(configuration.ignite());
        rocket.mount("/", routes())
    }

    #[test]
    fn ping_pong() {
        let rocket = ignite();

        let mut req = MockRequest::new(Get, "/ping");
        let mut response = req.dispatch_with(&rocket);
        let body_str = not_none!(response.body().and_then(|body| body.into_string()));

        assert_eq!("Pong", body_str);
    }

    #[test]
    fn token_getter_options_test() {
        let rocket = ignite();

        // Make headers
        let origin_header = Header::from(not_err!(hyper::header::Origin::from_str("https://www.example.com")));
        let method_header = Header::from(hyper::header::AccessControlRequestMethod(hyper::method::Method::Get));
        let request_headers = hyper::header::AccessControlRequestHeaders(vec![FromStr::from_str("Authorization")
                                                                                  .unwrap()]);
        let request_headers = Header::from(request_headers);

        // Make and dispatch request
        let mut req = MockRequest::new(Options, "/?service=https://www.example.com&scope=all")
            .header(origin_header)
            .header(method_header)
            .header(request_headers);
        let response = req.dispatch_with(&rocket);

        // Assert
        assert_eq!(response.status(), Status::Ok);
    }

    #[test]
    #[allow(deprecated)]
    fn token_getter_get_test() {
        let rocket = ignite();

        // Make headers
        let origin_header = Header::from(not_err!(hyper::header::Origin::from_str("https://www.example.com")));
        let auth_header = hyper::header::Authorization(auth::Basic {
                                                           username: "mei".to_owned(),
                                                           password: Some("冻住，不许走!".to_string()),
                                                       });
        let auth_header = Header::new("Authorization",
                                      hyper::header::HeaderFormatter(&auth_header).to_string());
        // Make and dispatch request
        let mut req = MockRequest::new(Get, "/?service=https://www.example.com&scope=all")
            .header(origin_header)
            .header(auth_header);
        let mut response = req.dispatch_with(&rocket);

        // Assert
        assert_eq!(response.status(), Status::Ok);
        let body_str = not_none!(response.body().and_then(|body| body.into_string()));

        let deserialized: Token<PrivateClaim> = not_err!(serde_json::from_str(&body_str));
        let actual_token = not_err!(deserialized.decode(&jwt::jws::Secret::bytes_from_str("secret"),
                                                        jwt::jwa::SignatureAlgorithm::HS512));

        assert!(actual_token.refresh_token.is_none());

        let registered = not_err!(actual_token.registered_claims());
        assert_eq!(Some(FromStr::from_str("https://www.acme.com").unwrap()),
                   registered.issuer);
        assert_eq!(Some(jwt::SingleOrMultiple::Single(FromStr::from_str("https://www.example.com").unwrap())),
                   registered.audience);

        // TODO: Test private claims

        let header = not_err!(actual_token.header());
        assert_eq!(header.registered.algorithm,
                   jwt::jwa::SignatureAlgorithm::HS512);
    }

    #[test]
    #[allow(deprecated)]
    fn token_getter_get_invalid_credentials() {
        // Ignite rocket
        let rocket = ignite();

        // Make headers
        let origin_header = Header::from(not_err!(hyper::header::Origin::from_str("https://www.example.com")));
        let auth_header = hyper::header::Authorization(auth::Basic {
                                                           username: "Aladin".to_owned(),
                                                           password: Some("let me in".to_string()),
                                                       });
        let auth_header = Header::new("Authorization",
                                      hyper::header::HeaderFormatter(&auth_header).to_string());
        // Make and dispatch request
        let mut req = MockRequest::new(Get, "/?service=https://www.example.com&scope=all")
            .header(origin_header)
            .header(auth_header);
        let response = req.dispatch_with(&rocket);

        // Assert
        assert_eq!(response.status(), Status::Unauthorized);
    }

    #[test]
    #[allow(deprecated)]
    fn token_getter_get_missing_credentials() {
        // Ignite rocket
        let rocket = ignite();

        // Make headers
        let origin_header = Header::from(not_err!(hyper::header::Origin::from_str("https://www.example.com")));

        // Make and dispatch request
        let mut req = MockRequest::new(Get, "/?service=https://www.example.com&scope=all").header(origin_header);
        let response = req.dispatch_with(&rocket);

        // Assert
        assert_eq!(response.status(), Status::Unauthorized);

        let www_header: Vec<_> = response.header_values("WWW-Authenticate").collect();
        assert_eq!(www_header, vec!["Basic realm=https://www.acme.com/"]);
    }

    #[test]
    #[allow(deprecated)]
    fn token_getter_get_invalid_service() {
        // Ignite rocket
        let rocket = ignite();

        // Make headers
        let origin_header = Header::from(not_err!(hyper::header::Origin::from_str("https://www.example.com")));
        let auth_header = hyper::header::Authorization(auth::Basic {
                                                           username: "mei".to_owned(),
                                                           password: Some("冻住，不许走!".to_string()),
                                                       });
        let auth_header = Header::new("Authorization",
                                      hyper::header::HeaderFormatter(&auth_header).to_string());
        // Make and dispatch request
        let mut req = MockRequest::new(Get, "/?service=foobar&scope=all")
            .header(origin_header)
            .header(auth_header);
        let response = req.dispatch_with(&rocket);

        // Assert
        assert_eq!(response.status(), Status::Forbidden);
    }

    /// Tests that we can request a refresh token and then get a new access token with the issued refresh token
    #[test]
    #[allow(deprecated)]
    fn token_getter_with_refresh_token_round_trip() {
        let rocket = ignite();

        // Initial authentication request
        // Make headers
        let origin_header = Header::from(not_err!(hyper::header::Origin::from_str("https://www.example.com")));
        let auth_header = hyper::header::Authorization(auth::Basic {
                                                           username: "mei".to_owned(),
                                                           password: Some("冻住，不许走!".to_string()),
                                                       });
        let auth_header = Header::new("Authorization",
                                      hyper::header::HeaderFormatter(&auth_header).to_string());
        // Make and dispatch request
        let mut req = MockRequest::new(Get,
                                       "/?service=https://www.example.com&scope=all&offline_token=true")
                .header(origin_header)
                .header(auth_header);
        let mut response = req.dispatch_with(&rocket);

        // Assert
        assert_eq!(response.status(), Status::Ok);
        let body_str = not_none!(response.body().and_then(|body| body.into_string()));

        let deserialized: Token<PrivateClaim> = not_err!(serde_json::from_str(&body_str));
        let actual_token = not_err!(deserialized.decode(&jwt::jws::Secret::bytes_from_str("secret"),
                                                        jwt::jwa::SignatureAlgorithm::HS512));

        let refresh_token = actual_token.refresh_token.unwrap();

        // Use refresh token to authenticate
        let origin_header = Header::from(not_err!(hyper::header::Origin::from_str("https://www.example.com")));
        let auth_header = hyper::header::Authorization(auth::Bearer { token: refresh_token.to_string().unwrap() });
        let auth_header = Header::new("Authorization",
                                      hyper::header::HeaderFormatter(&auth_header).to_string());
        // Make and dispatch request
        let mut req = MockRequest::new(Get, "/?service=https://www.example.com&scope=all")
            .header(origin_header)
            .header(auth_header);
        let mut response = req.dispatch_with(&rocket);

        // Assert
        assert_eq!(response.status(), Status::Ok);
        let body_str = not_none!(response.body().and_then(|body| body.into_string()));

        let deserialized: Token<PrivateClaim> = not_err!(serde_json::from_str(&body_str));
        let actual_token = not_err!(deserialized.decode(&jwt::jws::Secret::bytes_from_str("secret"),
                                                        jwt::jwa::SignatureAlgorithm::HS512));
        assert!(actual_token.refresh_token.is_none());

        let registered = not_err!(actual_token.registered_claims());
        assert_eq!(Some(FromStr::from_str("https://www.acme.com").unwrap()),
                   registered.issuer);
        assert_eq!(Some(jwt::SingleOrMultiple::Single(FromStr::from_str("https://www.example.com").unwrap())),
                   registered.audience);

        // TODO: Test private claims

        let header = not_err!(actual_token.header());
        assert_eq!(header.registered.algorithm,
                   jwt::jwa::SignatureAlgorithm::HS512);
    }

    /// Requesting for a refresh token when using a refresh token to authenticate should result in Bad Request
    #[test]
    #[allow(deprecated)]
    fn token_refresh_with_offline_token_should_return_bad_request() {
        let rocket = ignite();

        let origin_header = Header::from(not_err!(hyper::header::Origin::from_str("https://www.example.com")));
        let auth_header = hyper::header::Authorization(auth::Bearer { token: "foobar".to_string() });
        let auth_header = Header::new("Authorization",
                                      hyper::header::HeaderFormatter(&auth_header).to_string());
        // Make and dispatch request
        let mut req = MockRequest::new(Get,
                                       "/?service=https://www.example.com&scope=all&offline_token=true")
                .header(origin_header)
                .header(auth_header);
        let response = req.dispatch_with(&rocket);

        // Assert
        assert_eq!(response.status(), Status::BadRequest);
    }
}
