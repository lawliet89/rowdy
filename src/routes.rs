//! Routes mounted into Rocket
use std::ops::Deref;

use hyper;
use rocket::{self, State};
use rocket::http::Method::*;

use auth;
use cors;
use token::{Token, PrivateClaim};

pub struct TokenGetterCorsOptions(cors::Options);
impl_deref!(TokenGetterCorsOptions, cors::Options);

const TOKEN_GETTER_METHODS: &[rocket::http::Method] = &[Get];
const TOKEN_GETTER_HEADERS: &'static [&'static str] = &["Authorization"];

impl TokenGetterCorsOptions {
    pub fn new(config: &::Configuration) -> Self {
        TokenGetterCorsOptions(cors::Options {
                                   allowed_origins: config.allowed_origins.clone(),
                                   allowed_methods: TOKEN_GETTER_METHODS.iter().cloned().collect(),
                                   allowed_headers: TOKEN_GETTER_HEADERS.iter().map(|s| s.to_string().into()).collect(),
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

#[allow(unmounted_route)]
// mounted via `::launch()`
#[options("/?<_auth_param>")]
#[allow(needless_pass_by_value)]
fn token_getter_options(origin: cors::Origin,
                        method: cors::AccessControlRequestMethod,
                        headers: cors::AccessControlRequestHeaders,
                        options: State<TokenGetterCorsOptions>,
                        _auth_param: AuthParam)
                        -> Result<cors::Response<()>, cors::Error> {
    options.preflight(&origin, &method, Some(&headers))
}

#[allow(unmounted_route)]
// mounted via `::launch()`
#[get("/?<_auth_param>")]
#[allow(needless_pass_by_value)]
fn token_getter(origin: cors::Origin,
                authorization: Option<auth::Authorization<hyper::header::Basic>>,
                _auth_param: AuthParam,
                configuration: State<::Configuration>,
                cors_options: State<TokenGetterCorsOptions>,
                authenticator: State<Box<auth::BasicAuthenticator>>)
                -> Result<cors::Response<Token<PrivateClaim>>, ::Error> {

    authenticator.prepare_response(&configuration.issuer, authorization).and_then(|authorization| {
        let token = Token::<PrivateClaim>::with_configuration(&configuration,
                                                              &authorization.username(),
                                                              Default::default())?;
        let token = token.encode(configuration.secret.for_signing()?)?;
        Ok(cors_options.respond(token, &origin)?)
    })
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

    use super::*;
    use token::Secret;

    fn make_authenticator() -> Box<auth::BasicAuthenticator> {
        Box::new(::auth::tests::MockAuthenticator {})
    }

    fn ignite() -> Rocket {
        // Ignite rocket
        let allowed_origins = ["https://www.example.com"];
        let (allowed_origins, _) = ::cors::AllowedOrigins::new_from_str_list(&allowed_origins);
        let configuration = ::Configuration {
            issuer: "https://www.acme.com".to_string(),
            allowed_origins: allowed_origins,
            audience: Some(jwt::SingleOrMultipleStrings::Single("https://www.example.com".to_string())),
            signature_algorithm: Some(jwt::jws::Algorithm::HS512),
            secret: Secret::String("secret".to_string()),
            expiry_duration: Duration::from_secs(120),
        };
        let token_getter_cors_options = TokenGetterCorsOptions::new(&configuration);

        rocket::ignite()
            .mount("/",
                   routes![::routes::token_getter_options, ::routes::token_getter])
            .manage(configuration)
            .manage(make_authenticator())
            .manage(token_getter_cors_options)
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
        let mut req = MockRequest::new(Options, "/?service=foobar&scope=all")
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
        let auth_header = hyper::header::Authorization(hyper::header::Basic {
                                                           username: "mei".to_owned(),
                                                           password: Some("冻住，不许走!".to_string()),
                                                       });
        let auth_header = Header::new("Authorization",
                                      format!("{}", hyper::header::HeaderFormatter(&auth_header)));
        // Make and dispatch request
        let mut req = MockRequest::new(Get, "/?service=foobar&scope=all").header(origin_header).header(auth_header);
        let mut response = req.dispatch_with(&rocket);

        // Assert
        assert_eq!(response.status(), Status::Ok);
        let body_str = not_none!(response.body().and_then(|body| body.into_string()));

        let deserialized: Token<PrivateClaim> = not_err!(serde_json::from_str(&body_str));
        let actual_token = not_err!(deserialized.decode(jwt::jws::Secret::bytes_from_str("secret"),
                                                        jwt::jws::Algorithm::HS512));

        let registered = not_err!(actual_token.registered_claims());

        assert_eq!(Some("https://www.acme.com".to_string()), registered.issuer);
        assert_eq!(Some(jwt::SingleOrMultipleStrings::Single("https://www.example.com".to_string())),
                   registered.audience);

        // TODO: Test private claims

        let header = not_err!(actual_token.header());
        assert_eq!(header.algorithm, jwt::jws::Algorithm::HS512);
    }

    #[test]
    #[allow(deprecated)]
    fn token_getter_get_invalid_credentials() {
        // Ignite rocket
        let rocket = ignite();

        // Make headers
        let origin_header = Header::from(not_err!(hyper::header::Origin::from_str("https://www.example.com")));
        let auth_header = hyper::header::Authorization(hyper::header::Basic {
                                                           username: "Aladin".to_owned(),
                                                           password: Some("let me in".to_string()),
                                                       });
        let auth_header = Header::new("Authorization",
                                      format!("{}", hyper::header::HeaderFormatter(&auth_header)));
        // Make and dispatch request
        let mut req = MockRequest::new(Get, "/?service=foobar&scope=all").header(origin_header).header(auth_header);
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
        let mut req = MockRequest::new(Get, "/?service=foobar&scope=all").header(origin_header);
        let response = req.dispatch_with(&rocket);

        // Assert
        assert_eq!(response.status(), Status::Unauthorized);

        let www_header: Vec<_> = response.header_values("WWW-Authenticate").collect();
        assert_eq!(www_header, vec!["Basic realm=https://www.acme.com"]);
    }
}
