//! Routes mounted into Rocket

// mounted via `::launch()`
#![allow(unmounted_route)]

use hyper;
use rocket::{State, Route};

use auth;
use token::{Token, PrivateClaim, Configuration, RefreshToken, Keys};

#[derive(FromForm, Default, Clone, Debug)]
struct AuthParam {
    service: String,
    scope: String,
    offline_token: Option<bool>,
}

impl AuthParam {
    /// Verify the params are correct for the authentication type, that is if the authorization is a bearer token,
    /// then an offline token cannot be requested.
    fn verify<S: hyper::header::Scheme + 'static>(
        &self,
        authorization: &auth::Authorization<S>,
    ) -> Result<(), ::Error> {
        if authorization.is_bearer() && self.offline_token.is_some() {
            Err(::Error::BadRequest(
                "Offline token cannot be requested for when authenticating with a refresh token"
                    .to_string(),
            ))?
        }
        Ok(())
    }
}

/// Access token retrieval via initial authentication route
#[get("/?<auth_param>", rank = 1)]
fn token_getter(
    authorization: auth::Authorization<auth::Basic>,
    auth_param: AuthParam,
    configuration: State<Configuration>,
    keys: State<Keys>,
    authenticator: State<Box<auth::BasicAuthenticator>>,
) -> Result<Token<PrivateClaim>, ::Error> {

    auth_param.verify(&authorization)?;
    authenticator
        .prepare_authentication_response(&authorization, auth_param.offline_token.unwrap_or(false))
        .and_then(|result| {
            let token = Token::<PrivateClaim>::with_configuration(
                &configuration,
                &result.subject,
                &auth_param.service,
                result.private_claims.clone(),
                result.refresh_payload.as_ref(),
            )?;
            let signing_key = &keys.signing;
            let token = token.encode(signing_key)?;

            let token = if configuration.refresh_token_enabled() && token.has_refresh_token() {
                let refresh_token_key = keys.encryption.as_ref().expect(
                    "Refresh token was enabled but encryption key is missing",
                );
                token.encrypt_refresh_token(signing_key, refresh_token_key)?
            } else {
                token
            };

            Ok(token)
        })
}

/// Access token retrieval via refresh token route
#[get("/?<auth_param>", rank = 2)]
fn refresh_token(
    authorization: auth::Authorization<auth::Bearer>,
    auth_param: AuthParam,
    configuration: State<Configuration>,
    keys: State<Keys>,
    authenticator: State<Box<auth::BasicAuthenticator>>,
) -> Result<Token<PrivateClaim>, ::Error> {

    if !configuration.refresh_token_enabled() {
        return Err(::Error::BadRequest(
            "Refresh token is not enabled".to_string(),
        ));
    }
    let refresh_token_configuration = configuration.refresh_token();

    auth_param.verify(&authorization)?;
    let refresh_token = RefreshToken::new_encrypted(&authorization.token());
    let refresh_token = refresh_token.decrypt(
        &keys.signature_verification,
        keys.decryption.as_ref().expect(
            "Refresh token was enabled but decryption key is missing",
        ),
        configuration
            .signature_algorithm
            .unwrap_or_default(),
        refresh_token_configuration.cek_algorithm,
        refresh_token_configuration.enc_algorithm,
    )?;

    refresh_token.validate(
        &auth_param.service,
        &configuration,
        None,
    )?;

    authenticator
        .prepare_refresh_response(refresh_token.payload()?)
        .and_then(|result| {
            let token = Token::<PrivateClaim>::with_configuration(
                &configuration,
                &result.subject,
                &auth_param.service,
                result.private_claims.clone(),
                None,
            )?;
            let token = token.encode(&keys.signing)?;
            Ok(token)
        })
}

/// Route to catch missing Authorization
#[get("/?<auth_param>", rank = 3)]
fn bad_request(auth_param: AuthParam, configuration: State<Configuration>) -> Result<(), ::Error> {
    let _ = auth_param;
    auth::missing_authorization(&configuration.issuer.to_string())
}

/// A simple "Ping Pong" route to check the health of the server
#[get("/ping")]
fn ping() -> &'static str {
    "Pong"
}

/// Return routes provided by rowdy
pub fn routes() -> Vec<Route> {
    routes![
        token_getter,
        refresh_token,
        bad_request,
        ping,
    ]
}

#[cfg(test)]
mod tests {
    use std::time::Duration;
    use std::str::FromStr;

    use hyper;
    use jwt;
    use rocket::Rocket;
    use rocket::http::{Header, Status};
    use rocket::local::Client;
    use serde_json;

    use ByteSequence;
    use super::*;
    use token::{Secret, RefreshTokenConfiguration};

    fn ignite() -> Rocket {
        // Ignite rocket
        let allowed_origins = ["https://www.example.com"];
        let (allowed_origins, _) = ::cors::AllOrSome::new_from_str_list(&allowed_origins);
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
                key: Secret::ByteSequence(ByteSequence::Bytes(vec![0; 256 / 8])),
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
        let client = not_err!(Client::new(rocket));

        let req = client.get("/ping");
        let mut response = req.dispatch();
        let body_str = not_none!(response.body().and_then(|body| body.into_string()));

        assert_eq!("Pong", body_str);
    }

    #[test]
    fn token_getter_options_test() {
        let rocket = ignite();
        let client = not_err!(Client::new(rocket));

        // Make headers
        let origin_header = Header::from(not_err!(
            hyper::header::Origin::from_str("https://www.example.com")
        ));
        let method_header = Header::from(hyper::header::AccessControlRequestMethod(
            hyper::method::Method::Get,
        ));
        let request_headers =
            hyper::header::AccessControlRequestHeaders(vec![FromStr::from_str("Authorization").unwrap()]);
        let request_headers = Header::from(request_headers);

        // Make and dispatch request
        let req = client
            .options("/?service=https://www.example.com&scope=all")
            .header(origin_header)
            .header(method_header)
            .header(request_headers);
        let response = req.dispatch();

        // Assert
        assert!(response.status().class().is_success());
        let origin_header = response
            .headers()
            .get_one("Access-Control-Allow-Origin")
            .expect("to exist");
        assert_eq!("https://www.example.com/", origin_header);
    }

    #[test]
    #[allow(deprecated)]
    fn token_getter_get_test() {
        let rocket = ignite();
        let client = not_err!(Client::new(rocket));

        // Make headers
        let origin_header = Header::from(not_err!(
            hyper::header::Origin::from_str("https://www.example.com")
        ));
        let auth_header = hyper::header::Authorization(auth::Basic {
            username: "mei".to_owned(),
            password: Some("冻住，不许走!".to_string()),
        });
        let auth_header = Header::new(
            "Authorization",
            hyper::header::HeaderFormatter(&auth_header).to_string(),
        );
        // Make and dispatch request
        let req = client
            .get("/?service=https://www.example.com&scope=all")
            .header(origin_header)
            .header(auth_header);
        let mut response = req.dispatch();

        // Assert
        assert!(response.status().class().is_success());
        let body_str = not_none!(response.body().and_then(|body| body.into_string()));
        let origin_header = response
            .headers()
            .get_one("Access-Control-Allow-Origin")
            .expect("to exist");
        assert_eq!("https://www.example.com/", origin_header);

        let deserialized: Token<PrivateClaim> = not_err!(serde_json::from_str(&body_str));
        let actual_token = not_err!(deserialized.decode(
            &jwt::jws::Secret::bytes_from_str("secret"),
            jwt::jwa::SignatureAlgorithm::HS512,
        ));

        assert!(actual_token.refresh_token.is_none());

        let registered = not_err!(actual_token.registered_claims());
        assert_eq!(
            Some(FromStr::from_str("https://www.acme.com").unwrap()),
            registered.issuer
        );
        assert_eq!(
            Some(jwt::SingleOrMultiple::Single(
                FromStr::from_str("https://www.example.com").unwrap(),
            )),
            registered.audience
        );

        // TODO: Test private claims

        let header = not_err!(actual_token.header());
        assert_eq!(
            header.registered.algorithm,
            jwt::jwa::SignatureAlgorithm::HS512
        );
    }

    #[test]
    #[allow(deprecated)]
    fn token_getter_get_invalid_credentials() {
        // Ignite rocket
        let rocket = ignite();
        let client = not_err!(Client::new(rocket));

        // Make headers
        let origin_header = Header::from(not_err!(
            hyper::header::Origin::from_str("https://www.example.com")
        ));
        let auth_header = hyper::header::Authorization(auth::Basic {
            username: "Aladin".to_owned(),
            password: Some("let me in".to_string()),
        });
        let auth_header = Header::new(
            "Authorization",
            hyper::header::HeaderFormatter(&auth_header).to_string(),
        );
        // Make and dispatch request
        let req = client
            .get("/?service=https://www.example.com&scope=all")
            .header(origin_header)
            .header(auth_header);
        let response = req.dispatch();

        // Assert
        assert_eq!(response.status(), Status::Unauthorized);
        let origin_header = response
            .headers()
            .get_one("Access-Control-Allow-Origin")
            .expect("to exist");
        assert_eq!("https://www.example.com/", origin_header);
    }

    #[test]
    #[allow(deprecated)]
    fn token_getter_get_missing_credentials() {
        // Ignite rocket
        let rocket = ignite();
        let client = not_err!(Client::new(rocket));

        // Make headers
        let origin_header = Header::from(not_err!(
            hyper::header::Origin::from_str("https://www.example.com")
        ));

        // Make and dispatch request
        let req = client
            .get("/?service=https://www.example.com&scope=all")
            .header(origin_header);
        let response = req.dispatch();

        // Assert
        assert_eq!(response.status(), Status::Unauthorized);
        let origin_header = response
            .headers()
            .get_one("Access-Control-Allow-Origin")
            .expect("to exist");
        assert_eq!("https://www.example.com/", origin_header);

        let www_header: Vec<_> = response.headers().get("WWW-Authenticate").collect();
        assert_eq!(www_header, vec!["Basic realm=https://www.acme.com/"]);
    }

    #[test]
    #[allow(deprecated)]
    fn token_getter_get_invalid_service() {
        // Ignite rocket
        let rocket = ignite();
        let client = not_err!(Client::new(rocket));

        // Make headers
        let origin_header = Header::from(not_err!(
            hyper::header::Origin::from_str("https://www.example.com")
        ));
        let auth_header = hyper::header::Authorization(auth::Basic {
            username: "mei".to_owned(),
            password: Some("冻住，不许走!".to_string()),
        });
        let auth_header = Header::new(
            "Authorization",
            hyper::header::HeaderFormatter(&auth_header).to_string(),
        );
        // Make and dispatch request
        let req = client
            .get("/?service=foobar&scope=all")
            .header(origin_header)
            .header(auth_header);
        let response = req.dispatch();

        // Assert
        assert_eq!(response.status(), Status::Forbidden);
        let origin_header = response
            .headers()
            .get_one("Access-Control-Allow-Origin")
            .expect("to exist");
        assert_eq!("https://www.example.com/", origin_header);
    }

    /// Tests that we can request a refresh token and then get a new access token with the issued refresh token
    #[test]
    #[allow(deprecated)]
    fn token_getter_with_refresh_token_round_trip() {
        let rocket = ignite();
        let client = not_err!(Client::new(rocket));

        // Initial authentication request
        // Make headers
        let origin_header = Header::from(not_err!(
            hyper::header::Origin::from_str("https://www.example.com")
        ));
        let auth_header = hyper::header::Authorization(auth::Basic {
            username: "mei".to_owned(),
            password: Some("冻住，不许走!".to_string()),
        });
        let auth_header = Header::new(
            "Authorization",
            hyper::header::HeaderFormatter(&auth_header).to_string(),
        );
        // Make and dispatch request
        let req = client
            .get(
                "/?service=https://www.example.com&scope=all&offline_token=true",
            )
            .header(origin_header)
            .header(auth_header);
        let mut response = req.dispatch();

        // Assert
        assert!(response.status().class().is_success());
        let body_str = not_none!(response.body().and_then(|body| body.into_string()));
        let origin_header = response
            .headers()
            .get_one("Access-Control-Allow-Origin")
            .expect("to exist");
        assert_eq!("https://www.example.com/", origin_header);

        let deserialized: Token<PrivateClaim> = not_err!(serde_json::from_str(&body_str));
        let actual_token = not_err!(deserialized.decode(
            &jwt::jws::Secret::bytes_from_str("secret"),
            jwt::jwa::SignatureAlgorithm::HS512,
        ));

        let refresh_token = actual_token.refresh_token.unwrap();

        // Use refresh token to authenticate
        let origin_header = Header::from(not_err!(
            hyper::header::Origin::from_str("https://www.example.com")
        ));
        let auth_header = hyper::header::Authorization(auth::Bearer { token: refresh_token.to_string().unwrap() });
        let auth_header = Header::new(
            "Authorization",
            hyper::header::HeaderFormatter(&auth_header).to_string(),
        );
        // Make and dispatch request
        let req = client
            .get("/?service=https://www.example.com&scope=all")
            .header(origin_header)
            .header(auth_header);
        let mut response = req.dispatch();

        // Assert
        assert!(response.status().class().is_success());
        let body_str = not_none!(response.body().and_then(|body| body.into_string()));
        let origin_header = response
            .headers()
            .get_one("Access-Control-Allow-Origin")
            .expect("to exist");
        assert_eq!("https://www.example.com/", origin_header);

        let deserialized: Token<PrivateClaim> = not_err!(serde_json::from_str(&body_str));
        let actual_token = not_err!(deserialized.decode(
            &jwt::jws::Secret::bytes_from_str("secret"),
            jwt::jwa::SignatureAlgorithm::HS512,
        ));
        assert!(actual_token.refresh_token.is_none());

        let registered = not_err!(actual_token.registered_claims());
        assert_eq!(
            Some(FromStr::from_str("https://www.acme.com").unwrap()),
            registered.issuer
        );
        assert_eq!(
            Some(jwt::SingleOrMultiple::Single(
                FromStr::from_str("https://www.example.com").unwrap(),
            )),
            registered.audience
        );

        // TODO: Test private claims

        let header = not_err!(actual_token.header());
        assert_eq!(
            header.registered.algorithm,
            jwt::jwa::SignatureAlgorithm::HS512
        );
    }

    /// Requesting for a refresh token when using a refresh token to authenticate should result in Bad Request
    #[test]
    #[allow(deprecated)]
    fn token_refresh_with_offline_token_should_return_bad_request() {
        let rocket = ignite();
        let client = not_err!(Client::new(rocket));

        let origin_header = Header::from(not_err!(
            hyper::header::Origin::from_str("https://www.example.com")
        ));
        let auth_header = hyper::header::Authorization(auth::Bearer { token: "foobar".to_string() });
        let auth_header = Header::new(
            "Authorization",
            hyper::header::HeaderFormatter(&auth_header).to_string(),
        );
        // Make and dispatch request
        let req = client
            .get(
                "/?service=https://www.example.com&scope=all&offline_token=true",
            )
            .header(origin_header)
            .header(auth_header);
        let response = req.dispatch();

        // Assert
        assert_eq!(response.status(), Status::BadRequest);
        let origin_header = response
            .headers()
            .get_one("Access-Control-Allow-Origin")
            .expect("to exist");
        assert_eq!("https://www.example.com/", origin_header);
    }
}
