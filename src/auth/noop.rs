//! A "no-op" authenticator that lets everything through
use hyper::header::{self, Header};

use {JsonValue, JsonMap, Error};
use super::{Basic, Bearer, Authenticator, Authorization, AuthenticatorConfiguration, AuthenticationResult};

/// A "no-op" authenticator that lets everything through. _DO NOT USE THIS IN PRODUCTION_.
#[derive(Debug)]
pub struct NoOp {}

impl NoOp {
    #[allow(deprecated)]
    fn format<S: header::Scheme + 'static>(authorization: &header::Authorization<S>) -> String {
        header::HeaderFormatter(authorization).to_string()
    }

    /// Generate a refresh token payload from the header
    fn serialize_refresh_token_payload<S: header::Scheme + 'static>(authorization: &header::Authorization<S>)
                                                                    -> JsonValue {
        let string = From::from(Self::format(authorization));
        let mut map = JsonMap::with_capacity(1);
        map.insert("header".to_string(), string);
        JsonValue::Object(map)
    }

    /// From a refresh token payload, retrieve the headr
    fn deserialize_refresh_token_payload<S: header::Scheme + 'static>(refresh_payload: &JsonValue)
                                                                      -> Result<header::Authorization<S>, Error> {
        match *refresh_payload {
            JsonValue::Object(ref map) => {
                let header = map.get("header")
                    .ok_or_else(|| Error::Auth(super::Error::AuthenticationFailure))?
                    .as_str()
                    .ok_or_else(|| Error::Auth(super::Error::AuthenticationFailure))?;
                let header = header.as_bytes().to_vec();
                let header: header::Authorization<S> =
                    header::Authorization::parse_header(&[header])
                        .map_err(|_| Error::Auth(super::Error::AuthenticationFailure))?;
                Ok(header)
            }
            _ => Err(Error::Auth(super::Error::AuthenticationFailure)),
        }
    }
}

impl Authenticator<Basic> for NoOp {
    fn authenticate(&self,
                    authorization: &Authorization<Basic>,
                    include_refresh_payload: bool)
                    -> Result<AuthenticationResult, Error> {
        warn_!("Do not use the NoOp authenticator in production");
        let refresh_payload = if include_refresh_payload {
            Some(Self::serialize_refresh_token_payload(authorization))
        } else {
            None
        };
        Ok(AuthenticationResult {
               subject: authorization.username(),
               private_claims: JsonValue::Object(JsonMap::new()),
               refresh_payload,
           })
    }

    fn authenticate_refresh_token(&self, refresh_payload: &JsonValue) -> Result<AuthenticationResult, ::Error> {
        warn_!("Do not use the NoOp authenticator in production");
        let header: header::Authorization<Basic> = Self::deserialize_refresh_token_payload(refresh_payload)?;
        self.authenticate(&Authorization(header), false)
    }
}

impl Authenticator<Bearer> for NoOp {
    fn authenticate(&self,
                    authorization: &Authorization<Bearer>,
                    include_refresh_payload: bool)
                    -> Result<AuthenticationResult, Error> {
        warn_!("Do not use the NoOp authenticator in production");
        let refresh_payload = if include_refresh_payload {
            Some(Self::serialize_refresh_token_payload(authorization))
        } else {
            None
        };
        Ok(AuthenticationResult {
               subject: authorization.token(),
               private_claims: JsonValue::Object(JsonMap::new()),
               refresh_payload,
           })
    }

    fn authenticate_refresh_token(&self, refresh_payload: &JsonValue) -> Result<AuthenticationResult, ::Error> {
        warn_!("Do not use the NoOp authenticator in production");
        let header: header::Authorization<Bearer> = Self::deserialize_refresh_token_payload(refresh_payload)?;
        self.authenticate(&Authorization(header), false)
    }
}

impl Authenticator<String> for NoOp {
    fn authenticate(&self,
                    authorization: &Authorization<String>,
                    include_refresh_payload: bool)
                    -> Result<AuthenticationResult, Error> {
        warn_!("Do not use the NoOp authenticator in production");
        let refresh_payload = if include_refresh_payload {
            Some(Self::serialize_refresh_token_payload(authorization))
        } else {
            None
        };
        Ok(AuthenticationResult {
               subject: authorization.string(),
               private_claims: JsonValue::Object(JsonMap::new()),
               refresh_payload,
           })
    }

    fn authenticate_refresh_token(&self, refresh_payload: &JsonValue) -> Result<AuthenticationResult, ::Error> {
        warn_!("Do not use the NoOp authenticator in production");
        let header: header::Authorization<String> = Self::deserialize_refresh_token_payload(refresh_payload)?;
        self.authenticate(&Authorization(header), false)
    }
}

/// Configuration for the `no-op` authenticator. Nothing to configure.
#[derive(Serialize, Deserialize, Debug)]
pub struct NoOpConfiguration {}

impl<S: header::Scheme + 'static> AuthenticatorConfiguration<S> for NoOpConfiguration
    where NoOp: Authenticator<S>
{
    type Authenticator = NoOp;

    fn make_authenticator(&self) -> Result<Self::Authenticator, ::Error> {
        Ok(Self::Authenticator {})
    }
}

#[cfg(test)]
pub mod tests {
    use hyper;
    use rocket::http::{self, Status};
    use rocket::http::Method::Get;
    use rocket::testing::MockRequest;

    use auth::Authenticator;
    use super::*;
    use super::super::tests::{ignite_basic, ignite_bearer, ignite_string};

    #[test]
    fn authentication() {
        let authenticator = NoOp {};

        // Basic
        let auth_header = hyper::header::Authorization(Basic {
                                                           username: "anything".to_owned(),
                                                           password: Some("let me in".to_string()),
                                                       });
        let result = not_err!(authenticator.authenticate(&Authorization(auth_header), false));
        assert!(result.refresh_payload.is_none());

        // Bearer
        let auth_header = hyper::header::Authorization(Bearer { token: "foobar".to_string() });
        let result = not_err!(authenticator.authenticate(&Authorization(auth_header), false));
        assert!(result.refresh_payload.is_none());

        // String
        let auth_header = hyper::header::Authorization("anything goes".to_string());
        let result = not_err!(authenticator.authenticate(&Authorization(auth_header), false));
        assert!(result.refresh_payload.is_none());
    }

    #[test]
    fn authentication_with_refresh_token() {
        let authenticator = NoOp {};

        // Basic
        let auth_header = hyper::header::Authorization(Basic {
                                                           username: "anything".to_owned(),
                                                           password: Some("let me in".to_string()),
                                                       });
        let result = not_err!(authenticator.authenticate(&Authorization(auth_header), true));
        assert!(result.refresh_payload.is_some()); // should include a refresh token
        let result =
            not_err!(Authenticator::<Basic>::authenticate_refresh_token(&authenticator,
                                                                        result.refresh_payload.as_ref().unwrap()));
        assert!(result.refresh_payload.is_none()); // should NOT include a refresh token

        // Bearer
        let auth_header = hyper::header::Authorization(Bearer { token: "foobar".to_string() });
        let result = not_err!(authenticator.authenticate(&Authorization(auth_header), true));
        assert!(result.refresh_payload.is_some()); // should include a refresh token
        let result =
            not_err!(Authenticator::<Bearer>::authenticate_refresh_token(&authenticator,
                                                                         result.refresh_payload.as_ref().unwrap()));
        assert!(result.refresh_payload.is_none()); // should NOT include a refresh token

        // String
        let auth_header = hyper::header::Authorization("anything goes".to_string());
        let result = not_err!(authenticator.authenticate(&Authorization(auth_header), true));
        assert!(result.refresh_payload.is_some()); // should include a refresh token
        let result =
            not_err!(Authenticator::<String>::authenticate_refresh_token(&authenticator,
                                                                         result.refresh_payload.as_ref().unwrap()));
        assert!(result.refresh_payload.is_none()); // should NOT include a refresh token
    }

    #[test]
    #[allow(deprecated)]
    fn noop_basic_auth_get_test() {
        let rocket = ignite_basic(Box::new(NoOp {}));

        // Make headers
        let auth_header = hyper::header::Authorization(Basic {
                                                           username: "anything".to_owned(),
                                                           password: Some("let me in".to_string()),
                                                       });
        let auth_header = http::Header::new("Authorization",
                                            hyper::header::HeaderFormatter(&auth_header).to_string());
        // Make and dispatch request
        let mut req = MockRequest::new(Get, "/").header(auth_header);
        let response = req.dispatch_with(&rocket);

        // Assert
        assert_eq!(response.status(), Status::Ok);
    }

    #[test]
    #[allow(deprecated)]
    fn noop_bearer_auth_get_test() {
        let rocket = ignite_bearer(Box::new(NoOp {}));

        // Make headers
        let auth_header = hyper::header::Authorization(Bearer { token: "foobar".to_string() });
        let auth_header = http::Header::new("Authorization",
                                            hyper::header::HeaderFormatter(&auth_header).to_string());
        // Make and dispatch request
        let mut req = MockRequest::new(Get, "/").header(auth_header);
        let response = req.dispatch_with(&rocket);

        // Assert
        assert_eq!(response.status(), Status::Ok);
    }

    #[test]
    #[allow(deprecated)]
    fn noop_string_auth_get_test() {
        let rocket = ignite_string(Box::new(NoOp {}));

        // Make headers
        let auth_header = hyper::header::Authorization("anything goes".to_string());
        let auth_header = http::Header::new("Authorization",
                                            hyper::header::HeaderFormatter(&auth_header).to_string());
        // Make and dispatch request
        let mut req = MockRequest::new(Get, "/").header(auth_header);
        let response = req.dispatch_with(&rocket);

        // Assert
        assert_eq!(response.status(), Status::Ok);
    }
}
