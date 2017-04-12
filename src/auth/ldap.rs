//! LDAP Authentication module
use std::collections::HashMap;
use std::ptr;

use openldap::{RustLDAP, LDAPResponse};
use openldap::codes::results;
use openldap::errors::LDAPError;
use openldap::codes::options;
use openldap::codes::scopes;
use strfmt::{FmtError, strfmt};
use serde_json::value;

use {Error, JsonValue, JsonMap};
use super::{Basic, AuthenticationResult};

/// Error mapping for `LDAPError`
impl From<LDAPError> for Error {
    fn from(ldap_error: LDAPError) -> Error {
        Error::GenericError(ldap_error.to_string())
    }
}

/// Error mapping for `FmtError`
impl From<FmtError> for Error {
    fn from(e: FmtError) -> Error {
        Error::GenericError(e.to_string())
    }
}

/// Typedef of a "User" from `openldap`
type User = HashMap<String, Vec<String>>;

/// LDAP based authenticator
///
/// Use LDAP server as the identity provider.
///
/// # Example
/// ```
/// use rowdy::auth::LdapAuthenticator;
/// let authenticator = LdapAuthenticator {
///     address: "ldap://ldap.forumsys.com".to_string(),
///     bind_dn: "cn=read-only-admin,dc=example,dc=com".to_string(),
///     bind_password: "password".to_string(),
///     search_base: "dc=example,dc=com".to_string(),
///     search_filter: Some("(uid={account})".to_string()),
/// };
/// ```
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Debug)]
pub struct LdapAuthenticator {
    /// Location of the LDAP server
    pub address: String,
    /// The user that we will bind to LDAP to search for users
    pub bind_dn: String,
    /// The password that we will use to bind to LDAP to search for users
    pub bind_password: String,
    /// Base to use when searching for user. `{account}` is expanded to the user's account
    pub search_base: String,
    /// Filter to use when searching for user. `{account}` is expanded to the user's account
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub search_filter: Option<String>,
}

impl LdapAuthenticator {
    /// Connects to the LDAP server
    fn connect(&self) -> Result<RustLDAP, Error> {
        let connection = RustLDAP::new(&self.address)?;
        if !connection.set_option(options::LDAP_OPT_PROTOCOL_VERSION, &3) {
            Err(Error::GenericError("Unable to set LDAP version".to_string()))?;
        }
        Ok(connection)
    }

    /// Bind the "searcher" user
    fn searcher_bind(&self, connection: &RustLDAP) -> Result<(), Error> {
        self.bind(connection, &self.bind_dn, &self.bind_password)
    }

    /// Bind the connection to some dn
    fn bind(&self, connection: &RustLDAP, dn: &str, password: &str) -> Result<(), Error> {
        let result = connection.simple_bind(dn, password)?;
        if result == results::LDAP_SUCCESS {
            Ok(())
        } else {
            Err(Error::GenericError(format!("Binding failed with reason code: {}", result)))
        }
    }

    /// Search for the specified account in the directory
    fn search(&self, connection: &RustLDAP, account: &str) -> Result<LDAPResponse, Error> {
        let account: HashMap<String, String> = [("account".to_string(), account.to_string())]
            .iter()
            .cloned()
            .collect();
        let search_base = strfmt(&self.search_base, &account)?;
        let search_filter = match self.search_filter {
            None => None,
            Some(ref search_filter) => Some(strfmt(search_filter, &account)?),
        };

        let search_attrs_vec = vec!["cn", "dn"];
        let results = connection
            .ldap_search(&search_base,
                         scopes::LDAP_SCOPE_SUBTREE,
                         search_filter.as_ref().map(|s| &**s),
                         Some(search_attrs_vec),
                         false,
                         None,
                         None,
                         ptr::null_mut(),
                         -1)?;

        Ok(results)
    }

    /// Serialize a user as payload for a refresh token
    fn serialize_refresh_token_payload(user: User) -> Result<JsonValue, Error> {
        let user = value::to_value(user)
            .map_err(|_| super::Error::AuthenticationFailure)?;
        let mut map = JsonMap::with_capacity(1);
        map.insert("user".to_string(), user);
        Ok(JsonValue::Object(map))
    }

    /// Deserialize a user from a refresh token payload
    fn deserialize_refresh_token_payload(payload: JsonValue) -> Result<User, Error> {
        match payload {
            JsonValue::Object(ref map) => {
                let user = map.get("user")
                    .ok_or_else(|| Error::Auth(super::Error::AuthenticationFailure))?;
                Ok(value::from_value(user.clone())
                       .map_err(|_| super::Error::AuthenticationFailure)?)
            }
            _ => Err(Error::Auth(super::Error::AuthenticationFailure)),
        }
    }

    /// Build an `AuthenticationResult` for a `User`
    fn build_authentication_result(user: User, refresh_payload: bool) -> Result<AuthenticationResult, Error> {
        let user_dn = user["dn"][0].clone();
        let payload = if refresh_payload {
            Some(Self::serialize_refresh_token_payload(user)?)
        } else {
            None
        };
        Ok(AuthenticationResult {
               subject: user_dn,
               payload: payload,
           })
    }

    /// Authenticate the user with the username/password
    pub fn verify(&self, username: &str, password: &str, refresh_payload: bool) -> Result<AuthenticationResult, Error> {
        let user = {
            // First, we search for the user
            let connection = self.connect()?;
            self.searcher_bind(&connection)?;
            let user = self.search(&connection, username)
                .map_err(|_e| super::Error::AuthenticationFailure)?;
            if user.len() != 1 {
                Err(super::Error::AuthenticationFailure)?;
            }

            user[0].clone()
        };

        let user_dn = user["dn"][0].clone();

        {
            // Attempt a bind with the user's DN and password
            let connection = self.connect()?;
            self.bind(&connection, &user_dn, password)
                .map_err(|_e| super::Error::AuthenticationFailure)?;
        }

        Self::build_authentication_result(user, refresh_payload)
    }
}

impl super::Authenticator<Basic> for LdapAuthenticator {
    fn authenticate(&self,
                    authorization: &super::Authorization<Basic>,
                    refresh_payload: bool)
                    -> Result<AuthenticationResult, Error> {
        let username = authorization.username();
        let password = authorization
            .password()
            .unwrap_or_else(|| "".to_string());
        self.verify(&username, &password, refresh_payload)
    }

    // TODO: Implement retrieving updated information from LDAP server
    fn authenticate_refresh_token(&self, payload: &JsonValue) -> Result<AuthenticationResult, ::Error> {
        let user = Self::deserialize_refresh_token_payload(payload.clone())?;
        Self::build_authentication_result(user, false)
    }
}

impl super::AuthenticatorConfiguration<Basic> for LdapAuthenticator {
    type Authenticator = LdapAuthenticator;

    fn make_authenticator(&self) -> Result<Self::Authenticator, ::Error> {
        {
            // Test connection to LDAP server
            let connection = self.connect()?;
            // Test binding for user searcher
            self.searcher_bind(&connection)?;
        }

        Ok(self.clone())
    }
}

#[cfg(test)]
mod tests {
    //! These tests might intermittently fail due to Test server being inaccessible
    use auth::Authenticator;
    use super::*;

    /// Test LDAP server: http://www.forumsys.com/tutorials/integration-how-to/ldap/online-ldap-test-server/
    fn make_authenticator() -> LdapAuthenticator {
        LdapAuthenticator {
            address: "ldap://ldap.forumsys.com".to_string(),
            bind_dn: "cn=read-only-admin,dc=example,dc=com".to_string(),
            bind_password: "password".to_string(),
            search_base: "dc=example,dc=com".to_string(),
            search_filter: Some("(uid={account})".to_string()),
        }
    }

    #[test]
    fn authentication() {
        let authenticator = make_authenticator();
        let result = not_err!(authenticator.verify("euler", "password", false));
        assert!(result.payload.is_none());

        let result = not_err!(authenticator.verify("euler", "password", true));
        assert!(result.payload.is_some());

        let refresh_result = not_err!(authenticator.authenticate_refresh_token(result.payload.as_ref().unwrap()));
        assert!(refresh_result.payload.is_none());

        assert_eq!(result.subject, refresh_result.subject);
    }

    #[test]
    #[should_panic(expected = "AuthenticationFailure")]
    fn authentication_invalid_user() {
        let authenticator = make_authenticator();
        authenticator
            .verify("donald_trump", "password", false)
            .unwrap();
    }

    #[test]
    #[should_panic(expected = "AuthenticationFailure")]
    fn authentication_invalid_password() {
        let authenticator = make_authenticator();
        authenticator.verify("einstein", "FTL", false).unwrap();
    }
}
