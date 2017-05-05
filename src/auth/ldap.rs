//! LDAP Authentication module
use std::collections::HashMap;

use ldap3::{LdapConn, Scope, SearchEntry};
use strfmt::{FmtError, strfmt};
use serde_json::value;

use {Error, JsonValue, JsonMap};
use super::{Basic, AuthenticationResult};

const LDAP_SUCCESS: u8 = 0;

/// Error mapping for `FmtError`
impl From<FmtError> for Error {
    fn from(e: FmtError) -> Error {
        Error::GenericError(e.to_string())
    }
}

/// A "User" returned from LDAP. This is the same as `ldap3::SearchEntry`, but with additional traits implemented
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Debug)]
pub struct User {
    dn: String,
    attributes: HashMap<String, Vec<String>>
}

impl From<SearchEntry> for User {
    fn from(entry: SearchEntry) -> Self {
        Self {
            dn: entry.dn,
            attributes: entry.attrs,
        }
    }
}

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
    fn connect(&self) -> Result<LdapConn, Error> {
        let connection = LdapConn::new(&self.address)?;
        Ok(connection)
    }

    /// Bind the "searcher" user
    fn searcher_bind(&self, connection: &LdapConn) -> Result<(), Error> {
        self.bind(connection, &self.bind_dn, &self.bind_password)
    }

    /// Bind the connection to some dn
    fn bind(&self, connection: &LdapConn, dn: &str, password: &str) -> Result<(), Error> {
        let (result, _) = connection.simple_bind(dn, password)?;
        if result.rc == LDAP_SUCCESS {
            Ok(())
        } else {
            Err(Error::GenericError(format!("Binding failed with reason code: {}", result.rc)))
        }
    }

    /// Search for the specified account in the directory
    fn search(&self, connection: &LdapConn, account: &str) -> Result<Vec<SearchEntry>, Error> {
        let account: HashMap<String, String> = [("account".to_string(), account.to_string())]
            .iter()
            .cloned()
            .collect();
        let search_base = strfmt(&self.search_base, &account)?;
        let search_filter = match self.search_filter {
            None => "".to_string(),
            Some(ref search_filter) => strfmt(search_filter, &account)?,
        };

        // This specifies what to get back from the LDAP server
        let search_attrs_vec = vec!["cn", "dn"];
        let (results, status, _) = connection
            .search(&search_base,
                    Scope::Subtree,
                    &search_filter,
                    search_attrs_vec)?;

        if status.rc != LDAP_SUCCESS {
            Err(Error::GenericError(format!("Search failed with reason code: {}", status.rc)))?;
        }

        Ok(results
               .into_iter()
               .map(SearchEntry::construct)
               .collect())
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
        let user_dn = user.dn.clone();
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
            let mut user = self.search(&connection, username)
                .map_err(|_e| super::Error::AuthenticationFailure)?;
            if user.len() != 1 {
                Err(super::Error::AuthenticationFailure)?;
            }

            user.pop().unwrap() // safe to unwrap
        };

        let user_dn = user.dn.clone();

        {
            // Attempt a bind with the user's DN and password
            let connection = self.connect()?;
            self.bind(&connection, &user_dn, password)
                .map_err(|_e| super::Error::AuthenticationFailure)?;
        }

        Self::build_authentication_result(From::from(user), refresh_payload)
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
