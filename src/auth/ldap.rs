//! LDAP Authentication module
use std::collections::HashMap;
use std::ptr;

use openldap::{RustLDAP, LDAPResponse};
use openldap::codes::results;
use openldap::errors::LDAPError;
use openldap::codes::options;
use openldap::codes::scopes;
use strfmt::{FmtError, strfmt};

use super::{Basic, Error};

/// Error mapping for `LDAPError`
impl From<LDAPError> for Error {
    fn from(ldap_error: LDAPError) -> Error {
        Error::GenericError(format!("{}", ldap_error))
    }
}

/// Error mapping for `LDAPError`
impl From<LDAPError> for ::Error {
    fn from(ldap_error: LDAPError) -> ::Error {
        ::Error::GenericError(format!("{}", ldap_error))
    }
}

/// Error mapping for `FmtError`
impl From<FmtError> for Error {
    fn from(e: FmtError) -> Error {
        Error::GenericError(format!("{}", e))
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
        let account: HashMap<String, String> = [("account".to_string(), account.to_string())].iter().cloned().collect();
        let search_base = strfmt(&self.search_base, &account)?;
        let search_filter = match self.search_filter {
            None => None,
            Some(ref search_filter) => Some(strfmt(search_filter, &account)?),
        };

        let search_attrs_vec = vec!["cn", "dn"];
        let results = connection.ldap_search(&search_base,
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

    /// Authenticate the user with the username/password
    pub fn verify(&self, username: &str, password: &str) -> Result<(), Error> {
        let user_dn = {
            // First, we search for the user
            let connection = self.connect()?;
            self.searcher_bind(&connection)?;
            let user = self.search(&connection, username).map_err(|_e| Error::AuthenticationFailure)?;
            if user.len() != 1 {
                Err(Error::AuthenticationFailure)?;
            }

            user[0]["dn"][0].clone()
        };

        {
            // Attempt a bind with the user's DN and password
            let connection = self.connect()?;
            self.bind(&connection, &user_dn, password).map_err(|_e| Error::AuthenticationFailure)?;
        }

        Ok(())
    }
}

impl super::Authenticator<Basic> for LdapAuthenticator {
    fn authenticate(&self, authorization: &super::Authorization<Basic>) -> Result<(), Error> {
        let username = authorization.username();
        let password = authorization.password().unwrap_or_else(|| "".to_string());
        self.verify(&username, &password)
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
    fn authentication_smoke_test() {
        let authenticator = make_authenticator();
        not_err!(authenticator.verify("euler", "password"));
    }

    #[test]
    #[should_panic(expected = "AuthenticationFailure")]
    fn authentication_invalid_user() {
        let authenticator = make_authenticator();
        authenticator.verify("donald_trump", "password").unwrap();
    }

    #[test]
    #[should_panic(expected = "AuthenticationFailure")]
    fn authentication_invalid_password() {
        let authenticator = make_authenticator();
        authenticator.verify("einstein", "FTL").unwrap();
    }
}
