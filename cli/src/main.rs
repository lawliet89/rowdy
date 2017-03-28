#![feature(plugin)]
#![plugin(rocket_codegen)]

extern crate docopt;
#[macro_use]
extern crate log;
#[macro_use]
extern crate rocket;
extern crate rowdy;
extern crate rustc_serialize;
extern crate serde;
extern crate serde_json;

use docopt::Docopt;
use rowdy::auth;
use rocket::Rocket;

const USAGE: &'static str = r#"
rowdy JSON Web Token Authentication Server

Usage:
  rowdy noop <configuration-json>
  rowdy csv <configuration-json>
  rowdy ldap <configuration-json>
  rowdy (-h | --help)

Provide a configuration JSON file to run `rowdy` with. For available fields and examples for the JSON
configuration, refer to the documentation at https://lawliet89.github.io/rowdy/rowdy/struct.Configuration.html

You can also, additionally, configure Rocket by using `Rocket.toml` file.
See https://rocket.rs/guide/overview#configuration

The `noop` subcommand allows all username and passwords to authenticate.
The `csv` subcommand uses a CSV file as its username database. See
https://lawliet89.github.io/rowdy/rowdy/auth/simple/index.html for the database format.

The subcommands will change the format expected by the `basic_authenticator` key of the configuration JSON.
  - noop: The key is expected to be simply an empty map: i.e. `{}`
  - csv: The key should behave according to the format documented at
    https://lawliet89.github.io/rowdy/rowdy/auth/struct.SimpleAuthenticatorConfiguration.html
  - ldap: The key should behave according to the format documented at
    https://lawliet89.github.io/rowdy/rowdy/auth/struct.LdapAuthenticator.html

Options:
  -h --help                 Show this screen.
"#;

#[derive(Debug, RustcDecodable)]
struct Args {
    arg_configuration_json: String,
    cmd_noop: bool,
    cmd_csv: bool,
    cmd_ldap: bool,
}

fn main() {
    let args: Args = Docopt::new(USAGE).and_then(|d| d.decode()).unwrap_or_else(|e| e.exit());

    let rocket = if args.cmd_noop {
        ignite::<auth::NoOpConfiguration>(&args.arg_configuration_json)
    } else if args.cmd_csv {
        ignite::<auth::SimpleAuthenticatorConfiguration>(&args.arg_configuration_json)
    } else if args.cmd_ldap {
        ignite::<auth::LdapAuthenticator>(&args.arg_configuration_json)
    } else {
        unreachable!("Should never happen");
    };

    let rocket = rocket.unwrap_or_else(|e| panic!("{}", e));
    rocket.mount("/", rowdy::routes()).launch()
}

/// Read configuration files, and ignite a `Rocket`
fn ignite<B>(path: &str) -> Result<Rocket, rowdy::Error>
    where B: auth::AuthenticatorConfiguration<auth::Basic>
{
    let config = read_config::<B>(path)?;
    config.ignite()
}

fn read_config<B>(path: &str) -> Result<rowdy::Configuration<B>, String>
    where B: auth::AuthenticatorConfiguration<auth::Basic>
{
    use std::fs::File;
    use std::io::Read;

    info_!("Reading configuration from '{}'", path);
    let mut file = File::open(&path).map_err(|e| format!("{:?}", e))?;
    let mut config_json = String::new();
    file.read_to_string(&mut config_json).map_err(|e| format!("{:?}", e))?;

    deserialize_json(&config_json)
}

pub fn deserialize_json<T>(json: &str) -> Result<T, String>
    where T: serde::Deserialize
{
    serde_json::from_str(json).map_err(|e| format!("{:?}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ignite_noop() {
        ignite::<auth::NoOpConfiguration>("test/fixtures/config_noop.json").unwrap();
    }

    #[test]
    fn ignite_csv() {
        ignite::<auth::NoOpConfiguration>("test/fixtures/config_csv.json").unwrap();
    }

    #[test]
    fn ignite_ldap() {
        ignite::<auth::NoOpConfiguration>("test/fixtures/config_ldap.json").unwrap();
    }
}
