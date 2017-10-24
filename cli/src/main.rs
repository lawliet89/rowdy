#![feature(plugin)]
#![plugin(rocket_codegen)]

#[macro_use]
extern crate clap;
extern crate rocket;
extern crate rowdy;
extern crate rowdy_diesel;
extern crate serde;
extern crate serde_json;

use std::fs::File;
use std::io::{self, Read};

use clap::{App, AppSettings, Arg, ArgMatches, SubCommand};
use rowdy::auth;

fn main() {
    let args = make_parser().get_matches();
    let result = run_subcommand(&args);

    std::process::exit(match result {
        Ok(()) => 0,
        Err(e) => {
            println!("Error: {}", e.to_string());
            1
        }
    });
}

fn run_subcommand(args: &ArgMatches) -> Result<(), rowdy::Error> {
    match args.subcommand() {
        ("noop", Some(args)) => launch::<auth::NoOpConfiguration>(args),
        ("csv", Some(args)) => launch::<auth::SimpleAuthenticatorConfiguration>(args),
        ("ldap", Some(args)) => launch::<auth::LdapAuthenticator>(args),
        ("mysql", Some(args)) => run_diesel::<rowdy_diesel::mysql::Configuration, _, _, _>(args),
        _ => unreachable!("Unknown subcommand encountered."),
    }
}

/// Make a command line parser for options
fn make_parser<'a, 'b>() -> App<'a, 'b>
where
    'a: 'b,
{
    let noop = SubCommand::with_name("noop")
        .about("Launch rowdy with a `noop` authenticator.")
        .arg(
            Arg::with_name("config")
                .index(1)
                .help(
                    "Specifies the path to read the configuration from. \
                     Use - to refer to STDIN",
                )
                .takes_value(true)
                .value_name("config_path")
                .empty_values(false)
                .required(true),
        );

    let csv = SubCommand::with_name("csv")
        .about("Launch rowdy with a `csv` authenticator backed by a CSV user database.")
        .arg(
            Arg::with_name("config")
                .index(1)
                .help(
                    "Specifies the path to read the configuration from. \
                     Use - to refer to STDIN",
                )
                .takes_value(true)
                .value_name("config_path")
                .empty_values(false)
                .required(true),
        );

    let ldap = SubCommand::with_name("ldap")
        .about("Launch rowdy with a `ldap` authenticator backed by a LDAP directory.")
        .arg(
            Arg::with_name("config")
                .index(1)
                .help(
                    "Specifies the path to read the configuration from. \
                     Use - to refer to STDIN",
                )
                .takes_value(true)
                .value_name("config_path")
                .empty_values(false)
                .required(true),
        );

    let mysql = SubCommand::with_name("mysql")
        .about("Launch rowdy with a `mysql` authenticator backed by a MySQL table.")
        .arg(
            Arg::with_name("migrate")
                .help(
                    "Instead of launching the server, perform a migration to create the bare\
                     minimum table for Rowdy to work. The migration is idempotent. See \
                     https://lawliet89.github.io/rowdy/rowdy_diesel/schema/index.html \
                     for schema information",
                )
                .long("migrate"),
        )
        .arg(
            Arg::with_name("config")
                .index(1)
                .help(
                    "Specifies the path to read the configuration from. \
                     Use - to refer to STDIN",
                )
                .takes_value(true)
                .value_name("config_path")
                .empty_values(false)
                .required(true),
        );

    App::new("rowdy")
        .bin_name("rowdy")
        .version(crate_version!())
        .author(crate_authors!())
        .setting(AppSettings::SubcommandRequired)
        .setting(AppSettings::VersionlessSubcommands)
        .setting(AppSettings::PropagateGlobalValuesDown)
        .global_setting(AppSettings::DontCollapseArgsInUsage)
        .global_setting(AppSettings::NextLineHelp)
        .about(
            r#"
Provide a configuration JSON file to run `rowdy` with. For available fields and examples for the
JSON configuration, refer to the documentation at
https://lawliet89.github.io/rowdy/rowdy/struct.Configuration.html

You can also, additionally, configure Rocket by using `Rocket.toml` file.
See https://rocket.rs/guide/overview#configuration

The `noop` subcommand allows all username and passwords to authenticate.
The `csv` subcommand uses a CSV file as its username database. See
https://lawliet89.github.io/rowdy/rowdy/auth/simple/index.html for the database format.
The `mysql` subcommand uses a MySQL database for usernames. See
https://lawliet89.github.io/rowdy/rowdy/auth/mysql/index.html for the database format.

The subcommands will change the format expected by the `basic_authenticator` key of the
configuration JSON.
  - noop: The key is expected to be simply an empty map: i.e. `{}`
  - csv: The key should behave according to the format documented at
    https://lawliet89.github.io/rowdy/rowdy/auth/struct.SimpleAuthenticatorConfiguration.html
  - ldap: The key should behave according to the format documented at
    https://lawliet89.github.io/rowdy/rowdy/auth/struct.LdapAuthenticator.html
  - mysql: The key should behave according to the format documented at
    https://lawliet89.github.io/rowdy/rowdy/auth/struct.MysqlAuthenticatorConfiguration.html
        "#,
        )
        .subcommand(noop)
        .subcommand(csv)
        .subcommand(ldap)
        .subcommand(mysql)
}

/// Launch a rocket -- this function will block and never return unless on error
fn launch<B>(args: &ArgMatches) -> Result<(), rowdy::Error>
where
    B: auth::AuthenticatorConfiguration<auth::Basic>,
{
    let config = args.value_of("config")
        .expect("Required options to be present");

    let reader = input_reader(&config)?;
    let config = read_config::<B, _>(reader)?;
    let rocket = config.ignite()?;

    // launch() will never return except in error
    let launch_error = rocket.mount("/", rowdy::routes()).launch();
    Err(launch_error)?
}

fn run_diesel<Config, Auth, Connection, ConnectionPool>(
    args: &ArgMatches,
) -> Result<(), rowdy::Error>
where
    Config: auth::AuthenticatorConfiguration<auth::Basic, Authenticator = Auth>,
    Auth: auth::Authenticator<auth::Basic>
        + rowdy_diesel::schema::Migration<Connection, Connection = ConnectionPool>,
    Connection: rowdy_diesel::Connection + 'static,
    ConnectionPool: std::ops::Deref<Target = Connection>,
{
    let config = args.value_of("config")
        .expect("Required options to be present");
    let reader = input_reader(&config)?;
    let config = read_config::<Config, _>(reader)?;

    if args.is_present("migrate") {
        println!("Performing migration...");
        let authenticator = config.basic_authenticator.make_authenticator()?;
        authenticator.migrate()?;
        println!("Migration complete.");
        Ok(())
    } else {
        let rocket = config.ignite()?;

        // launch() will never return except in error
        let launch_error = rocket.mount("/", rowdy::routes()).launch();
        Err(launch_error)?
    }
}

fn read_config<B, R: Read>(reader: R) -> Result<rowdy::Configuration<B>, rowdy::Error>
where
    B: auth::AuthenticatorConfiguration<auth::Basic>,
{
    Ok(serde_json::from_reader(reader).map_err(|e| e.to_string())?)
}

/// Gets a `Read` depending on the path. If the path is `-`, read from STDIN
fn input_reader(path: &str) -> Result<Box<Read>, rowdy::Error> {
    match path {
        "-" => Ok(Box::new(io::stdin())),
        path => {
            let file = File::open(path)?;
            Ok(Box::new(file))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Cursor;

    fn noop_json() -> &'static str {
        include_str!("../test/fixtures/config_noop.json")
    }

    fn csv_json() -> &'static str {
        include_str!("../test/fixtures/config_csv.json")
    }

    fn ldap_json() -> &'static str {
        include_str!("../test/fixtures/config_ldap.json")
    }

    fn mysql_json() -> &'static str {
        include_str!("../test/fixtures/config_mysql.json")
    }

    fn to_cursor<F, T>(fixture: F) -> Cursor<T>
    where
        F: Fn() -> T,
        T: AsRef<[u8]>,
    {
        Cursor::new(fixture())
    }

    #[test]
    fn noop_configuration_reading() {
        let config = to_cursor(noop_json);
        let _ = read_config::<auth::NoOpConfiguration, _>(config).expect("to succeed");
    }

    #[test]
    fn csv_configuration_reading() {
        let config = to_cursor(csv_json);
        let _ =
            read_config::<auth::SimpleAuthenticatorConfiguration, _>(config).expect("to succeed");
    }

    #[test]
    fn ldap_configuration_reading() {
        let config = to_cursor(ldap_json);
        let _ = read_config::<auth::LdapAuthenticator, _>(config).expect("to succeed");
    }

    #[test]
    fn mysql_configuration_reading() {
        let config = to_cursor(mysql_json);
        let _ = read_config::<rowdy_diesel::mysql::Configuration, _>(config).expect("to succeed");
    }
}
