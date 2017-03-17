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

const USAGE: &'static str = r#"
rowdy JSON Web Token Authentication Server

Usage:
  rowdy noop <configuration-json>
  rowdy csv [options] <configuration-json> <csv> <salt>
  rowdy (-h | --help)

Provide a configuration JSON file to run `rowdy` with. For available fields and examples for the JSON
configuration, refer to the documentation at https://lawliet89.github.io/rowdy/rowdy/struct.Configuration.html

You can also configure Rocket by using `Rocket.toml` file. See https://rocket.rs/guide/overview#configuration

The `noop` subcommand allows all username and passwords to authenticate.
The `csv` subcommand uses a CSV file as its username database. See
https://lawliet89.github.io/rowdy/rowdy/auth/simple/index.html for the database format.

Options:
  -h --help                 Show this screen.
  --delimiter=<sep>         The CSV seperator [default: ,]
  --csv-header=<header>     Whether the CSV file has a header [default: false]
"#;

#[derive(Debug, RustcDecodable)]
struct Args {
    arg_configuration_json: String,
    arg_csv: String,
    arg_salt: String,
    flag_delimiter: char,
    flag_csv_header: bool,
    cmd_noop: bool,
    cmd_csv: bool,
}

fn main() {
    let args: Args = Docopt::new(USAGE).and_then(|d| d.decode()).unwrap_or_else(|e| e.exit());

    let config = read_config(&args.arg_configuration_json)
        .map_err(|err| {
                     panic!("Failed to read configuration file {}: {}",
                            &args.arg_configuration_json,
                            err)
                 })
        .unwrap();
    debug!("Configuration parsed {:?}", config);

    let authenticator: Box<rowdy::auth::BasicAuthenticator> = if args.cmd_noop {
        Box::new(rowdy::auth::NoOp {})
    } else if args.cmd_csv {
        Box::new(rowdy::auth::SimpleAuthenticator::with_csv_file(args.arg_salt.as_bytes(),
                                                                 &args.arg_csv,
                                                                 args.flag_csv_header,
                                                                 args.flag_delimiter as u8) // FIXME
                         .unwrap_or_else(|e| panic!("{:?}", e)))
    } else {
        unreachable!("Should never happen");
    };

    rowdy::launch(config, authenticator);
}

fn read_config(path: &str) -> Result<rowdy::Configuration, String> {
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
    fn read_config_smoke_test() {
        read_config("test/fixtures/config.json").unwrap();
    }
}
