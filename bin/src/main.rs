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
  rowdy <configuration-json>
  rowdy (-h | --help)

Provide a configuration JSON file to run `rowdy` with.

To allow all origins, your configuration file would look like: `{ "allowed_origins": null }`
Otherwise, it should be `{ "allowed_origins": ["http://127.0.0.1:8000/","https://foobar.com/"] }`

Options:
  -h --help     Show this screen.
"#;

#[derive(Debug, RustcDecodable)]
struct Args {
    arg_configuration_json: String,
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

    rowdy::launch(config);
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
