#![feature(plugin)]
#![plugin(rocket_codegen)]

extern crate jwt;
extern crate hyper;
extern crate rocket;
extern crate uuid;

#[cfg(test)]
#[macro_use]
mod test;
pub mod cors;

#[allow(unmounted_route)]
// The library crate does not mount anything
#[get("/")]
fn hello() -> cors::CORS<&'static str> {
    cors::CORS::any("Hello, world!")
}
