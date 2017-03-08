#![feature(plugin)]
#![plugin(rocket_codegen)]

extern crate jwt;
extern crate rocket;

#[get("/")]
fn hello() -> &'static str {
    "Hello, world!"
}
