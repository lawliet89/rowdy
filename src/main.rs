#![feature(plugin)]
#![plugin(rocket_codegen)]

extern crate jwt;
extern crate rocket;
extern crate rowdy;

fn main() {
    rocket::ignite().mount("/", routes![rowdy::hello]).launch();
}
