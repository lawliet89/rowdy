# rowdy

[Documentation](https://lawliet89.github.io/rowdy/)

A [Rocket](https://rocket.rs/) based JSON Web Token authentication server.

## Requirements

Rocket requires nightly Rust. You should probably install Rust with [rustup](https://www.rustup.rs/), then override the code directory to use nightly instead of stable. See
[installation instructions](https://rocket.rs/guide/getting-started/#installing-rust).

## Testing

To separate the dependencies of the `library` part of the crate from the `binary` part, the crate is set up
to make use of [workspaces](http://doc.crates.io/manifest.html#the-workspace--field-optional).

To run tests on both the `libary` and `binary`, do `cargo test --all`.
