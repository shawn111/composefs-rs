# composefs experiments in rust

This is a set of experiments attempting to implement dramatically-simplified
versions of some of the tools from
[composefs](https://github.com/containers/composefs) in a legacy-free way using
pure Rust.

It depends on (currently pre-release) Linux 6.12.

We use [`rustix`](https://github.com/bytecodealliance/rustix) because it's
awesome, but otherwise try to stick to `std::` and the libraries listed in,
[`rust-lang`](https://crates.io/teams/github:rust-lang:libs), and
[`rust-lang-nursery`](https://crates.io/teams/github:rust-lang-nursery:libs).

The purpose of this is to iterate fast on some new ideas (without worrying
about breaking existing composefs users) and also as a learning experience (as
my first real Rust project).

Nothing here is currently expected to be useful to anybody at all, and probably
never will be.  If these experiments go well, this code will probably end up
merged in other places.
