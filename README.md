authz-sys
=========

Rust FFI bindings for Microsoft's AuthZ API (see [https://docs.microsoft.com/en-us/windows/win32/secauthz/using-authz-api](https://docs.microsoft.com/en-us/windows/win32/secauthz/using-authz-api)). 

Building
--------------------

Create a `build.rs` file telling rustc where to find the `Authz.lib` static library from your local Windows SDK. For instance:

```rust
fn main() {
    println!("cargo:rustc-link-search=C:/Program Files (x86)/Microsoft SDKs/Windows/v7.1A/Lib/");
}
```

Then, just `cargo build` the crate.

Contributing
--------------------

If these bindings are missing some functions or don't work in your usecase, please open an issue or a pull request. You can also contact me on [Twitter](https://twitter.com/mtth_bfft).

