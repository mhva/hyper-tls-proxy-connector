# Hyper HTTP/HTTPS Connector with Proxy Support

This crate implements a [hyper](https://github.com/hyperium/hyper) connector that supports both HTTP and HTTPS and allows connecting either directly or through a proxy server.

**NOTE**: Requires nightly version of Rust at the moment.

# Example Usage

```
// Create example reactor that will execute network tasks.
let mut core = tokio_core::reactor::Core::new().unwrap();

// Create a simple builder without configuring any parameters. In this
// configuration, connector will use internal CPU pool for DNS resolution.
let builder = httpx::HttpxConnectorBuilder::new(&core.handle());
let httpx_connector = connector_builder.build();

// Create hyper::Client that will use our HttpxConnector instead of default.
let client = hyper::Client::configure()
                .connector(httpx_connector)
                .build(&core.handle());

// ...
```
