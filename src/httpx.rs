use std::{self, io};
use std::fmt::Display;
use std::io::{Read, Write};
use std::rc::Rc;
use std::net::{IpAddr, SocketAddr,ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::collections::BTreeMap;

use failure::{self, Error, Fail};
use futures::prelude::*;
use futures::{self, Future, Poll};
use futures::future::{self, Executor};
use futures_cpupool;

use hyper::{self, Uri};
use openssl;
use openssl::ssl::{SslConnector, SslConnectorBuilder, SslMethod, SslSession, SslStream};

use tokio_core::reactor::Handle;
use tokio_core::net::TcpStream;
use tokio_io::{AsyncRead, AsyncWrite};
use tokio_io::io::{read_exact, write_all};
use tokio_service::Service;

use dns;
use socks5;

#[derive(Clone)]
struct SslSessionCache(Arc<Mutex<BTreeMap<(String, u16), SslSession>>>);

impl SslSessionCache {
    fn new() -> SslSessionCache {
        SslSessionCache(Arc::new(Mutex::new(BTreeMap::new())))
    }

    fn insert(&self, k: (String, u16), v: SslSession) {
        self.0.lock().unwrap().insert(k, v);
    }

    fn get(&self, k: &(String, u16)) -> Option<SslSession> {
        self.0.lock().unwrap().get(k).map(|x| x.clone())
    }
}

struct SslConnectorFuture<S>(Option<openssl::ssl::MidHandshakeSslStream<S>>);

impl<S: Read + Write> Future for SslConnectorFuture<S> {
    type Item = SslStream<S>;
    type Error = HttpxError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self.0.take().unwrap().handshake() {
            Ok(s) => Ok(Async::Ready(s)),
            Err(openssl::ssl::HandshakeError::Interrupted(s)) => {
                self.0 = Some(s);
                Ok(Async::NotReady)
            },
            Err(openssl::ssl::HandshakeError::SetupFailure(err)) => {
                let msg = "ssl stream setup failure".to_owned();
                Err(HttpxError::SslError(msg, Some(err)))
            },
            Err(openssl::ssl::HandshakeError::Failure(_)) => {
                let msg = "ssl handshake failed".to_owned();
                Err(HttpxError::SslError(msg, None))
            }
        }
    }
}

#[derive(Debug, Fail)]
enum HttpxError {
    InvalidParameter(String),
    ConnectionError(SocketAddr, io::Error),
    DnsError(failure::Error),
    ProxyError(failure::Error),
    SslError(String, Option<openssl::error::ErrorStack>),
    OtherError(String),
}

impl Display for HttpxError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        match self {
            &HttpxError::InvalidParameter(ref s) =>
                write!(f, "invalid parameter ({})", s),
            &HttpxError::DnsError(ref err) =>
                write!(f, "dns error ({})", err),
            &HttpxError::ConnectionError(ref sa, ref err) =>
                write!(f, "failed to connect to {}:{} ({})",
                    sa.ip(),
                    sa.port(),
                    err),
            &HttpxError::SslError(ref s, Some(ref err)) =>
                write!(f, "{} ({})", s, err),
            &HttpxError::SslError(ref s, None) =>
                write!(f, "{}", s),
            &HttpxError::OtherError(ref s) =>
                write!(f, "{}", s),
            &HttpxError::ProxyError(ref err) =>
                write!(f, "{}", err),
        }
    }
}

impl From<HttpxError> for io::Error {
    fn from(err: HttpxError) -> Self {
        use std::io::ErrorKind;
        use std::io::Error;
        match &err {
            HttpxError::InvalidParameter(_) =>
                return Error::new(ErrorKind::InvalidInput, err.to_string()),
            HttpxError::ConnectionError(_, e) =>
                return Error::new(e.kind(), err.to_string()),
            _ =>
                return Error::new(ErrorKind::Other, err.to_string()),
        }
    }
}

#[derive(Debug)]
pub enum HttpxStream<S> {
    CleartextStream(S),
    EncryptedStream(SslStream<S>)
}

impl<S: Read + Write> Read for HttpxStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        match self {
            &mut HttpxStream::CleartextStream(ref mut s) => s.read(buf),
            &mut HttpxStream::EncryptedStream(ref mut s) => s.read(buf),
        }
    }
}

impl<S: Read + Write> Write for HttpxStream<S> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
        match self {
            &mut HttpxStream::CleartextStream(ref mut s) => s.write(buf),
            &mut HttpxStream::EncryptedStream(ref mut s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> Result<(), io::Error> {
        match self {
            &mut HttpxStream::CleartextStream(ref mut s) => s.flush(),
            &mut HttpxStream::EncryptedStream(ref mut s) => s.flush(),
        }
    }
}

impl<S: Read + Write> AsyncRead for HttpxStream<S> {
    unsafe fn prepare_uninitialized_buffer(&self, _buf: &mut [u8]) -> bool {
        // Not neccessary to zero out the buffer because it's not read
        // during the read() by any underlying streams.
        true
    }
}

impl<S: Read + Write + AsyncWrite> AsyncWrite for HttpxStream<S> {
    fn shutdown(&mut self) -> Poll<(), io::Error> {
        println!("SHUTDOWN HAS BEEN CALLED!");
        use openssl::ssl::Error;
        match self {
            &mut HttpxStream::CleartextStream(ref mut s) => s.shutdown(),
            &mut HttpxStream::EncryptedStream(ref mut s) => {
                match s.shutdown() {
                    Ok(_result) => Ok(Async::Ready(())),
                    Err(Error::ZeroReturn) => Ok(Async::Ready(())),
                    Err(Error::WantRead(_)) | Err(Error::WantWrite(_)) => Ok(Async::NotReady),
                    Err(Error::Stream(err)) => Err(err),
                    Err(Error::Ssl(err)) => Err(err.into()),
                    Err(_) => Err(io::Error::new(io::ErrorKind::Other, "SSL shutdown error")),
                }
            }
        }
    }
}

pub struct HttpxConnector {
    proxy_uri: Option<Uri>,
    reactor_handle: Handle,
    dns_executor: Rc<Executor<dns::DnsWorker>>,
    ssl_session_cache: SslSessionCache,
    ssl_connector: Option<SslConnector>,
}

impl HttpxConnector {
    pub fn new(reactor_handle: &Handle, dns_threads: usize) -> HttpxConnector {
        let pool = futures_cpupool::Builder::new()
            .name_prefix("httpx-dns-")
            .pool_size(dns_threads)
            .create();
        HttpxConnector {
            proxy_uri: None,
            reactor_handle: reactor_handle.clone(),
            dns_executor: Rc::new(pool),
            ssl_session_cache: SslSessionCache::new(),
            ssl_connector: None,
        }
    }

    fn validate_server_uri(uri: &Uri) -> Result<(), HttpxError> {
        match uri.scheme() {
            Some("http") | Some("https") => {},
            _ => return Err(param_err("unsupported URL scheme")),
        }
        if uri.host().is_none() {
            return Err(param_err("empty hostname in supplied URL"));
        }

        Ok(())
    }

    fn validate_proxy_uri(uri: &Uri) -> Result<(), HttpxError> {
        match uri.scheme() {
            Some("socks5") | Some("socks5h") => {},
            _ => return Err(param_err("unsupported proxy type")),
        }
        if uri.host().is_none() {
            return Err(param_err("proxy url with empty hostname"));
        }

        Ok(())
    }

    fn socks5_port_from_uri(uri: &Uri) -> u16 {
        uri.port().unwrap_or(8080)
    }

    fn http_port_from_uri(uri: &Uri) -> u16 {
        uri.port().unwrap_or_else(|| {
            let scheme = uri.scheme().unwrap_or("http");
            if scheme == "https" { 443 } else { 80 }
        })
    }

    #[async(boxed)]
    fn connect(
        server_uri: Uri,
        proxy_uri: Option<Uri>,
        reactor_handle: Handle,
        exec: Rc<Executor<dns::DnsWorker>>,
        ssl_session_cache: SslSessionCache,
        ssl_connector: Option<SslConnector>,
    ) -> Result<HttpxStream<TcpStream>, io::Error> {
        // TODO: convert entire HttpxConnector stack back to using io::Error.
        await!(
            HttpxConnector::connect_(
                server_uri,
                proxy_uri,
                reactor_handle,
                exec,
                ssl_session_cache,
                ssl_connector
            )
        ).map_err(|err| err.into())
    }

    #[async]
    fn connect_(
        server_uri: Uri,
        proxy_uri: Option<Uri>,
        reactor_handle: Handle,
        exec: Rc<Executor<dns::DnsWorker>>,
        ssl_session_cache: SslSessionCache,
        ssl_connector: Option<SslConnector>,
    ) -> Result<HttpxStream<TcpStream>, HttpxError> {
        HttpxConnector::validate_server_uri(&server_uri)?;
        if let &Some(ref uri) = &proxy_uri {
            HttpxConnector::validate_proxy_uri(uri)?;
        }

        let is_https = server_uri.scheme().map_or(false, |x| x == "https");
        let host_tuple = (
            server_uri.host().unwrap().to_owned(),
            Self::http_port_from_uri(&server_uri)
        );
        let stream = if let Some(x) = proxy_uri {
            await!(Self::connect_through_proxy(server_uri, x, reactor_handle, exec))?
        } else {
            await!(Self::connect_directly(server_uri, reactor_handle, exec))?
        };

        if !is_https {
            return Ok(HttpxStream::CleartextStream(stream));
        }

        let ssl_connector = if let Some(b) = ssl_connector {
            b
        } else {
            SslConnectorBuilder::new(SslMethod::tls())
                .map_err(|err| HttpxError::SslError(
                    "couldn't create SSL connector builder".to_owned(),
                    Some(err)))?
                .build()
        };

        if let Some(session) = ssl_session_cache.get(&host_tuple) {
            let mut conf = ssl_connector.configure()
                .map_err(|err| HttpxError::SslError(
                    "couldn't retrieve SSL connector configuration".to_owned(),
                    Some(err)))?;
            unsafe { conf.set_session(&session) }
                .map_err(|err| HttpxError::SslError(
                    "unable to assign SSL session to an OpenSSL context".to_owned(),
                    Some(err)))?;
        }

        // Initiate handshake by passing a non-blocking TcpStream to
        // SslConnector. SslConnector, being unaware of this, will try to
        // connect to remote host but will inevitably fail with E_WOULDBLOCK-
        // type of error.
        //
        // To run the handshake to completion we use SslConnectorFuture which
        // will complete the rest of handshake asynchronously.
        let connect_result = ssl_connector.connect(&host_tuple.0, stream);
        let ssl_stream = match connect_result {
            Ok(s) => s,
            Err(openssl::ssl::HandshakeError::Interrupted(s)) => {
                await!(SslConnectorFuture(Some(s)))?
            },
            Err(openssl::ssl::HandshakeError::SetupFailure(err)) => {
                return Err(HttpxError::SslError(
                    "stream setup failure".to_owned(), Some(err)).into());
            },
            Err(openssl::ssl::HandshakeError::Failure(_)) => {
                return Err(HttpxError::SslError(
                    "secure handshake failed".to_owned(), None).into());
            }
        };

        if !ssl_stream.ssl().session_reused() {
            if let Some(session) = ssl_stream.ssl().session() {
                ssl_session_cache.insert(host_tuple, session.to_owned());
            }
        }

        Ok(HttpxStream::EncryptedStream(ssl_stream))
    }

    #[async]
    fn connect_directly(
        server_uri: Uri,
        reactor_handle: Handle,
        exec: Rc<Executor<dns::DnsWorker>>,
    ) -> Result<TcpStream, HttpxError> {
        let server_static_ip = dns::resolve_static(server_uri.host().unwrap());
        let server_port = HttpxConnector::http_port_from_uri(&server_uri);

        let server_ips = match server_static_ip {
            Some(ip) => {
                vec![SocketAddr::new(ip, server_port)]
            }
            None => {
                await!(
                    dns::resolve(server_uri.host().unwrap(), &*exec)
                ).map_err(HttpxError::DnsError)?.iter().map(|x| {
                    SocketAddr::new(*x, server_port)
                }).collect()
            }
        };

        let nr_server_ips = server_ips.len();
        for server_idx in 0..nr_server_ips {
            let result = await!(
                TcpStream::connect(&server_ips[server_idx], &reactor_handle)
            ).map_err(|err| {
                let sa = server_ips[server_idx].clone();
                HttpxError::ConnectionError(sa, err)
            });

            match result {
                Ok(stream) => return Ok(stream),
                Err(err) => {
                    // Return error, if this is the last iteration.
                    if server_idx + 1 >= nr_server_ips {
                        return Err(err);
                    }
                }
            }
        }

        if nr_server_ips == 0 {
            let msg = "DNS query returned no A/AAAA records?";
            return Err(HttpxError::OtherError(msg.to_owned()));
        } else {
            panic!("BUG: unreachable!");
        }
    }

    #[async]
    fn connect_through_proxy(
        server_uri: Uri,
        proxy_uri: Uri,
        reactor_handle: Handle,
        exec: Rc<Executor<dns::DnsWorker>>,
    ) -> Result<TcpStream, HttpxError> {
        let proxy_static_ip = dns::resolve_static(proxy_uri.host().unwrap());
        let server_static_ip = dns::resolve_static(server_uri.host().unwrap());
        let proxy_port = HttpxConnector::socks5_port_from_uri(&proxy_uri);
        let server_port = HttpxConnector::http_port_from_uri(&server_uri);

        let proxy_ips = match proxy_static_ip {
            Some(ip) => vec![SocketAddr::new(ip, proxy_port)],
            None => {
                await!(dns::resolve(proxy_uri.host().unwrap(), &*exec))
                    .map_err(HttpxError::DnsError)?
                    .iter()
                    .map(|x| SocketAddr::new(*x, proxy_port))
                    .collect()
            }
        };

        let server_ips = match server_static_ip {
            Some(ip) => {
                let sa = SocketAddr::new(ip, server_port);
                vec![socks5::TunnelDestAddr::IpAddr(sa)]
            }
            None => {
                if proxy_uri.scheme().unwrap() == "socks5" {
                    await!(
                        dns::resolve(server_uri.host().unwrap(), &*exec)
                    ).map_err(HttpxError::DnsError)?.iter().map(|x| {
                        let sa = SocketAddr::new(*x, server_port);
                        socks5::TunnelDestAddr::IpAddr(sa)
                    }).collect()
                } else if proxy_uri.scheme().unwrap() == "socks5h" {
                    let h = server_uri.host().unwrap().to_owned();
                    vec![socks5::TunnelDestAddr::Hostname(h, server_port)]
                } else {
                    panic!("unsupported proxy scheme")
                }
            }
        };

        // Try to connect to each IP, until we find a working one.
        let nr_proxy_ips = proxy_ips.len();
        let nr_server_ips = server_ips.len();
        for proxy_idx in 0..nr_proxy_ips {
            for server_idx in 0..nr_server_ips {
                let result = await!(
                    socks5::Socks5Tunnel::connect(
                        &proxy_ips[proxy_idx],
                        &server_ips[server_idx],
                        &reactor_handle
                    )
                ).map_err(HttpxError::ProxyError);

                match result {
                    Ok(stream) => return Ok(stream),
                    Err(err) => {
                        // Return error, if this is the last iteration.
                        if proxy_idx + 1 >= nr_proxy_ips && server_idx + 1 >= nr_server_ips {
                           return Err(err);
                        }
                    }
                }
            }
        }

        if nr_proxy_ips == 0 {
            return Err(other_err("no proxy ip addresses found"));
        } else if nr_server_ips == 0 {
            return Err(other_err("no server ip addresses found"));
        } else {
            panic!("BUG: unreachable!");
        }
    }
}

impl Service for HttpxConnector {
    type Request = Uri;
    type Response = HttpxStream<TcpStream>;
    type Error = io::Error;
    type Future = Box<Future<Item = Self::Response, Error = Self::Error>>;

    fn call(&self, uri: Self::Request) -> Self::Future {
        HttpxConnector::connect(
            uri,
            self.proxy_uri.clone(),
            self.reactor_handle.clone(),
            self.dns_executor.clone(),
            self.ssl_session_cache.clone(),
            self.ssl_connector.clone()
        )
    }
}

pub struct HttpxConnectorBuilder {
    reactor_handle: Handle,
    proxy_uri: Option<Uri>,
    dns_executor: Option<Rc<Executor<dns::DnsWorker>>>,
    session_cache: Option<SslSessionCache>,
    ssl_connector: Option<SslConnector>,
}

impl HttpxConnectorBuilder {
    pub fn new(reactor_handle: &Handle) -> HttpxConnectorBuilder {
        HttpxConnectorBuilder {
            proxy_uri: None,
            reactor_handle: reactor_handle.clone(),
            dns_executor: None,
            session_cache: None,
            ssl_connector: None,
        }
    }

    pub fn default_executor(mut self, threads: usize) -> Self {
        let pool = futures_cpupool::Builder::new()
            .name_prefix("httpx-dns-")
            .pool_size(threads)
            .create();
        self.dns_executor = Some(Rc::new(pool));
        self
    }

    pub fn custom_executor<E>(mut self, dns_executor: E) -> Self
    where E: Executor<dns::DnsWorker> + 'static {
        self.dns_executor = Some(Rc::new(dns_executor));
        self
    }

    pub fn ssl_connector(mut self, connector: SslConnector) -> Self {
        self.ssl_connector = Some(connector);
        self
    }

    pub fn proxy(mut self, proxy_uri: Uri) -> Self {
        self.proxy_uri = Some(proxy_uri);
        self
    }

    pub fn build(mut self) -> HttpxConnector {
        if self.dns_executor.is_none() {
            self = self.default_executor(2);
        }
        HttpxConnector {
            proxy_uri: self.proxy_uri,
            reactor_handle: self.reactor_handle,
            dns_executor: self.dns_executor.unwrap(),
            ssl_session_cache: self.session_cache.unwrap_or(
                SslSessionCache::new()
            ),
            ssl_connector: self.ssl_connector,
        }
    }
}

struct HttpxConnectorFuture {
    handle: Handle,
    server_uri: Uri,
    proxy_uri: Option<Uri>,
}

fn param_err(msg: &str) -> HttpxError {
    HttpxError::InvalidParameter(msg.to_owned())
}

fn other_err(msg: &str) -> HttpxError {
    HttpxError::OtherError(msg.to_owned())
}