use std::{self, io};
use std::convert::From;
use std::net::SocketAddr;

use failure::{self, Fail};
use futures::prelude::*;
use futures::Future;

use tokio_core::reactor::Handle;
use tokio_core::net::TcpStream;
use tokio_io::io::{read_exact, write_all};

pub struct Socks5Tunnel();

impl Socks5Tunnel {
    const FIELD_PROTOV5: u8         = 0x05;
    const FIELD_AUTH_NONE: u8       = 0x00;
    //const FIELD_AUTH_USERPASSWD: u8 = 0x02;
    const FIELD_CMD_CONNECT: u8     = 0x01;
    //const FIELD_CMD_BIND: u8        = 0x02;
    //const FIELD_CMD_UDPASSOC: u8    = 0x03;
    const FIELD_ADR_V4: u8          = 0x01;
    const FIELD_ADR_V6: u8          = 0x04;
    const FIELD_ADR_HOSTNAME: u8    = 0x03;

    pub fn connect(
        proxy_addr: &SocketAddr,
        server_addr: &TunnelDestAddr,
        handle: &Handle
    ) -> impl Future<Item = TcpStream, Error = failure::Error> {
        // This is function is just a scaffolding over a real one.
        // futures-await does not support using parameters passed as
        // references, so we do all our copying here.
        Socks5Tunnel::connect_(
            proxy_addr.clone(),
            server_addr.clone(),
            handle.clone())
    }

    #[async]
    fn connect_(
        proxy_addr: SocketAddr,
        server_addr: TunnelDestAddr,
        handle: Handle
    ) -> Result<TcpStream, failure::Error> {
        // Establish connection with proxy server, and negotiate auth method.
        let stream = Socks5Tunnel::lift_error(
            await!(TcpStream::connect(&proxy_addr, &handle))
        )?;

        // We do not have support for the authentication ATM, request a free
        // pass from the server.
        let handshaking = write_all(stream, [
            Socks5Tunnel::FIELD_PROTOV5,   // Protocol version
            1,                             // Number of auth methods
            Socks5Tunnel::FIELD_AUTH_NONE, // Auth method: no auth
        ]).and_then(|(s, _)| {
            // Read a 2-byte response from server with the auth
            // method it has chosen.
            read_exact(s, [0, 0])
        });

        let (stream, handshake_resp) = Socks5Tunnel::lift_error(
            await!(handshaking)
        )?;

        // First byte in the response is protocol version.
        // Second byte is the auth method the server chose.
        if handshake_resp[1] != 0x00 {
            let msg = format!(
                "Proxy server refused to accept our auth method (0x{:X})",
                handshake_resp[1]);
            return Err(Socks5Error::GeneralFailure(msg).into());
        }

        // Request proxy server to setup a TCP tunnel to a remote server.
        // The response to this message has variable length depending on the
        // returned ATYP field (4th byte).
        //
        // We capture 5 bytes from the message during first read. To avoid
        // an extra invocation of read_all() we read an extra byte past the
        // ATYP field. This byte indicates the length of the BND.ADDR field, if
        // it contains a hostname (indicated by ATYP). Otherwise, it's the
        // first octet of BND.ADDR IP address.
        let message = Socks5Tunnel::make_connect_message(&server_addr)?;
        let tunneling = write_all(stream, message)
            .and_then(|(s, _)| read_exact(s, [0; 5]));
        let (stream, response_preamble) = Socks5Tunnel::lift_error(
            await!(tunneling)
        )?;

        Socks5Tunnel::check_socks5_error_code(response_preamble[1])?;

        // Discard BND.ADDR & BND.PORT for now.
        // TODO: Should this be supported?
        let discarding = match response_preamble[3] {
            Socks5Tunnel::FIELD_ADR_V4 => {
                // Read 1 octet less because it was captured during the
                // previous read.
                read_exact(stream, vec![0; 4 - 1 + 2])
            },
            Socks5Tunnel::FIELD_ADR_V6 => {
                read_exact(stream, vec![0; 16 - 1 + 2])
            },
            Socks5Tunnel::FIELD_ADR_HOSTNAME => {
                read_exact(stream, vec![0; response_preamble[4] as usize])
            },
            _ => return Err(Socks5Error::GeneralFailure(
                    "Unexpected address type".to_owned()).into()),
        };

        let (stream, _whatever) = Socks5Tunnel::lift_error(
            await!(discarding)
        )?;
        Ok(stream)
    }

    fn lift_error<T>(t: Result<T, io::Error>) -> Result<T, Socks5Error> {
        match t {
            Ok(x) => Ok(x),
            Err(err) => Err(Socks5Error::ProxyConnectionFailed(err).into()),
        }
    }

    fn make_connect_message(
        server_addr: &TunnelDestAddr
    ) -> Result<Vec<u8>, Socks5Error> {
        let mut message = Vec::<u8>::with_capacity(32);

        // Message preamble.
        message.extend(&[
            Socks5Tunnel::FIELD_PROTOV5,     // Protocol version
            Socks5Tunnel::FIELD_CMD_CONNECT, // Command
            0x00,                            // Reserved
        ]);

        // Add destination address info to the message.
        let server_port = match server_addr {
            &TunnelDestAddr::IpAddr(SocketAddr::V4(ref ipv4)) => {
                // Append address type, IPv4 in this case.
                message.push(Socks5Tunnel::FIELD_ADR_V4);
                message.extend(&ipv4.ip().octets());
                ipv4.port()
            },
            &TunnelDestAddr::IpAddr(SocketAddr::V6(ref ipv6)) => {
                message.push(Socks5Tunnel::FIELD_ADR_V6);
                message.extend(&ipv6.ip().octets());
                ipv6.port()
            },
            &TunnelDestAddr::Hostname(ref h, p) => {
                message.push(Socks5Tunnel::FIELD_ADR_HOSTNAME);

                if h.len() > u8::max_value().into() {
                    let msg = "Hostname length exceeds 255 characters";
                    return Err(Socks5Error::GeneralFailure(msg.into()).into());
                }

                // Hostname is preceded by its length.
                message.push(h.len() as u8);
                message.extend(h.as_bytes());
                p
            }
        };

        let port_bytes: [u8; 2] = unsafe {
            std::mem::transmute(server_port.to_be())
        };
        message.extend(&port_bytes);
        Ok(message)
    }

    fn check_socks5_error_code(errc: u8) -> Result<(), Socks5Error> {
        if errc == 0 {
            return Ok(());
        }

        let msg = match errc {
            3 => Some("Remote host's network is unreachable"),
            4 => Some("Remote host is unreachable"),
            5 => Some("Remote host has refused connection"),
            _ => None,
        };
        if msg.is_some() {
            return Err(Socks5Error::RemoteConnectionFailed(
                msg.unwrap().into()).into());
        }
        let msg = match errc {
            1 => Some("General proxy server failure"),
            2 => Some("Proxy server refused to allow access"),
            6 => Some("TTL expired"),
            7 => Some("Command not supported"),
            8 => Some("Address type not supported"),
            _ => Some("Proxy server returned an unknown error"),
        }.unwrap().to_owned();
        return Err(Socks5Error::GeneralFailure(msg).into());
    }
}

#[derive(Debug, Fail)]
pub enum Socks5Error {
    #[fail(display = "Coudln't connect to proxy server")]
    ProxyConnectionFailed(#[cause] io::Error),
    #[fail(display = "Proxy server is unable to reach remote server ({})", _0)]
    RemoteConnectionFailed(String),
    #[fail(display = "General proxy server failure ({})", _0)]
    GeneralFailure(String),
}

#[derive(Clone)]
pub enum TunnelDestAddr {
    IpAddr(SocketAddr),
    Hostname(String, u16),
}

impl From<SocketAddr> for TunnelDestAddr {
    fn from(t: SocketAddr) -> TunnelDestAddr {
        TunnelDestAddr::IpAddr(t)
    }
}

impl<'a> From<(&'a str, u16)> for TunnelDestAddr {
    fn from(t: (&'a str, u16)) -> TunnelDestAddr {
        TunnelDestAddr::Hostname(t.0.into(), t.1)
    }
}