use std::{self, io};
use std::convert::From;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

use futures::prelude::*;
use futures::{self, Future, future, Poll, Stream};

use tokio_core::reactor::Handle;
use tokio_core::net::TcpStream;
use tokio_io::io::{read_exact, write_all};

pub struct Socks5Tunnel();

impl Socks5Tunnel {
    const FIELD_PROTOV5: u8         = 0x05;
    const FIELD_AUTH_NONE: u8       = 0x00;
    const FIELD_AUTH_USERPASSWD: u8 = 0x02;
    const FIELD_CMD_CONNECT: u8     = 0x01;
    const FIELD_CMD_BIND: u8        = 0x02;
    const FIELD_CMD_UDPASSOC: u8    = 0x03;
    const FIELD_ADR_V4: u8          = 0x01;
    const FIELD_ADR_V6: u8          = 0x04;
    const FIELD_ADR_HOSTNAME: u8    = 0x03;

    pub fn connect(
        proxy_addr: &SocketAddr,
        server_addr: &TunnelDestAddr,
        handle: &Handle
    ) -> impl Future<Item = TcpStream, Error = io::Error> {
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
    ) -> Result<TcpStream, io::Error> {
        // Establish connection with proxy server, and negotiate auth method.
        let stream = await!(TcpStream::connect(&proxy_addr, &handle)).map_err(|err| {
            wrap_io_err("unable to connect to proxy server ({})", err)
        })?;

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

        let (stream, handshake_resp) = await!(handshaking).map_err(|err| {
            wrap_io_err("proxy handshake failure ({})", err)
        })?;

        // First byte in the response is protocol version.
        // Second byte is the auth method the server chose.
        if handshake_resp[1] != 0x00 {
            let msg = format!(
                "proxy did not accept our auth method (0x{:02X})",
                handshake_resp[1]
            );
            return Err(other_err(&msg));
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
        let (stream, response_preamble) = await!(tunneling).map_err(|err| {
            wrap_io_err("proxy handshake failure ({})", err)
        })?;

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
            _ => {
                let msg = format!(
                    "proxy response contains unsupported BND.ADDR (0x{:02X})",
                    response_preamble[3]
                );
                return Err(other_err(&msg));
            }
        };

        let (stream, _whatever) = await!(discarding).map_err(|err| {
            wrap_io_err("proxy handshake failure ({})", err)
        })?;
        Ok(stream)
    }

    fn make_connect_message(
        server_addr: &TunnelDestAddr
    ) -> Result<Vec<u8>, io::Error> {
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
                    return other_err("hostname is too long");
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

    fn check_socks5_error_code(errc: u8) -> Result<(), io::Error> {
        if errc == 0 {
            return Ok(());
        }

        let err = match errc {
            3 => Some("proxy reports that host's network is unreachable"),
            4 => Some("proxy reports that host is unreachable"),
            5 => Some("proxy reports that host has refused connection"),
            _ => None,
        };
        if err.is_some() {
            let msg = format!(
                "proxy server was unable to connect to destination host ({})",
                err
            );
            return Err(other_err(&msg));
        }
        let err = match errc {
            1 => Some("general proxy server failure"),
            2 => Some("proxy server refused to allow access"),
            6 => Some("ttl expired"),
            7 => Some("command not supported"),
            8 => Some("address type not supported"),
            _ => Some("unknown error"),
        }.unwrap().to_owned();
        let msg = format!("proxy server returned an error ({})", err);
        return Err(other_err(&msg));
    }
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

fn wrap_io_err(msg: &str, err: io::Error) -> io::Error {
    let kind = err.kind();
    let msg = format!("{} ({})", msg, err);
    io::Error::new(kind, msg)
}

fn other_err(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Other, msg)
}