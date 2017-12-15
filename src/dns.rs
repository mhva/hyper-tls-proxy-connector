use std::{self, io};
use std::error::Error;
use std::net::{IpAddr, SocketAddr,ToSocketAddrs};

use failure::{self, Fail};

use futures::prelude::*;
use futures::{Async, Future, future, Poll};
use futures::future::Executor;
use futures::sync::oneshot;

#[derive(Debug, Fail)]
#[fail(display = "Failed to resolve host address")]
pub struct ResolveError(String);

pub fn resolve(domain: &str, executor: &Executor<DnsWorker>) -> DnsFuture {
    let (tx, rx) = oneshot::channel::<Result<Vec<IpAddr>, io::Error>>();
    let future = DnsWorker {
        domain: domain.to_owned(),
        tx_chan: DnsWorkerOneshotChannel::new(tx),
    };
    executor.execute(future);
    DnsFuture(rx)
}

pub fn resolve_static(domain: &str) -> Option<IpAddr> {
    use std::str::FromStr;
    match IpAddr::from_str(domain) {
        Ok(ip_addr) => Some(ip_addr),
        _ => None,
    }
}

pub struct DnsWorker {
    domain: String,
    tx_chan: DnsWorkerOneshotChannel<Result<Vec<IpAddr>, io::Error>>,
}

impl Future for DnsWorker {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let addrs: Result<Vec<IpAddr>, io::Error> = (&*self.domain, 0)
            .to_socket_addrs()
            .map(|addr_it| {
                addr_it.map(|sa| {
                    match sa {
                        SocketAddr::V4(ipv4) => ipv4.ip().clone().into(),
                        SocketAddr::V6(ipv6) => ipv6.ip().clone().into(),
                    }
                }).collect()
            });
        self.tx_chan.send(addrs);
        Ok(Async::Ready(()))
    }
}

pub struct DnsFuture(oneshot::Receiver<Result<Vec<IpAddr>, io::Error>>);

impl Future for DnsFuture {
    type Item = Vec<IpAddr>;
    type Error = failure::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self.0.poll() {
            Ok(Async::Ready(result)) => {
                result
                    .map(|x| Async::Ready(x))
                    .map_err(|err| {
                        let msg = err.description().to_owned();
                        ResolveError(msg).into()
                    })
            },
            Ok(Async::NotReady) => Ok(Async::NotReady),
            Err(_) => {
                let msg = "resolver task got dropped".to_owned();
                Err(ResolveError(msg).into())
            }
        }
    }
}

/// Wrapper around `futures::sync::oneshot` that does not consume itself after
/// send(), allowing its use in borrowed contexts.
enum DnsWorkerOneshotChannel<T> {
    Active(oneshot::Sender<T>),
    Closed,
}

impl<T> DnsWorkerOneshotChannel<T> {
    fn new(tx: oneshot::Sender<T>) -> Self {
        DnsWorkerOneshotChannel::Active(tx)
    }

    fn send(&mut self, data: T) -> Result<(), T> {
        let chan = std::mem::replace(self, DnsWorkerOneshotChannel::Closed);
        match chan {
            DnsWorkerOneshotChannel::Active(tx) => tx.send(data),
            DnsWorkerOneshotChannel::Closed     => Err(data)
        }
    }
}