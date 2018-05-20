#![feature(proc_macro, generators)]

#[macro_use] extern crate failure;
extern crate futures_await as futures;
extern crate futures_cpupool;
extern crate hyper;
extern crate openssl;
extern crate tokio_core;
extern crate tokio_io;
extern crate tokio_service;

pub mod dns;
pub mod socks5;
pub mod httpx;