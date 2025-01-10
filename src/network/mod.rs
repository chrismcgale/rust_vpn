pub mod connection;
pub mod tcp_client;
pub mod tcp_server;

use std::{
    io::{Read, Write},
    net::TcpStream as StdTcpStream,
    time::Duration,
};
