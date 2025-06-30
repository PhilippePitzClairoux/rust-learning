use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;

use crate::errors::Tcp as TcpError;


pub fn read_message(sock: &mut TcpStream) -> Result<String, TcpError> {
    let mut buffer = String::new();
    let mut reader = BufReader::new(sock.try_clone().unwrap());

    match reader.read_line(&mut buffer) {
        Ok(len) => {
            if len == 0 {
                return Err(TcpError::ConnectionClosed)
            }

            Ok(buffer)
        }
        Err(_) => Err(TcpError::ReadMessageFailed),
    }
}

pub fn send_message(sock: &mut TcpStream, msg: &str) -> Result<(), TcpError> {
    match sock.write_all(&msg.as_bytes()) {
        Ok(_) => Ok(()),
        Err(_) => Err(TcpError::SendMessageFailed),
    }
}