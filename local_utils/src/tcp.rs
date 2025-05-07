use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::fmt;

// ConnectionClosed is an error return by get_message
// when a TcpStream.read() returns nothing 
#[derive(Debug, Clone)]
pub struct ConnectionClosed;

impl fmt::Display for ConnectionClosed {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "connection closed")
    }
}

pub fn read_message(sock: &mut TcpStream) -> Result<String, ConnectionClosed> {
    let mut buffer = String::new();
    let mut reader = BufReader::new(sock.try_clone().unwrap());

    match reader.read_line(&mut buffer) {
        Ok(len) => {
            if len == 0 {
                return Err(ConnectionClosed)
            }

            Ok(buffer)
        }
        Err(e) => {
            panic!("could not read from host - server might not be running: {}", e)
        }
    }
}

pub fn send_message(sock: &mut TcpStream, msg: &str) {
    match sock.write_all(&msg.as_bytes()) {
        Ok(_) => {
            println!("Sent : {:?}", &msg)
        }
        Err(e) => {
            panic!("could not write to host - server might not be running: {}", e)
        }
    }
}