use std::{thread};
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration};

fn serve_connection(stream: &mut TcpStream) {
    println!("inside server_connection!");
    stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    stream.set_write_timeout(Some(Duration::from_secs(2))).unwrap();

    loop {
        let mut buffer = String::new();
        let mut bff = BufReader::new(stream.try_clone().unwrap());

        match bff.read_line(&mut buffer) {
            Ok(size) => {
                if size == 0 {
                    println!("Client disconnected (read 0 bytes)!");
                    return;
                }

                println!("Got a message ({:?} bytes) : {}", size, buffer.strip_suffix("\n").unwrap());
                stream.write(buffer.as_bytes())
                    .expect("could not write to socket");
            }

            Err(error) => {
                println!("Could not read from stream : {:?}", error);
                println!("Leaving function...");
                return;
            }
        }


    }
}

fn main() {
    let listener = TcpListener::bind("127.0.0.1:8080")
                                .unwrap_or_else(|e| panic!("could not bind : {:?}", e));

    for stream in listener.incoming() {
        match stream {
            Ok(mut s) => {
                thread::spawn(move || serve_connection(&mut s));
            }

            Err(e) => {
                panic!("could not serve connection : {:?}", e)
            }
        }
    }
}
