use std::{thread};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration};
use local_utils::tcp;

fn serve_connection(stream: &mut TcpStream) {
    println!("inside server_connection!");
    stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    stream.set_write_timeout(Some(Duration::from_secs(2))).unwrap();

    loop {
        match tcp::get_message(stream) {
            Ok(msg) => {
                println!("Got message: {:?}", msg);
                tcp::send_message(stream, &msg);
            }
            Err(e) => {
                println!("{}", e);
                return
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
