use std::fmt::Debug;
use std::net::{Shutdown, TcpStream};
use local_utils::tcp;
use std::thread;
use std::thread::{JoinHandle};

const MESSAGES: &[&str] = &[
    "Hello there!",
    "Damn son!!",
    "Well well well, look who's here...",
    "GET OUT OF MY SWAAAAMP"
];

fn send_messages(sock: &mut TcpStream, name: &str) {
    for i in 0..MESSAGES.len() {
        let msg = format!("{} says {:?}\n", name, MESSAGES[i]).as_str().to_owned();
        tcp::send_message(sock, &msg);

        let msg = tcp::get_message(sock);
        println!("Got : {:?}", msg)
    }
}

fn main() {
    let mut pending_jobs: Vec<JoinHandle<()>> = Vec::new();
    for _ in 0..10 {
        pending_jobs.push(thread::spawn(|| {
            let id = thread::current().id();
            match &mut TcpStream::connect("127.0.0.1:8080") {
                Ok(sock) => {
                    send_messages(sock,
                        format!("{:?}", id).to_owned().as_str()
                    );

                    sock.shutdown(Shutdown::Both).unwrap();
                }
                Err(e) => {
                    println!("{}", e);
                }
            }
        }));
    }

    while let Some(handle) = pending_jobs.pop() {
        handle.join().unwrap();
    }
    println!("Done sending stuff!")
}
