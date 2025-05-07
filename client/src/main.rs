use std::fmt::Debug;
use std::net::{Shutdown, TcpStream};
use std::io::{BufRead, BufReader, Write};
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
        send_message(sock, &msg);

        let msg = get_message(sock);
        println!("Got : {:?}", msg)
    }
}

fn get_message(sock: &mut TcpStream) -> String {
    let mut buffer = String::new();
    let mut reader = BufReader::new(sock.try_clone().unwrap());

    match reader.read_line(&mut buffer) {
        Ok(_) => {
            buffer
        }
        Err(e) => {
            panic!("could not read from host - server might not be running: {}", e)
        }
    }
}
fn send_message(sock: &mut TcpStream, msg: &str) {
    match sock.write_all(&msg.as_bytes()) {
        Ok(_) => {
            println!("Sent : {:?}", &msg)
        }
        Err(e) => {
            panic!("could not write to host - server might not be running: {}", e)
        }
    }
}

fn main() {
    let mut pending_jobs: Vec<JoinHandle<()>> = Vec::new();
    for _ in 0..10 {
        pending_jobs.push(thread::spawn(|| {
            let id = thread::current().id();
            let mut sock = TcpStream::connect("127.0.0.1:8080")
                .expect("could not connect to host - server might not be running");
            send_messages(
                &mut sock,
                format!("{:?}", id).to_owned().as_str()
            );

            sock.shutdown(Shutdown::Both).unwrap();
            return;
        }));
    }

    while let Some(handle) = pending_jobs.pop() {
        handle.join().unwrap();
    }
    println!("Done sending stuff!")
}
