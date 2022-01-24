use url::Url;
use tungstenite::{connect, Message};
use std::fs;
use std::path::Path;

// publishes signed event to local dummy websocket

fn get_event() -> String {
    return fs::read_to_string("signed_event.json").expect("Unable to read file");
}

pub fn publish() {
    // todo: add event as params

    // let url_string = "wss://nostr.rocks";
    let url_string = "ws://localhost:8080";
    let url = url::Url::parse(url_string).unwrap();

    let (mut socket, response) = connect(url).expect("Can't connect");

    println!("Connected to the server");
    println!("Response HTTP code: {}", response.status());
    println!("Response contains the following headers:");

    for (ref header, _value) in response.headers() {
        println!("* {}", header);
    }

    let event = get_event();

    socket.write_message(Message::Text(event.into())).unwrap();

    loop {
        let msg = socket.read_message().expect("Error reading message");
        println!("Received: {}", msg);
    }
}
