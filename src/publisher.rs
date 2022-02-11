// publishes signed event to relay

use serde_json::json;
use tungstenite::{connect, Message};
use url::Url;

pub fn publish(event: serde_json::Value) {
    let url_string = "wss://nostr-pub.wellorder.net";
    // let url_string = "wss://relayer.fiatjaf.com";
    let url = Url::parse(url_string).unwrap();

    let (mut socket, response) = connect(url).expect("Can't connect");

    println!("Connected to the server");
    println!("Response HTTP code: {}", response.status());
    println!("Response contains the following headers:");

    for (ref header, _value) in response.headers() {
        println!("* {}", header);
    }

    // format: ["EVENT", event]
    // the second event is the json
    let payload = json!(["EVENT", event]);
    socket
        .write_message(Message::Text(payload.to_string()))
        .unwrap();

    let msg = socket.read_message().expect("Error reading message");
    println!("Received: {}", msg);
}

pub fn publish_raw(event: String) {
    let url_string = "wss://nostr-pub.wellorder.net";
    // let url_string = "wss://relayer.fiatjaf.com";
    let url = Url::parse(url_string).unwrap();

    let (mut socket, response) = connect(url).expect("Can't connect");

    println!("Connected to the server");
    println!("Response HTTP code: {}", response.status());
    println!("Response contains the following headers:");

    for (ref header, _value) in response.headers() {
        println!("* {}", header);
    }

    // format: ["EVENT", event]
    // the second event is the json
    let payload = format!("[{}, {}]", "\"EVENT\"", event);
    socket.write_message(Message::Text(payload.to_string())).unwrap();

    let msg = socket.read_message().expect("Error reading message");
    println!("Received: {}", msg);
}