// publishes signed event to relay 

use url::Url;
use tungstenite::{connect, Message};
use serde_json::json;

pub fn publish(event: serde_json::Value) {
    // let url_string = "ws://localhost:8080";
    // let url_string = "wss://nostr-pub.wellorder.net";
    let url_string = "wss://relayer.fiatjaf.com";
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
    println!("{}", payload);

    socket.write_message(Message::Text(payload.to_string())).unwrap();

    loop {
        let msg = socket.read_message().expect("Error reading message");
        println!("Received: {}", msg);
    }

    // socket.close(None);
}
