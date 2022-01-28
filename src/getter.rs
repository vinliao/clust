// get stuff from relay

use serde_json::json;
use std::fs;
use tungstenite::{connect, Message};
use url::Url;

fn get(payload: String) {
    let url_string = "wss://relayer.fiatjaf.com";
    // let url_string = "wss://nostr-pub.wellorder.net";
    let url = Url::parse(url_string).unwrap();

    let (mut socket, response) = connect(url).expect("Can't connect");

    println!("Connected to the server");
    println!("Response HTTP code: {}", response.status());
    println!("Response contains the following headers:");

    for (ref header, _value) in response.headers() {
        println!("* {}", header);
    }

    socket.write_message(Message::Text(payload)).unwrap();

    loop {
        let msg = socket.read_message().expect("Error reading message");
        println!("Received: {}", msg);
    }

    // socket.close(None);
}

// request format: ["REQ", <id>, <filter>]
// id is random string to represent the websocket connection
// filter is the information to get (see nip-01)

pub fn get_event(id: String) {
    let filter = json!({
        "ids": [id],
    });

    let payload = json!(["REQ", "p380vv138", filter]);
    println!("{}", payload);

    get(payload.to_string());
}

pub fn get_profile(pubkey: String) {
    let filter = json!({
        "authors": [pubkey],
    });

    let payload = json!(["REQ", "p380vv138", filter]);
    println!("{}", payload);

    get(payload.to_string());
}

pub fn get_event_from_subscription() {
    let res = fs::read_to_string("clust.json");

    if res.is_ok() {
        // if config file exist
        let data = res.unwrap();
        let json_data: serde_json::Value = serde_json::from_str(&data).expect("Fail to parse");
        let subscription = &json_data["subscription"];

        let filter = json!({
            "authors": subscription,
        });

        let payload = json!(["REQ", "p380vv138", filter]);
        println!("{}", payload);

        get(payload.to_string());
    } else {
        // if config file doesn't exist
        println!("Can't find config file!")
    }
}
