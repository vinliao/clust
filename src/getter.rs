// get stuff from relay

use serde_json::json;
use tungstenite::{connect, Message};
use url::Url;

fn get(payload: String) -> String {
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

    let msg = socket.read_message().expect("Error reading message");
    return msg.to_text().unwrap().to_string(); 
}

// request format: ["REQ", <id>, <filter>]
// id is random string to represent the websocket connection
// filter is the information to get (see nip-01)

pub fn get_event(id: String) -> String {
    let filter = json!({
        "ids": [id],
    });

    let payload = json!(["REQ", "foobar", filter]);

    return get(payload.to_string());
}

pub fn get_dm(pubkey: String) -> String {
    let filter = json!({
        "kinds": [4],
        "#p": [pubkey],
    });

    let payload = json!(["REQ", "foobar", filter]);

    return get(payload.to_string());
}
