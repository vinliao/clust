// get stuff from relay

use serde_json::json;
use tungstenite::{connect, Message};
use url::Url;

pub fn get_event() {
    let url_string = "wss://relayer.fiatjaf.com";
    let url = Url::parse(url_string).unwrap();

    let (mut socket, response) = connect(url).expect("Can't connect");

    println!("Connected to the server");
    println!("Response HTTP code: {}", response.status());
    println!("Response contains the following headers:");

    for (ref header, _value) in response.headers() {
        println!("* {}", header);
    }

    // format: ["GET", <id>, <filter>]
    // id is random string to represent the websocket connection
    // filter is the information to get (see nip-01)
    let filter = json!({
        "ids": ["44f46af1331dd3f8a77b92b070d8c639387b2336f2ec9eac1d77f0ab7083b9b1"]
    });

    let payload = json!(["REQ", "p380vv138", filter]);
    println!("{}", payload);

    socket
        .write_message(Message::Text(payload.to_string()))
        .unwrap();

    loop {
        let msg = socket.read_message().expect("Error reading message");
        println!("Received: {}", msg);
    }

    // socket.close(None);
}
