use url::Url;
use tungstenite::{connect, Message};

// publishes signed dummy event to relay 

// struct Event {
//     id: String,
//     pubkey: String,
//     created_at: u32,
//     kind: u32,
//     tags: [String; 0],
//     content: String,
//     sig: String
// }

pub fn publish() {
    // todo: add event as params

    // let url_string = "ws://localhost:8080";
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
    // todo: use struct for this
    let event = r#"["EVENT", 
{
  "id": "4d84e4c12ff5ff2a74eb7febfdec6c72ce38b769dc7143c02fcdffc108ced01c",
  "pubkey": "5b5e64c8c9145b9c1d89bc7aee3b1829c2f6c6a20b3b44360b740d32de3cfdec",
  "created_at": 1643171089,
  "kind": 1,
  "tags": [],
  "content": "From Nostrandom https://nostrandom.netlify.app",
  "sig": "88026d93306dafa28248bcdf6bf69f4e8dd6a9933b2f193b2c6a95cf1d178c670a5c689be062c08fd53bdcb677d8e34614c0c87044364fb215a721d9fb7fa53b"
}
]
"#;

    socket.write_message(Message::Text(event.to_string())).unwrap();

    loop {
        let msg = socket.read_message().expect("Error reading message");
        println!("Received: {}", msg);
    }

    // socket.close(None);
}
