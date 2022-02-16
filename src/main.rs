use clap::Parser;
mod getter;
mod publisher;
mod util;
use futures_channel;
use futures_util::{future, pin_mut, StreamExt};
use tokio::io::AsyncReadExt;
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};
use url;

use serde_json::json;
use tungstenite::connect;

#[derive(Parser)]
struct Cli {
    command: String,

    #[clap(default_value = "")]
    subcommand: String,

    #[clap(default_value = "")]
    subcommand_2: String,
}

fn main() {
    let args = Cli::parse();

    // messy as hell, can be refactored
    if args.command == "generate-keypair" {
        let (privkey, pubkey) = util::generate_key();

        println!("Private key: {}", privkey.display_secret().to_string());
        println!("Public key: {}", pubkey.to_string());
    } else if args.command == "set-private" {
        util::set_privkey(args.subcommand);
    } else if args.command == "init" {
        util::generate_config();
    } else if args.command == "publish-raw" {
        publisher::publish_raw(args.subcommand);
    } else if args.command == "get-event" {
        let event = getter::get_event(args.subcommand);
        println!("{}", event);
    } else if args.command == "create-dm" {
        let recipient_pub_hex = util::contact_pubkey_from_name(&args.subcommand).unwrap();
        println!(
            "{}",
            util::create_dm_event(&recipient_pub_hex, &args.subcommand_2)
        );
    } else if args.command == "get-dm" {
        let pubkey_hex = util::get_pubkey().to_string();
        let raw_string = getter::get_dm(pubkey_hex);
        let payload: serde_json::Value = serde_json::from_str(&raw_string).unwrap();
        println!("{}", payload);
        // let dm = util::decrypt_dm(payload[2].clone());
        // println!("{}", dm);
    } else if args.command == "add-contact" {
        util::add_contact(&args.subcommand, &args.subcommand_2);
        let event = util::create_announcement_event(&args.subcommand_2);
        publisher::publish(event);
    } else if args.command == "change-contact-pubkey" {
        util::change_contact_pubkey(args.subcommand, args.subcommand_2);
    } else if args.command == "chat" {
        // todo: get this value from config file instead
        // todo: pass the contact name to the fn
        run("wss://nostr-pub.wellorder.net", &args.subcommand);
        // run("ws://localhost:8080");
    } else if args.command == "announce" {
        let event = util::create_announcement_event(&args.subcommand);
        publisher::publish(event);
    } else if args.command == "inbox" {
        // this pulls all the nip-04 event and input it as contact list
        // this consumes what `clust announce` puts out
        add_new_contact();
    } else if args.command == "get-pubkey" {
        println!("Pubkey: {}", util::get_pubkey().to_string());
    }
}

#[tokio::main]
async fn run(connect_addr: &str, contact_name: &str) {
    let url = url::Url::parse(connect_addr).unwrap();

    // get shared key here...
    let recipient_pubkey_hex = util::contact_pubkey_from_name(contact_name).unwrap();
    let shared_key = util::get_shared_key_from_hex(&recipient_pubkey_hex);

    let (stdin_tx, stdin_rx) = futures_channel::mpsc::unbounded();
    tokio::spawn(read_stdin(stdin_tx, recipient_pubkey_hex));

    let (ws_stream, _) = connect_async(url).await.expect("Failed to connect");
    println!("WebSocket handshake has been successfully completed");

    let (write, read) = ws_stream.split();
    let stdin_to_ws = stdin_rx.map(Ok).forward(write);

    let ws_to_stdout = {
        read.for_each(|message| async {
            // data is the stuff from relay, decrypt here

            let data = message.unwrap().into_data();
            let data_string = String::from_utf8(data).unwrap();
            let payload: serde_json::Value = serde_json::from_str(&data_string).unwrap();
            let event = payload[2].clone();

            // if identity from others, display "name: "
            // otherwise, display "you: "
            let inner_dm = util::decrypt_dm(event, shared_key);
            let dm = util::decrypt_dm(serde_json::from_str(&inner_dm).unwrap(), shared_key);
            println!("{}", dm);

            // below is the official way to do it, but it prints out nothing
            // let vec = dm.as_bytes();
            // tokio::io::stdout().write_all(&vec).await.unwrap();
        })
    };

    pin_mut!(stdin_to_ws, ws_to_stdout);
    future::select(stdin_to_ws, ws_to_stdout).await;
}

// stdin stuff, modify input here
async fn read_stdin(
    tx: futures_channel::mpsc::UnboundedSender<Message>,
    recipient_pub_hex: String,
) {
    let mut stdin = tokio::io::stdin();

    // send initial payload before capturing stdin
    let shared_sha = util::get_sha_shared_key(&recipient_pub_hex);
    let initial_payload = util::to_public_dm_request(&shared_sha);
    println!("{}", initial_payload);
    tx.unbounded_send(Message::text(initial_payload)).unwrap();

    loop {
        let mut buf = vec![0; 1024];
        let n = match stdin.read(&mut buf).await {
            Err(_) | Ok(0) => break,
            Ok(n) => n,
        };

        buf.truncate(n);
        buf.pop(); // this is a newline, basically
        let message = String::from_utf8(buf).expect("Fail turning vec to string");
        let event = util::create_public_dm_event(&recipient_pub_hex, &message);
        let payload = util::to_payload(event);

        tx.unbounded_send(Message::text(payload)).unwrap();
    }
}

fn add_new_contact() {
    let pubkey = util::get_pubkey();

    let filter = json!({
        "kinds": [4],
        "#p": [pubkey.to_string()],
    });

    let payload = json!(["REQ", "foobar", filter]);
    // let url_string = "wss://relayer.fiatjaf.com";
    let url_string = "wss://nostr-pub.wellorder.net";
    let url = url::Url::parse(url_string).unwrap();

    let (mut socket, response) = connect(url).expect("Can't connect");

    println!("Connected to the server");
    println!("Response HTTP code: {}", response.status());
    println!("Response contains the following headers:");

    for (ref header, _value) in response.headers() {
        println!("* {}", header);
    }

    socket
        .write_message(Message::Text(payload.to_string()))
        .unwrap();

    loop {
        let msg = socket.read_message().expect("Error reading message");
        let event_str = msg.to_text().unwrap();
        let payload: serde_json::Value = serde_json::from_str(event_str).unwrap();

        // decrypt events then put inside contact
        let event = payload[2].clone();
        let throwaway_pubkey = event["pubkey"].as_str().unwrap();
        let throwaway_shared_key = util::get_shared_key_from_hex(throwaway_pubkey);
        let inner_event_str = util::decrypt_dm(event, throwaway_shared_key);
        let inner_event: serde_json::Value = serde_json::from_str(&inner_event_str).unwrap();

        util::verify_event(inner_event.clone());
        // get pubkey from inner event
        let contact_pubkey = inner_event["pubkey"].as_str().unwrap();
        util::add_contact(contact_pubkey.clone(), contact_pubkey);
        println!("Contact added: {}", contact_pubkey);
        println!(
            "You can assign name to it by running `clust run change-contact-name {} <name>`",
            contact_pubkey
        );
        println!(
            "You can chat now by running `clust run chat {}`",
            contact_pubkey
        );

        // println!("{}", event);
    }
}
