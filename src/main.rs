use clap::Parser;
mod getter;
mod publisher;
mod util;
use futures_channel;
use futures_util::{future, pin_mut, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};
use url;

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
        util::add_contact(args.subcommand, args.subcommand_2);
    } else if args.command == "change-contact-pubkey" {
        util::change_contact_pubkey(args.subcommand, args.subcommand_2);
    } else if args.command == "chat" {
        // todo: get this value from config file instead
        // todo: pass the contact name to the fn
        run("wss://nostr-pub.wellorder.net", &args.subcommand);
        // run("ws://localhost:8080");
    }
}

#[tokio::main]
async fn run(connect_addr: &str, contact_name: &str) {
    let url = url::Url::parse(connect_addr).unwrap();

    let (stdin_tx, stdin_rx) = futures_channel::mpsc::unbounded();
    tokio::spawn(read_stdin(stdin_tx));

    let (ws_stream, _) = connect_async(url).await.expect("Failed to connect");
    println!("WebSocket handshake has been successfully completed");

    let (write, read) = ws_stream.split();
    let stdin_to_ws = stdin_rx.map(Ok).forward(write);

    // get shared key here...
    let recipient_pubkey_hex = util::contact_pubkey_from_name(contact_name).unwrap();
    let shared_key = util::get_shared_key_from_hex(&recipient_pubkey_hex);

    let ws_to_stdout = {
        read.for_each(|message| async {
            // data is the stuff from relay, decrypt here

            let data = message.unwrap().into_data();
            let data_string = String::from_utf8(data).unwrap();
            let payload: serde_json::Value = serde_json::from_str(&data_string).unwrap();
            let event = payload[2].clone();

            // if identity from others, display "name: "
            // otherwise, display "you: "
            let dm = util::decrypt_dm(event.clone(), shared_key);

            if event["pubkey"].as_str().unwrap().to_string() == recipient_pubkey_hex {
                println!("{}: {}", contact_name, dm);
            } else {
                println!("you: {}", dm);
            }

            // below is the official way to do it, but it prints out nothing
            // let vec = dm.as_bytes();
            // tokio::io::stdout().write_all(&vec).await.unwrap();
        })
    };

    pin_mut!(stdin_to_ws, ws_to_stdout);
    future::select(stdin_to_ws, ws_to_stdout).await;
}

// stdin stuff, modify input here
async fn read_stdin(tx: futures_channel::mpsc::UnboundedSender<Message>) {
    let mut stdin = tokio::io::stdin();

    // send initial payload before capturing stdin
    let pubkey_hex = util::get_pubkey().to_string();
    // apparently passing a value as params to async function is hard
    let recipient_pub_hex =
        util::contact_pubkey_from_name("branle").expect("Fail to get contact's pubkey");
    let initial_payload = util::to_dm_request_payload(&pubkey_hex, &recipient_pub_hex);
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
        let recipient_pub_hex = util::contact_pubkey_from_name("branle").unwrap();
        let event = util::create_dm_event(&recipient_pub_hex, &message);
        let payload = util::to_payload(event);

        tx.unbounded_send(Message::text(payload)).unwrap();
    }
}
