use clap::Parser;
mod getter;
mod publisher;
mod util;

#[derive(Parser)]
struct Cli {
    command: String,

    #[clap(default_value = "")]
    subcommand: String,

    #[clap(default_value = "")]
    message: String,
}

fn main() {
    let args = Cli::parse();

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
        let recipient_pub_hex = "ffb7e7b5a20bb1cf55a4b1d6ba610ddb97e84aa27708fdbb0b1e7e486fec1a50";
        println!("{}", util::create_dm_event(recipient_pub_hex, "helloworld"));
    } else if args.command == "get-dm" {
        let pubkey_hex = util::get_pubkey().to_string();
        let raw_string = getter::get_dm(pubkey_hex);
        let payload: serde_json::Value = serde_json::from_str(&raw_string).unwrap();
        println!("{}", payload);
        let dm = util::decrypt_dm(payload[2].clone());
        println!("{}", dm);
    }
}
