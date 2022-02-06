use clap::Parser;
mod getter;
mod publisher;
mod util;

#[derive(Parser)]
struct Cli {
    command: String,

    // subcommand is optional
    // maybe there's a better way to do this
    #[clap(default_value = "")]
    subcommand: String,
}

fn main() {
    let args = Cli::parse();

    if args.command == "generate-keypair" {
        let (privkey, pubkey) = util::generate_key();
        // todo: mnemonic
        println!("Private key: {}", privkey.display_secret().to_string());
        println!("Public key: {}", pubkey.to_string());
    } else if args.command == "set-private" {
        util::set_privkey(args.subcommand);
    } else if args.command == "init" {
        util::generate_config();
    } else if args.command == "publish-raw" {
        publisher::publish_raw(args.subcommand);
    } else if args.command == "get-event" {
        getter::get_event(args.subcommand);
    } else if args.command == "message-send" {
        let dummy_privkey = "d6ba84470e3da5c945251799062bbe2b52774321b9a43c90d548dd283728d7d9";
        let dummy_pubkey = "7b27c478232bbc9791d403b1db67e9696d87e7e6fff4e57a9cdfdedb754ad475";
        let message = util::create_message(args.subcommand, dummy_pubkey.to_string());
        // publisher::publish(message);
    } else if args.command == "broadcast" {
        // broadcast is really a bad name
        // ideally not exposed to end user
        let dummy_pubkey = "7b27c478232bbc9791d403b1db67e9696d87e7e6fff4e57a9cdfdedb754ad475";
        util::send_encrypted_pubkey(dummy_pubkey.to_string())
    } else if args.command == "pull" {
        // broadcast is really a bad name
        // ideally not exposed to end user
        util::pull_and_decrypt();
    }
}
