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

    if args.command == "generate-key" {
        let (privkey, pubkey) = util::generate_key();
        // todo: mnemonic
        println!("Private key: {}", privkey);
        println!("Public key: {}", pubkey);
    } else if args.command == "set-private" {
        util::set_privkey(args.subcommand);
    } else if args.command == "init" {
        util::generate_config();
    } else if args.command == "publish-raw" {
        publisher::publish_raw(args.subcommand);
    } else if args.command == "get-event" {
        getter::get_event(args.subcommand);
    } else if args.command == "message-send" {
        let dummy_pubkey = "7002538efd7175b2b5fafe4ee5a933242081c067a48ff019deca56eb13ef2186";
        let message = util::create_message(args.subcommand, dummy_pubkey.to_string());
        // publisher::publish(message);
    }
}
