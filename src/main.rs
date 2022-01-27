use clap::Parser;
mod publisher;
mod getter;
mod util;

// how to make subcommand optional? turn it into a flag?
#[derive(Parser)]
struct Cli {
    command: String,
    subcommand: String
}

fn main() {
    let args = Cli::parse();

    if args.command == "publish" {
        // publish signed event
        // publisher::publish(args.subcommand);
    } else if args.command == "post" {
        let event = util::generate_event(args.subcommand);
        publisher::publish(event);
    } else if args.command == "get" {
        getter::get_event();
    } else if args.command == "generate-key" {
        let (privkey, pubkey) = util::generate_key();
        // todo: mnemonic
        println!("Private key: {}", privkey);
        println!("Public key: {}", pubkey);
    } else if args.command == "set-private" {
        println!("asdfd");
    }
}
