use clap::Parser;
mod publisher;
mod generator;
mod getter;

#[derive(Parser)]
struct Cli {
    command: String,
    content: String
}

fn main() {
    let args = Cli::parse();

    if args.command == "publish" {
        // publish signed event
        // publisher::publish(args.content);
    } else if args.command == "post" {
        let event = generator::generate_event(args.content);
        publisher::publish(event);
    } else if args.command == "get" {
        getter::get_event();
    } else if args.command == "generate-key" {
        let (privkey, pubkey) = generator::generate_key();
        // todo: mnemonic
        println!("Private key: {}", privkey);
        println!("Public key: {}", pubkey);
    }
}
