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

    if args.command == "post" {
        if args.subcommand == "" {
           println!("Cannot post empty string!") 
        } else {
            let event = util::generate_event(args.subcommand);
            publisher::publish(event);
        }
    } else if args.command == "get" {
        getter::get_event();
    } else if args.command == "generate-key" {
        let (privkey, pubkey) = util::generate_key();
        // todo: mnemonic
        println!("Private key: {}", privkey);
        println!("Public key: {}", pubkey);
    } else if args.command == "set-private" {
        util::set_privkey(args.subcommand);
    } else if args.command == "init" {
        util::generate_config();
    }
}
