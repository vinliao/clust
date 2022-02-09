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

    #[clap(default_value = "")]
    message: String,
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
    } else if args.command == "get-dm" {
        getter::get_dm(args.subcommand);
    } else if args.command == "create-dm-throwaway-key" {
        util::create_dm_throwaway_key(args.subcommand, args.message);
    } else if args.command == "create-alias" {
        let (linkage_events, _alias_privkey) = util::create_alias();
        println!("{}", linkage_events.to_string());
    }
}
