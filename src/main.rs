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
        let event = getter::get_event(args.subcommand);
        println!("{}", event);
    } else if args.command == "get-dm" {
        // what if get_dm is insereted name as function
        getter::get_dm(args.subcommand);
        
        // if type 13, create (or change) pubkey on clust.json

    } else if args.command == "create-dm-throwaway-key" {
        util::create_dm_throwaway_key(args.subcommand, args.message);
    } else if args.command == "send-alias" {
        let dummy_pubkey = "d269e4e470bbf0113ef7ea3cf0af92d3f709f07f3dba0cc7970d1e86d7afceed";
        let (encrypted_linkage_events, alias_privkey) =
            util::create_alias_encrypted_event(dummy_pubkey.to_string());

        // publish the alias only when contact is successfully added
        util::add_contact(args.subcommand, dummy_pubkey.to_string(), alias_privkey);
        // publisher::publish(encrypted_linkage_events);
    } else if args.command == "change-contact-pubkey" {
        let dummy_pubkey = "45b9d57f1389ea027a0613346904ac76c0e1b20ca41301b477e332d116007064";
        util::change_contact_pubkey(args.subcommand, dummy_pubkey.to_string());
    }
}
