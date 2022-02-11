use clap::Parser;
mod getter;
mod publisher;
mod util;
use secp256k1;

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
        let dummy_pubkey_hex = "466a107552bb71d6df6120055b916afbbd038eeadb9c449087ff9cad6933aaa9";
        let raw_string = getter::get_dm(dummy_pubkey_hex.to_string());
        let payload: serde_json::Value = serde_json::from_str(&raw_string).unwrap();

        let dummy_privkey_hex = "705a26e1936321f191fe218b188a9b41828fa3f151a6a1a4766e39b9db8e972b";
        let dummy_privkey_byte_array = hex::decode(dummy_privkey_hex).unwrap();
        let dummy_privkey = secp256k1::SecretKey::from_slice(&dummy_privkey_byte_array[..]).expect("32 bytes, within curve order");
        println!("{}", util::decrypt_dm(payload[2].clone(), dummy_privkey));

        // idea: extract event id of main event from alt event, then pull the event
        // when both even is present, add contact
        // this way, even when both event are separated, they can be referenced
        // use branle to test to send and receive stuff

        // check sig is legit or not, all sig must be checked by client
        // if type 13, create (or change) pubkey on clust.json
    } else if args.command == "create-dm-throwaway-key" {
        util::create_dm_throwaway_key(args.subcommand, args.message);
    } else if args.command == "send-alias" {
        let dummy_pubkey_hex = "466a107552bb71d6df6120055b916afbbd038eeadb9c449087ff9cad6933aaa9";
        let (encrypted_main_event, encrypted_alt_event, alias_privkey) =
            util::create_alias_encrypted_event(dummy_pubkey_hex.to_string());

        println!("{}", encrypted_main_event);
        println!("{}", encrypted_alt_event);

        // publish the alias only when contact is successfully added
        // util::add_contact(args.subcommand, dummy_pubkey.to_string(), alias_privkey);
        // publisher::publish(encrypted_linkage_events);
    } else if args.command == "change-contact-pubkey" {
        let dummy_pubkey = "45b9d57f1389ea027a0613346904ac76c0e1b20ca41301b477e332d116007064";
        util::change_contact_pubkey(args.subcommand, dummy_pubkey.to_string());
    }
}
