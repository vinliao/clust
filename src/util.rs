// a bunch of generators

use schnorr_fun::{
fun::{marker::*, Scalar, nonce},
    Schnorr,
    Message
};
use hex;
use sha2::{Sha256, Digest};
use rand::rngs::ThreadRng;
use serde_json::json;
use chrono::Local;
use std::fs;

pub fn generate_key() -> (String, String) {
    let nonce_gen = nonce::Synthetic::<Sha256, nonce::GlobalRng<ThreadRng>>::default();
    let schnorr = Schnorr::<Sha256, _>::new(nonce_gen.clone());
    let keypair = schnorr.new_keypair(Scalar::random(&mut rand::thread_rng()));
    let (privkey, pubkey) = keypair.as_tuple();
    return (privkey.to_string(), pubkey.to_string());
}

pub fn generate_event(content: String) -> serde_json::Value {
    // generate key
    // todo: `clust set-private <key>`
    // todo: use secp256k1 instead of schnorr_fun
    let nonce_gen = nonce::Synthetic::<Sha256, nonce::GlobalRng<ThreadRng>>::default();
    let schnorr = Schnorr::<Sha256, _>::new(nonce_gen.clone());
    let keypair = schnorr.new_keypair(Scalar::random(&mut rand::thread_rng()));
    let (_secret_key, pubkey) = keypair.as_tuple();

    // todo: use local json key to do things from here
    // let privkey = util::get_privkey();
    // println!("{}", privkey);
    let privkey = get_privkey();
    println!("{}", privkey);


    // create data
    // NIP-01 spec: [0, toHexString(publicKey), unixTime, 1, [], content];
    let time = Local::now();
    let unix_time = time.timestamp();

    let data = json!([0, pubkey.to_string(), unix_time, 1, [], content.to_string()]);

    // hash data
    let mut hasher = Sha256::new();
    hasher.update(data.to_string());
    let event_id = hasher.finalize();    
    let event_id_hex = hex::encode(event_id);

    // sign id
    let message = Message::<Public>::raw(&event_id);
    let signature = schnorr.sign(&keypair, message);
    let signature_bytes = signature.to_bytes();
    let signature_hex = hex::encode(signature_bytes);

    let event = json!({
        "id": event_id_hex,
        "pubkey": pubkey.to_string(),
        "created_at": unix_time,
        "kind": 1,
        "tags": [],
        "content": content.to_string(),
        "sig": signature_hex
    });

    return event;
}

// todo: 
pub fn generate_rc() {
    // generate .clustrc, which has this pattern:
    // {privkey: privkey_hex, relays: ["wss://something", "wss://something"]}
}

fn get_privkey() -> String {
    let data = fs::read_to_string("clust.json").expect("Unable to read file");
    let json_data: serde_json::Value = serde_json::from_str(&data).expect("Fail to parse");

    return json_data["privkey"].to_string();
}

pub fn set_privkey(privkey: String) {
    let data = fs::read_to_string("clust.json").expect("Unable to read file");
    let mut json_data: serde_json::Value = serde_json::from_str(&data).expect("Fail to parse");

    json_data["privkey"] = serde_json::Value::String(privkey);
    fs::write("clust.json", json_data.to_string());
    println!("Private key updated");
}

pub fn add_relay() {
    // add a relay to .clustrc
}

pub fn remove_relay() {
    // remove a relay to .clustrc
}
