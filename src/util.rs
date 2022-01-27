// a bunch of generators

use schnorr_fun::{
fun::{Scalar, nonce},
    Schnorr,
};
use hex;
use sha2::{Sha256, Digest};
use rand::rngs::ThreadRng;
use serde_json::json;
use chrono::Local;
use std::fs;
use secp256k1::{Secp256k1, Message, SecretKey};

// use schnorr_fun for key generation
// but use secp256k1 for everything else cryptography related
// reason: secp256k1 has buggy key generation (doesn't compile)
pub fn generate_key() -> (String, String) {
    let nonce_gen = nonce::Synthetic::<Sha256, nonce::GlobalRng<ThreadRng>>::default();
    let schnorr = Schnorr::<Sha256, _>::new(nonce_gen.clone());
    let keypair = schnorr.new_keypair(Scalar::random(&mut rand::thread_rng()));
    let (privkey, pubkey) = keypair.as_tuple();
    return (privkey.to_string(), pubkey.to_string());
}

pub fn generate_event(content: String) -> serde_json::Value {
    // get usable privkey from privkey hexstring
    // todo: use config file
    // idea: maybe private key as param
    let privkey_hex = "38d23a761454f281a70de8de2607469206c9945bd335f56d9eb8458f5462c7c1";
    let privkey_byte_array = hex::decode(privkey_hex).unwrap();
    let secp = Secp256k1::new();
    let privkey = SecretKey::from_slice(&privkey_byte_array[..]).expect("32 bytes, within curve order");
    let keypair = secp256k1::KeyPair::from_secret_key(&secp, privkey);
    let pubkey = secp256k1::XOnlyPublicKey::from_keypair(&keypair);

    println!("{}", privkey.display_secret());
    println!("{}", pubkey.to_string());

    // create data
    // NIP-01 spec: [0, toHexString(publicKey), unixTime, 1, [], content];
    let time = Local::now();
    let unix_time = time.timestamp();
    let event_id = get_event_id(pubkey.to_string(), content.to_string(), unix_time);

    // sign id
    let event_id_byte = hex::decode(event_id.clone()).unwrap();
    let message = Message::from_slice(&event_id_byte[..]).expect("32 bytes, within curve order");
    let sig = secp.sign_schnorr(&message, &keypair);

    let event = json!({
        "id": event_id,
        "pubkey": pubkey.to_string(),
        "created_at": unix_time,
        "kind": 1,
        "tags": [],
        "content": content.to_string(),
        "sig": sig.to_string()
    });

    println!("{}", event);

    return event;
}

fn get_event_id(pubkey: String, content: String, unix_time: i64) -> String {
    let data = json!([0, pubkey, unix_time, 1, [], content]);

    // hash data
    let mut hasher = Sha256::new();
    hasher.update(data.to_string());
    let event_id = hasher.finalize();    
    let event_id_hex = hex::encode(event_id);

    return event_id_hex;
}

// todo: 
pub fn generate_rc() {
    // generate .clustrc, which has this pattern:
    // {privkey: privkey_hex, relays: ["wss://something", "wss://something"]}
}

// todo: this still has quote when reading
fn get_privkey() -> String {
    let data = fs::read_to_string("clust.json").expect("Unable to read file");
    let json_data: serde_json::Value = serde_json::from_str(&data).expect("Fail to parse");

    return json_data["privkey"].to_string();
}

pub fn set_privkey(privkey: String) {
    let data = fs::read_to_string("clust.json").expect("Unable to read file");
    let mut json_data: serde_json::Value = serde_json::from_str(&data).expect("Fail to parse");

    json_data["privkey"] = serde_json::Value::String(privkey);
    fs::write("clust.json", json_data.to_string()).expect("Unable to write file");
    println!("Private key updated");
}

pub fn add_relay() {
    // add a relay to .clustrc
}

pub fn remove_relay() {
    // remove a relay to .clustrc
}