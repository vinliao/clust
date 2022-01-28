// a bunch of util functions

use chrono::Local;
use hex;
use secp256k1::rand::rngs::OsRng;
use secp256k1::{Message, Secp256k1, SecretKey};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs;

pub fn generate_key() -> (String, String) {
    let secp = Secp256k1::new();
    let mut rng = OsRng::new().expect("OsRng");
    let (privkey, _) = secp.generate_keypair(&mut rng);
    let keypair = secp256k1::KeyPair::from_secret_key(&secp, privkey);
    let pubkey = secp256k1::XOnlyPublicKey::from_keypair(&keypair);

    return (privkey.display_secret().to_string(), pubkey.to_string());
}

pub fn generate_event(content: String) -> serde_json::Value {
    // get usable privkey from privkey hexstring
    let privkey_hex = get_privkey();
    let privkey_byte_array = hex::decode(privkey_hex).unwrap();
    let secp = Secp256k1::new();
    let privkey =
        SecretKey::from_slice(&privkey_byte_array[..]).expect("32 bytes, within curve order");
    let keypair = secp256k1::KeyPair::from_secret_key(&secp, privkey);
    let pubkey = secp256k1::XOnlyPublicKey::from_keypair(&keypair);

    // create data
    // NIP-01 spec: [0, toHexString(publicKey), unixTime, 1, [], content];
    let time = Local::now();
    let unix_time = time.timestamp();
    let event_id = get_event_id(pubkey.to_string(), content.to_string(), unix_time);

    // sign id
    let event_id_byte = hex::decode(event_id.clone()).unwrap();
    let message = Message::from_slice(&event_id_byte[..]).expect("32 bytes, within curve order");
    let sig = secp.sign_schnorr(&message, &keypair);

    // for more information about the data below:
    // https://github.com/fiatjaf/nostr/blob/master/nips/01.md
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

// todo: these fs stuff needs to be refactored
fn get_privkey() -> String {
    let data = fs::read_to_string("clust.json").expect("Unable to read config file");
    let json_data: serde_json::Value = serde_json::from_str(&data).expect("Fail to parse");
    let privkey_hex = json_data["privkey"].to_string();

    // not sure why there's quote here...
    return privkey_hex.replace("\"", "");
}

pub fn set_privkey(privkey: String) {
    let res = fs::read_to_string("clust.json");

    if res.is_ok() {
        // if config file exist
        let data = res.unwrap();
        let mut json_data: serde_json::Value = serde_json::from_str(&data).expect("Fail to parse");

        json_data["privkey"] = serde_json::Value::String(privkey);
        fs::write("clust.json", json_data.to_string()).expect("Unable to write file");
    } else {
        // if config file doesn't exist
        let json_data = json!({ "privkey": privkey });
        fs::write("clust.json", json_data.to_string()).expect("Unable to write file");
    }

    println!("Private key updated");
}

pub fn generate_config() {
    let res = fs::read_to_string("clust.json");

    if res.is_err() {
        // if file doesn't exist
        let (privkey, _) = generate_key();
        let json_data = json!({
            "privkey": privkey,
            "subscription": [],
            "relay": []
        });

        fs::write("clust.json", json_data.to_string()).expect("Unable to write file");
    } else {
        println!("Config file exists!");
    }
}

pub fn subscribe_to(pubkey: String) {
    let res = fs::read_to_string("clust.json");

    if res.is_ok() {
        // if config file exist
        let data = res.unwrap();
        let mut json_data: serde_json::Value = serde_json::from_str(&data).expect("Fail to parse");
        json_data["subscription"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::Value::String(pubkey));
        fs::write("clust.json", json_data.to_string()).expect("Unable to write file");

        println!("Subscribed");
    } else {
        // if config file doesn't exist
        println!("Can't find config file!")
    }
}

pub fn unsubscribe_from(pubkey: String) {
    let res = fs::read_to_string("clust.json");

    if res.is_ok() {
        // if config file exist
        let data = res.unwrap();
        let mut json_data: serde_json::Value = serde_json::from_str(&data).expect("Fail to parse");
        json_data["subscription"]
            .as_array_mut()
            .unwrap()
            .retain(|value| *value != pubkey);

        fs::write("clust.json", json_data.to_string()).expect("Unable to write file");

        println!("Unsubscribed");
    } else {
        // if config file doesn't exist
        println!("Can't find config file!")
    }
}
