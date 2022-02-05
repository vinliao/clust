// a bunch of util functions

use aes::Aes256;
use base64;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use chrono::Local;
use hex;
use secp256k1::rand::rngs::OsRng;
use secp256k1::{KeyPair, Message, PublicKey, Secp256k1, SecretKey};
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

pub fn create_message(content: String) -> serde_json::Value {
    // for testing only
    let sender_priv = "d5f9b88ae04e7adb2fc075515e39df546df56d88ccdb304a9a779af1563d79ba";
    let sender_pub = "ab1a33b0cf3d8f8896c433e6996744e48f1401e6fbc94aea6f84291074fb1b75";
    let recipient_priv = "c10d9871f37f5d7dae09e93f2a381593b57697e02e15b446fbc99531b4623555";
    let recipient_pub = "7002538efd7175b2b5fafe4ee5a933242081c067a48ff019deca56eb13ef2186";

    let secp = Secp256k1::new();

    let (shared_keypair, shared_priv, shared_pub) =
        get_shared_key(recipient_priv.to_string(), sender_pub.to_string());
    // todo: check whether broadcast event is present

    // create data
    // NIP-01 spec: [0, toHexString(publicKey), unixTime, 1, [], content];
    let time = Local::now();
    let unix_time = time.timestamp();

    // encrypt content with aes and shared ecdh key
    type Aes256Cbc = Cbc<Aes256, Pkcs7>;

    // todo: random bytes
    let mut iv_bytes = [0u8; 16];
    hex::decode_to_slice(
        "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        &mut iv_bytes as &mut [u8],
    )
    .unwrap();

    // what if this plaintext is just json
    // {pubkey: content} then encrypt
    let plaintext = content.as_bytes();
    let cipher =
        Aes256Cbc::new_from_slices(&shared_priv.serialize_secret()[..], &iv_bytes).unwrap();

    // buffer must have enough space for message+padding
    let mut buffer = [0u8; 50];
    // copy message to the buffer
    let pos = plaintext.len();
    buffer[..pos].copy_from_slice(plaintext);
    let ciphertext = cipher.encrypt(&mut buffer, pos).unwrap();
    let ciphertext_content = format!(
        "{}?iv={}",
        base64::encode(ciphertext),
        base64::encode(iv_bytes)
    );

    // decrypt
    // let cipher = Aes256Cbc::new_from_slices(&key, &iv).unwrap();
    // let mut buf = ciphertext.to_vec();
    // let decrypted_ciphertext = cipher.decrypt(&mut buf).unwrap();
    // assert_eq!(decrypted_ciphertext, plaintext);

    let event_id = get_event_id(
        shared_pub.to_string(),
        ciphertext_content.to_string(),
        unix_time,
        4,
    );

    // sign id
    let event_id_byte = hex::decode(event_id.clone()).unwrap();
    let message = Message::from_slice(&event_id_byte[..]).expect("32 bytes, within curve order");
    let sig = secp.sign_schnorr(&message, &shared_keypair);

    // for more information about the data below:
    // https://github.com/fiatjaf/nostr/blob/master/nips/01.md
    let event = json!({
        "id": event_id,
        "pubkey": shared_pub.to_string(),
        "created_at": unix_time,
        "kind": 4,
        "tags": [],
        "content": ciphertext_content,
        "sig": sig.to_string()
    });

    println!("{}", event);

    return event;
}

fn get_shared_key(
    sender_privkey: String,
    recipient_pubkey: String,
) -> (
    secp256k1::KeyPair,
    secp256k1::SecretKey,
    secp256k1::XOnlyPublicKey,
) {
    let secp = Secp256k1::new();

    let privkey_byte_array = hex::decode(sender_privkey).unwrap();
    let privkey =
        SecretKey::from_slice(&privkey_byte_array[..]).expect("32 bytes, within curve order");

    // not precisely sure why there needs to be 0x03 or 0x02 in front
    let pubkey_hex = format!("03{}", recipient_pubkey);
    let pubkey_byte_array = hex::decode(pubkey_hex).unwrap();
    let pubkey =
        PublicKey::from_slice(&pubkey_byte_array[..]).expect("32 bytes, within curve order");

    // turn this shared secret into a privkey,
    // which a schnorr pubkey can be derived from
    let shared_byte_array = secp256k1::ecdh::SharedSecret::new(&pubkey, &privkey);
    // let shared_hex = hex::encode(shared_byte_array); // can be used to debug
    let shared_privkey =
        SecretKey::from_slice(&shared_byte_array[..]).expect("32 bytes, within curve order");
    let shared_keypair = secp256k1::KeyPair::from_secret_key(&secp, shared_privkey);
    let shared_pub = secp256k1::XOnlyPublicKey::from_keypair(&shared_keypair);

    return (shared_keypair, shared_privkey, shared_pub);
}

fn get_event_id(pubkey: String, content: String, unix_time: i64, kind: u32) -> String {
    let data = json!([0, pubkey, unix_time, kind, [], content]);

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
