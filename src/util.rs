// a bunch of util functions

use aes::Aes256;
use base64;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use chrono::Local;
use hex;
use rand::Rng;
use secp256k1::rand::rngs::OsRng;
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{fs, str};

pub fn generate_key() -> (secp256k1::SecretKey, secp256k1::XOnlyPublicKey) {
    let secp = Secp256k1::new();
    let mut rng = OsRng::new().expect("OsRng");
    let (privkey, _) = secp.generate_keypair(&mut rng);
    let keypair = secp256k1::KeyPair::from_secret_key(&secp, privkey);
    let pubkey = secp256k1::XOnlyPublicKey::from_keypair(&keypair);

    return (privkey, pubkey);
}

pub fn create_dm_throwaway_key(recipient_pub_hex: String, message: String) -> serde_json::Value {
    // create dm event to a pubkey with random key

    let secp = Secp256k1::new();

    let (throwaway_privkey, throwaway_pubkey) = generate_key();
    let throwaway_keypair = secp256k1::KeyPair::from_secret_key(&secp, throwaway_privkey);

    let pubkey_hex = format!("03{}", recipient_pub_hex);
    let pubkey_byte_array = hex::decode(pubkey_hex).unwrap();
    let recipient_pub =
        PublicKey::from_slice(&pubkey_byte_array[..]).expect("32 bytes, within curve order");
    let (_, shared_priv, _) = get_shared_key(throwaway_privkey, recipient_pub);

    // create data
    let time = Local::now();
    let unix_time = time.timestamp();
    let encrypted_message = encrypt_ecdh(shared_priv, message);
    let event_id_hex = get_event_id(
        throwaway_pubkey.to_string(),
        encrypted_message.clone(),
        unix_time,
        4,
        json!([["p", recipient_pub_hex]]),
    );

    // sign id
    let event_id_byte = hex::decode(event_id_hex.clone()).unwrap();
    let event_id_message = Message::from_slice(&event_id_byte[..]).expect("32 bytes, within curve order");
    // sign from throwaway keypair
    let sig = secp.sign_schnorr(&event_id_message, &throwaway_keypair);

    let event = json!({
        "id": event_id_hex,
        "pubkey": throwaway_pubkey.to_string(),
        "created_at": unix_time,
        "kind": 4,
        "tags": [["p", recipient_pub_hex]],
        "content": encrypted_message,
        "sig": sig.to_string()
    });

    println!("{}", event);

    return event;
}

pub fn create_alias() -> (serde_json::Value, secp256k1::SecretKey) {
    // create an array that consists of main event and alias event

    let secp = Secp256k1::new();
    let main_privkey = get_privkey();
    let main_pubkey = get_schnorr_pub(main_privkey);
    let main_keypair = secp256k1::KeyPair::from_secret_key(&secp, main_privkey);

    let (alias_privkey, alias_pubkey) = generate_key();
    let alias_keypair = secp256k1::KeyPair::from_secret_key(&secp, alias_privkey);

    let time = Local::now();
    let unix_time = time.timestamp();

    // todo: duplicate code, refactor
    let main_tag = json!([["p", alias_pubkey.to_string()]]);
    // todo: change "kind" to new kind defined in new NIP
    let main_event_id_hex = get_event_id(main_pubkey.to_string(), "".to_string(), unix_time, 1, main_tag.clone());
    let main_event_id_byte = hex::decode(main_event_id_hex.clone()).unwrap();
    let main_event_id_message = Message::from_slice(&main_event_id_byte[..]).expect("32 bytes, within curve order");
    let main_sig = secp.sign_schnorr(&main_event_id_message, &main_keypair);

    // todo: change kind to new kind defined in new NIP
    let main_event = json!({
        "id": main_event_id_hex,
        "pubkey": main_pubkey.to_string(),
        "created_at": unix_time,
        "kind": 1,
        "tags": main_tag,
        "content": "",
        "sig": main_sig.to_string()
    });

    let alias_tag = json!([["p", main_pubkey.to_string()], ["e", main_event_id_hex]]);
    // todo: change "kind" to new kind defined in new NIP
    let alias_event_id_hex = get_event_id(alias_pubkey.to_string(), "".to_string(), unix_time, 1, alias_tag.clone());
    let alias_event_id_byte = hex::decode(alias_event_id_hex.clone()).unwrap();
    let alias_event_id_message = Message::from_slice(&alias_event_id_byte[..]).expect("32 bytes, within curve order");
    let alias_sig = secp.sign_schnorr(&alias_event_id_message, &alias_keypair);

    let alias_event = json!({
        "id": alias_event_id_hex,
        "pubkey": alias_pubkey.to_string(),
        "created_at": unix_time,
        "kind": 1,
        "tags": alias_tag,
        "content": "",
        "sig": alias_sig.to_string()
    });

    return (json!([main_event, alias_event]), alias_privkey);
}

fn get_shared_key(
    sender_priv: secp256k1::SecretKey,
    recipient_pub: secp256k1::PublicKey,
) -> (
    secp256k1::KeyPair,
    secp256k1::SecretKey,
    secp256k1::XOnlyPublicKey,
) {
    let secp = Secp256k1::new();

    let shared_byte_array = secp256k1::ecdh::SharedSecret::new(&recipient_pub, &sender_priv);
    // let shared_hex = hex::encode(shared_byte_array); // can be used to debug
    let shared_privkey =
        SecretKey::from_slice(&shared_byte_array[..]).expect("32 bytes, within curve order");
    let shared_keypair = secp256k1::KeyPair::from_secret_key(&secp, shared_privkey);
    let shared_pub = secp256k1::XOnlyPublicKey::from_keypair(&shared_keypair);

    return (shared_keypair, shared_privkey, shared_pub);
}

fn get_schnorr_pub(privkey: secp256k1::SecretKey) -> secp256k1::XOnlyPublicKey {
    let secp = Secp256k1::new();
    let keypair = secp256k1::KeyPair::from_secret_key(&secp, privkey);
    return secp256k1::XOnlyPublicKey::from_keypair(&keypair);
}

fn encrypt_ecdh(shared_priv: secp256k1::SecretKey, content: String) -> String {
    // encrypt content
    type Aes256Cbc = Cbc<Aes256, Pkcs7>;

    // random bytes
    let mut iv_bytes = [0u8; 16];
    rand::thread_rng().fill(&mut iv_bytes);

    let plaintext_json = content;
    let plaintext = plaintext_json.to_string();
    let plaintext_bytes = plaintext.as_bytes();

    let cipher =
        Aes256Cbc::new_from_slices(&shared_priv.serialize_secret()[..], &iv_bytes).unwrap();
    // buffer must have enough space for message+padding
    let mut buffer = [0u8; 5000];
    // copy message to the buffer
    let pos = plaintext_bytes.len();
    buffer[..pos].copy_from_slice(plaintext_bytes);
    let ciphertext = cipher.encrypt(&mut buffer, pos).unwrap();
    let ciphertext_string = format!(
        "{}?iv={}",
        base64::encode(ciphertext),
        base64::encode(iv_bytes)
    );

    return ciphertext_string;
}

fn decrypt_ecdh(
    shared_priv: secp256k1::SecretKey,
    iv_bytes: [u8; 16],
    ciphertext: Vec<u8>,
) -> String {
    // decrypt content
    type Aes256Cbc = Cbc<Aes256, Pkcs7>;

    let cipher =
        Aes256Cbc::new_from_slices(&shared_priv.serialize_secret()[..], &iv_bytes).unwrap();
    let mut buf = ciphertext.to_vec();
    let decrypted_ciphertext = cipher.decrypt(&mut buf).unwrap();

    return str::from_utf8(decrypted_ciphertext).unwrap().to_string();
}

fn get_event_id(
    pubkey: String,
    content: String,
    unix_time: i64,
    kind: u32,
    tags: serde_json::Value,
) -> String {
    let data = json!([0, pubkey, unix_time, kind, tags, content]);

    // hash data
    let mut hasher = Sha256::new();
    hasher.update(data.to_string());
    let event_id = hasher.finalize();
    let event_id_hex = hex::encode(event_id);

    return event_id_hex;
}

// todo: these fs stuff needs to be refactored
fn get_privkey() -> secp256k1::SecretKey {
    let data = fs::read_to_string("clust.json").expect("Unable to read config file");
    let json_data: serde_json::Value = serde_json::from_str(&data).expect("Fail to parse");
    let privkey_hex_raw = json_data["privkey"].to_string();
    let privkey_hex = privkey_hex_raw.replace("\"", "");
    let privkey_byte_array = hex::decode(privkey_hex).unwrap();
    return SecretKey::from_slice(&privkey_byte_array[..]).expect("32 bytes, within curve order");
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
            "privkey": privkey.display_secret().to_string(),
            "relay": []
        });

        fs::write("clust.json", json_data.to_string()).expect("Unable to write file");
    } else {
        println!("Config file exists!");
    }
}
