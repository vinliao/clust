// a bunch of util functions

use aes::Aes256;
use base64;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use chrono::Local;
use hex;
use secp256k1::rand::rngs::OsRng;
use secp256k1::{Message, Secp256k1, SecretKey};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::str::FromStr;
use std::{fs, str};

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

pub fn generate_key() -> (secp256k1::SecretKey, secp256k1::XOnlyPublicKey) {
    let secp = Secp256k1::new();
    let mut rng = OsRng::new().expect("OsRng");
    let (privkey, _) = secp.generate_keypair(&mut rng);
    let keypair = secp256k1::KeyPair::from_secret_key(&secp, privkey);
    let pubkey = secp256k1::XOnlyPublicKey::from_keypair(&keypair);

    return (privkey, pubkey);
}

fn create_empty_event() -> serde_json::Value {
    // create empty nip-01 event to announce pubkey

    let secp = Secp256k1::new();

    let sender_privkey = get_privkey();
    let sender_pubkey = get_schnorr_pub(sender_privkey);
    let sender_keypair = secp256k1::KeyPair::from_secret_key(&secp, sender_privkey);

    // create data
    let time = Local::now();
    let unix_time = time.timestamp();
    let event_id_hex = get_event_id(&sender_pubkey.to_string(), "", unix_time, 1, json!([]));

    // sign id
    let event_id_byte = hex::decode(event_id_hex.clone()).unwrap();
    let event_id_message =
        Message::from_slice(&event_id_byte[..]).expect("32 bytes, within curve order");
    let sig = secp.sign_schnorr(&event_id_message, &sender_keypair);

    let event = json!({
        "id": event_id_hex,
        "pubkey": sender_pubkey.to_string(),
        "created_at": unix_time,
        "kind": 1,
        "tags": [],
        "content": "",
        "sig": sig.to_string()
    });

    return event;
}

pub fn create_dm_event(recipient_pub_hex: &str, message: &str) -> serde_json::Value {
    // create nip-04 dm event

    let secp = Secp256k1::new();

    let sender_privkey = get_privkey();
    let sender_pubkey = get_schnorr_pub(sender_privkey);
    let sender_keypair = secp256k1::KeyPair::from_secret_key(&secp, sender_privkey);

    let recipient_schnorr = secp256k1::XOnlyPublicKey::from_str(recipient_pub_hex).unwrap();
    let recipient_pub = schnorr_to_normal_pub(recipient_schnorr);
    let shared_priv = get_shared_key(sender_privkey, recipient_pub);

    // create data
    let time = Local::now();
    let unix_time = time.timestamp();
    let encrypted_message = encrypt_ecdh(shared_priv, message);
    let event_id_hex = get_event_id(
        &sender_pubkey.to_string(),
        &encrypted_message.clone(),
        unix_time,
        4,
        json!([["p", recipient_pub_hex]]),
    );

    // sign id
    let event_id_byte = hex::decode(event_id_hex.clone()).unwrap();
    let event_id_message =
        Message::from_slice(&event_id_byte[..]).expect("32 bytes, within curve order");
    let sig = secp.sign_schnorr(&event_id_message, &sender_keypair);

    let event = json!({
        "id": event_id_hex,
        "pubkey": sender_pubkey.to_string(),
        "created_at": unix_time,
        "kind": 4,
        "tags": [["p", recipient_pub_hex]],
        "content": encrypted_message,
        "sig": sig.to_string()
    });

    return event;
}

pub fn create_announcement_event(recipient_pub_hex: &str) -> serde_json::Value {
    // announce sender's pubkey to recipient with throwaway keypair
    let secp = Secp256k1::new();

    let (throwaway_privkey, throwaway_pubkey) = generate_key();
    let throwaway_keypair = secp256k1::KeyPair::from_secret_key(&secp, throwaway_privkey);

    let recipient_schnorr_pub = secp256k1::XOnlyPublicKey::from_str(recipient_pub_hex).unwrap();
    let recipient_normal_pub = schnorr_to_normal_pub(recipient_schnorr_pub);
    let shared_priv = get_shared_key(throwaway_privkey, recipient_normal_pub);

    // create data
    let time = Local::now();
    let unix_time = time.timestamp();
    let encrypted_message = encrypt_ecdh(shared_priv, &create_empty_event().to_string());
    let event_id_hex = get_event_id(
        &throwaway_pubkey.to_string(),
        &encrypted_message.clone(),
        unix_time,
        4,
        json!([["p", recipient_pub_hex]]),
    );

    // sign id
    let event_id_byte = hex::decode(event_id_hex.clone()).unwrap();
    let event_id_message =
        Message::from_slice(&event_id_byte[..]).expect("32 bytes, within curve order");
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

    return event;

}

pub fn create_public_dm_event(recipient_pub_hex: &str, message: &str) -> serde_json::Value {
    // create event, signed with public inbox
    // event is encrypted message between both parties
    // the identifier is sha256 of shared key
    // both have shared key once one party sends announcement event

    let secp = Secp256k1::new();

    // use config json to do this
    let inbox_privkey_hex = "13bad4c07bdea3a3397e7f52824d77c8a01b8edcc328f0ca5dd8e2540df5efb5";
    let inbox_privkey = secp256k1::SecretKey::from_str(inbox_privkey_hex).unwrap();
    let inbox_keypair = secp256k1::KeyPair::from_secret_key(&secp, inbox_privkey);
    let inbox_pubkey = secp256k1::XOnlyPublicKey::from_keypair(&inbox_keypair);

    let sender_privkey = get_privkey();

    let recipient_schnorr = secp256k1::XOnlyPublicKey::from_str(recipient_pub_hex).unwrap();
    let recipient_pub = schnorr_to_normal_pub(recipient_schnorr);
    let shared_priv = get_shared_key(sender_privkey, recipient_pub);

    // hash shared_priv
    let mut hasher = Sha256::new();
    hasher.update(shared_priv.display_secret().to_string());
    let sha_shared_priv_byte = hasher.finalize();
    let sha_shared_priv_hex = hex::encode(sha_shared_priv_byte);

    // create data with inbox public key and shared sha
    let time = Local::now();
    let unix_time = time.timestamp();

    // envelope the real nip-04 dm with another dm
    let inner_encrypted_message = create_dm_event(recipient_pub_hex, message);
    let encrypted_message = encrypt_ecdh(shared_priv, &inner_encrypted_message.to_string());

    let event_id_hex = get_event_id(
        &inbox_pubkey.to_string(),
        &encrypted_message.clone(),
        unix_time,
        4,
        json!([["shared", sha_shared_priv_hex]]),
    );

    // sign id
    let event_id_byte = hex::decode(event_id_hex.clone()).unwrap();
    let event_id_message =
        Message::from_slice(&event_id_byte[..]).expect("32 bytes, within curve order");
    let sig = secp.sign_schnorr(&event_id_message, &inbox_keypair);

    let event = json!({
        "id": event_id_hex,
        "pubkey": inbox_pubkey.to_string(),
        "created_at": unix_time,
        "kind": 4,
        "tags": [["shared", sha_shared_priv_hex]],
        "content": encrypted_message,
        "sig": sig.to_string()
    });

    return event;
}

pub fn decrypt_dm(event: serde_json::Value, shared_privkey: secp256k1::SecretKey) -> String {
    let content = event["content"].as_str().unwrap().to_string();
    let (iv_bytes, encrypted_content) = separate_iv_ciphertext(content);

    return decrypt_ecdh(shared_privkey, iv_bytes, encrypted_content);
}

// for external use
pub fn get_pubkey() -> secp256k1::XOnlyPublicKey {
    let secp = Secp256k1::new();
    let privkey = get_privkey();
    let keypair = secp256k1::KeyPair::from_secret_key(&secp, privkey);
    return secp256k1::XOnlyPublicKey::from_keypair(&keypair);
}

fn schnorr_to_normal_pub(schnorr_pub: secp256k1::XOnlyPublicKey) -> secp256k1::PublicKey {
    let schnorr_hex = format!("02{}", schnorr_pub.to_string());
    return secp256k1::PublicKey::from_str(&schnorr_hex).unwrap();
}

fn separate_iv_ciphertext(encrypted_content: String) -> ([u8; 16], Vec<u8>) {
    let iv_position = encrypted_content.find("?iv=").unwrap();
    let encrypted_content_base64 = &encrypted_content[..iv_position];
    let iv_base64 = &encrypted_content[iv_position + 4..];

    let encrypted_content = base64::decode(encrypted_content_base64).unwrap();
    let iv_vec = base64::decode(iv_base64).unwrap();

    // turn vec to bytes
    let mut iv_bytes = [0u8; 16];
    iv_bytes.copy_from_slice(&iv_vec[..]);

    return (iv_bytes, encrypted_content);
}

fn get_shared_key(
    sender_privkey: secp256k1::SecretKey,
    recipient_pub: secp256k1::PublicKey,
) -> secp256k1::SecretKey {
    // without the hash, it doesn't work
    let shared_byte_array =
        secp256k1::ecdh::SharedSecret::new_with_hash(&recipient_pub, &sender_privkey, |x, _| {
            x.into()
        });

    let shared_privkey =
        SecretKey::from_slice(&shared_byte_array[..]).expect("32 bytes, within curve order");

    return shared_privkey;
}

pub fn get_shared_key_from_hex(recipient_pub_hex: &str) -> secp256k1::SecretKey {
    let recipient_schnorr = secp256k1::XOnlyPublicKey::from_str(recipient_pub_hex).unwrap();
    let recipient_pub = schnorr_to_normal_pub(recipient_schnorr);

    return get_shared_key(get_privkey(), recipient_pub);
}

fn get_schnorr_pub(privkey: secp256k1::SecretKey) -> secp256k1::XOnlyPublicKey {
    let secp = Secp256k1::new();
    let keypair = secp256k1::KeyPair::from_secret_key(&secp, privkey);
    return secp256k1::XOnlyPublicKey::from_keypair(&keypair);
}

fn encrypt_ecdh(shared_priv: secp256k1::SecretKey, content: &str) -> String {
    // encrypt content

    let iv_bytes: [u8; 16] = secp256k1::rand::random();
    let cipher =
        Aes256Cbc::new_from_slices(&shared_priv.serialize_secret()[..], &iv_bytes).unwrap();
    let ciphertext = cipher.encrypt_vec(content.as_bytes());
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

    let cipher =
        Aes256Cbc::new_from_slices(&shared_priv.serialize_secret()[..], &iv_bytes).unwrap();
    let mut buf = ciphertext.to_vec();
    let decrypted_ciphertext = cipher.decrypt(&mut buf).unwrap();

    return str::from_utf8(decrypted_ciphertext).unwrap().to_string();
}

fn get_event_id(
    pubkey: &str,
    content: &str,
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

fn get_privkey() -> secp256k1::SecretKey {
    let data = fs::read_to_string("clust.json").expect("Unable to read config file");
    let json_data: serde_json::Value = serde_json::from_str(&data).expect("Fail to parse");
    let privkey_hex_raw = json_data["main_privkey"].as_str().unwrap();
    return SecretKey::from_str(privkey_hex_raw).unwrap();
}

// todo: all these fs-related stuff needs massive refactor
pub fn set_privkey(privkey: String) {
    let data = fs::read_to_string("clust.json").expect("Unable to read config file");
    let mut json_data: serde_json::Value = serde_json::from_str(&data).expect("Fail to parse");
    json_data["main_privkey"] = serde_json::Value::String(privkey);
    fs::write("clust.json", json_data.to_string()).expect("Unable to write file");
    println!("Private key updated");
}

pub fn generate_config() {
    let res = fs::read_to_string("clust.json");

    if res.is_err() {
        // if config file doesn't exist
        let (privkey, _) = generate_key();
        let json_data = json!({
            "main_privkey": privkey.display_secret().to_string(),
            "relay": [],
            "contact": []
        });
        fs::write("clust.json", json_data.to_string()).expect("Unable to write file");
        println!("Config file created");
    } else {
        println!("Config file exists, not doing anything");
    }
}

// todo: two function below can be refactored further
pub fn add_contact(name: String, contact_pubkey: String) {
    let data = fs::read_to_string("clust.json").expect("Unable to read config file");
    let mut json_data: serde_json::Value = serde_json::from_str(&data).expect("Fail to parse");
    let contact_iter = json_data["contact"].as_array().unwrap().iter();

    // check whether name exists
    let mut name_index = usize::MAX;
    for (index, single_json) in contact_iter.enumerate() {
        if single_json["name"] == name {
            name_index = index;
        }
    }

    if name_index == usize::MAX {
        // if contact name doesn't exist
        let new_contact = json!({
            "name": name,
            "contact_pubkey": contact_pubkey,
        });

        json_data["contact"]
            .as_array_mut()
            .unwrap()
            .push(new_contact);

        fs::write("clust.json", json_data.to_string()).expect("Unable to write file");
        println!("Successfully added contact");
    } else {
        // if contact name exist, don't do anything
        println!("Contact name exists, pick another name");
    }
}

pub fn change_contact_pubkey(name: String, contact_pubkey: String) {
    let data = fs::read_to_string("clust.json").expect("Unable to read config file");
    let mut json_data: serde_json::Value = serde_json::from_str(&data).expect("Fail to parse");
    let contact_iter = json_data["contact"].as_array().unwrap().iter();

    // check whether name exists
    let mut name_index = usize::MAX;
    for (index, single_json) in contact_iter.enumerate() {
        if single_json["name"] == name {
            name_index = index;
        }
    }

    if name_index == usize::MAX {
        // if contact name doesn't exists
        println!("Contact name doens't exist, add contact first!");
    } else {
        // if contact name exists, change contact pubkey
        let mut changed_contact_json = json_data["contact"][name_index].clone();
        changed_contact_json["contact_pubkey"] = serde_json::Value::String(contact_pubkey);

        json_data["contact"]
            .as_array_mut()
            .unwrap()
            .remove(name_index);

        json_data["contact"]
            .as_array_mut()
            .unwrap()
            .push(changed_contact_json);

        fs::write("clust.json", json_data.to_string()).expect("Unable to write file");
        println!("Successfully changed contact pubkey");
    }
}

pub fn contact_pubkey_from_name(name: &str) -> Option<String> {
    let data = fs::read_to_string("clust.json").expect("Unable to read config file");
    let json_data: serde_json::Value = serde_json::from_str(&data).expect("Fail to parse");
    let contact_iter = json_data["contact"].as_array().unwrap().iter();

    // check whether name exists
    for (_, single_json) in contact_iter.enumerate() {
        if single_json["name"] == name {
            return Some(single_json["contact_pubkey"].as_str().unwrap().to_string());
        }
    }

    return None;
}

pub fn to_payload(event: serde_json::Value) -> String {
    let payload = json!(["EVENT", event]);
    return payload.to_string();
}

pub fn to_dm_request_payload(pubkey: &str, recipient_pubkey: &str) -> String {
    let filter = json!({
        "kinds": [4],
        "#p": [pubkey, recipient_pubkey],
    });

    let payload = json!(["REQ", "foobar", filter]);

    return payload.to_string();
}
