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

pub fn send_encrypted_pubkey(recipient_pub_hex: String) {
    // encrypt sender's pubkey to recipient so both can have shared key
    let secp = Secp256k1::new();

    let (throwaway_privkey, throwaway_pubkey) = generate_key();
    let throwaway_keypair = secp256k1::KeyPair::from_secret_key(&secp, throwaway_privkey);
    let sender_pub = get_schnorr_pub(get_privkey());

    let pubkey_hex = format!("03{}", recipient_pub_hex);
    let pubkey_byte_array = hex::decode(pubkey_hex).unwrap();
    let recipient_pub =
        PublicKey::from_slice(&pubkey_byte_array[..]).expect("32 bytes, within curve order");
    let (_, shared_priv, _) = get_shared_key(throwaway_privkey, recipient_pub);

    // create data
    // content is encrypted sender's pubkey
    let time = Local::now();
    let unix_time = time.timestamp();
    let encrypted_pubkey = encrypt_ecdh(shared_priv, sender_pub.to_string());
    // tag "#p" the recipeint pub (hex)
    let event_id = get_event_id(
        throwaway_pubkey.to_string(),
        encrypted_pubkey.clone(),
        unix_time,
        4,
        json!([["p", recipient_pub_hex]]),
    );

    // sign id
    let event_id_byte = hex::decode(event_id.clone()).unwrap();
    let message = Message::from_slice(&event_id_byte[..]).expect("32 bytes, within curve order");
    // sign from throwaway keypair
    let sig = secp.sign_schnorr(&message, &throwaway_keypair);

    let event = json!({
        "id": event_id,
        "pubkey": throwaway_pubkey.to_string(),
        "created_at": unix_time,
        "kind": 4,
        "tags": [["p", recipient_pub_hex]],
        "content": encrypted_pubkey,
        "sig": sig.to_string()
    });

    println!("{}", event);

    // return event;
}

pub fn create_message(content: String, recipient_pub_hex: String) -> serde_json::Value {
    let secp = Secp256k1::new();
    let sender_priv = get_privkey();
    let sender_pub = get_schnorr_pub(sender_priv);

    // not precisely sure why there needs to be 0x03 or 0x02 in front
    let pubkey_hex = format!("03{}", recipient_pub_hex);
    let pubkey_byte_array = hex::decode(pubkey_hex).unwrap();
    let recipient_pub =
        PublicKey::from_slice(&pubkey_byte_array[..]).expect("32 bytes, within curve order");

    let (shared_keypair, shared_priv, shared_pub) = get_shared_key(sender_priv, recipient_pub);

    // todo: check whether broadcast event is present

    // encrypt content
    type Aes256Cbc = Cbc<Aes256, Pkcs7>;

    // random bytes
    let mut iv_bytes = [0u8; 16];
    rand::thread_rng().fill(&mut iv_bytes);

    let plaintext_json = json!({ sender_pub.to_string(): content });
    let plaintext = plaintext_json.to_string();
    let plaintext_bytes = plaintext.as_bytes();

    let cipher =
        Aes256Cbc::new_from_slices(&shared_priv.serialize_secret()[..], &iv_bytes).unwrap();
    // buffer must have enough space for message+padding
    // todo: figure out what the ideal buffer size is
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

    // create event id with encrypted data
    let time = Local::now();
    let unix_time = time.timestamp();
    let event_id = get_event_id(
        shared_pub.to_string(),
        ciphertext_string.to_string(),
        unix_time,
        4,
        json!([]),
    );

    // sign id with shared key
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
        "content": ciphertext_string,
        "sig": sig.to_string()
    });

    println!("{}", event);

    return event;
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

pub fn pull_and_decrypt() {
    // pull init messages, then decrypt the content (the sender's pubkey)
    // how do i code and test this systematically?

    let sender_priv = get_privkey();
    let sender_pub = get_schnorr_pub(sender_priv);
    // request to relay: ["REQ", "foobar", [{"#p": sender_pub}]]
    // todo: replace this with pulls to real relay

    println!("{}", sender_pub);
    // is this dummy event's pub the same as pub above?
    let dummy_event = json!({
        "content":"TNFR/PLHSeJfzbj/lVP4vjfIWAaYDhOUnLvnza6kYn8P3bgpI6Tt/A7l1fGLxicYiRW+s5r1Azw9ggbSgVB4O/P97Uuti2KeOunn5px6KWg=?iv=W4H29vgjaOsE7WZzI7Irlg==",
        "created_at":1644088300,
        "id":"1c141a2603af0ce19d6bd8e75e9ded03eac94df0d67c010ca8e2e37aa6e0dc86",
        "kind":4,
        "pubkey":"0553362b7f036acf8cb5ce0db095c7d05cee0d52293cb9818131228d726b3295",
        "sig":"9461f1328f5e3e72fe56a92f7535f37267eff6fa719ae9abe2821b02d72c204e48c4dbc3fb2bf712a3dc9524372cfe56f60fd5bf4689da907902f95f706405b1",
        "tags":[["p","7b27c478232bbc9791d403b1db67e9696d87e7e6fff4e57a9cdfdedb754ad475"]]
    });

    let encrypted_content_base64 = "TNFR/PLHSeJfzbj/lVP4vjfIWAaYDhOUnLvnza6kYn8P3bgpI6Tt/A7l1fGLxicYiRW+s5r1Azw9ggbSgVB4O/P97Uuti2KeOunn5px6KWg";
    let encrypted_vec = base64::decode(encrypted_content_base64).unwrap();
    let iv_base64 = "W4H29vgjaOsE7WZzI7Irlg==";
    let iv_vec = base64::decode(iv_base64).unwrap();
    let dummy_pub = "0553362b7f036acf8cb5ce0db095c7d05cee0d52293cb9818131228d726b3295";
    let dummy_pubkey_hex = format!("03{}", dummy_pub);
    let dummy_pubkey_byte_array = hex::decode(dummy_pubkey_hex).unwrap();
    let dummy_recipient_pub =
        PublicKey::from_slice(&dummy_pubkey_byte_array[..]).expect("32 bytes, within curve order");
    let (_, shared_priv, _) = get_shared_key(sender_priv, dummy_recipient_pub);

    // let mut encrypted_bytes = [0u8; 5000];
    // // copy message to the buffer
    // let encrypted_vec_pos = encrypted_vec.len();
    // encrypted_bytes[..encrypted_vec_pos].copy_from_slice(&encrypted_vec[..]);

    let mut iv_bytes = [0u8; 16];
    // copy message to the buffer
    iv_bytes.copy_from_slice(&iv_vec[..]);

    println!("{:?}", iv_bytes);
    println!("{:?}", encrypted_vec);
    let plaintext = decrypt_ecdh(shared_priv, iv_bytes, encrypted_vec);

    println!("{}", plaintext);
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
            "subscription": [],
            "relay": []
        });

        fs::write("clust.json", json_data.to_string()).expect("Unable to write file");
    } else {
        println!("Config file exists!");
    }
}
