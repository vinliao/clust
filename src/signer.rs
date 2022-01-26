use std::fs;
use secp256k1::{Secp256k1, Message, SecretKey, PublicKey};

// sign unsigned event
// currently unsigned event from file
// end goal is create unsigned event with event.rs

fn get_event() -> String {
    return fs::read_to_string("unsigned_event.json").expect("Unable to read file");
}

fn get_hex_slice() {
    // 13ea3d37b40b103db640b7bd84ba6d5664aee32d22d2b08868853e98f1286430
    // turns into slice of 0x13, 0xea, 0x3d, etc
    // use return of this function to SecretKey::from_slice
    // looks like requires loop
}

pub fn sign() {
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    // This is unsafe unless the supplied byte slice is the output of a cryptographic hash function.
    // See the above example for how to use this library together with bitcoin_hashes.
    let message = Message::from_slice(&[0xab; 32]).expect("32 bytes");

    let sig = secp.sign_ecdsa(&message, &secret_key);
    assert!(secp.verify_ecdsa(&message, &sig, &public_key).is_ok());


    println!("sign");
}
