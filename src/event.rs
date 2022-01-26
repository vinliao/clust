use schnorr_fun::{
fun::{marker::*, Scalar, nonce},
    Schnorr,
    Message
};
use hex;
use sha2::{Sha256, Digest};
use rand::rngs::ThreadRng;
use json::array;

struct Event {
    id: String,
    pubkey: String,
    created_at: u32,
    kind: u32,
    tags: [String; 0],
    content: String,
    sig: String
}

pub fn create_event() {
    // steps:
    // 1. generate key
    // 2. hash data (as aligned in nip-01)
    // 3. get event id
    // 4. get sig
    // 5. create struct, return it
    
    // content should be inputted, time should be generated
    let content = "random message";
    let unix_time = 1643198791;
    
    // generate key
    // Use synthetic nonces
    let nonce_gen = nonce::Synthetic::<Sha256, nonce::GlobalRng<ThreadRng>>::default();
    let schnorr = Schnorr::<Sha256, _>::new(nonce_gen.clone());
    // Generate your public/private key-pair
    let keypair = schnorr.new_keypair(Scalar::random(&mut rand::thread_rng()));
    let (secret_key, public_key) = keypair.as_tuple();

    println!("{}", secret_key);
    println!("{}", public_key);

    // create data
    // [0, toHexString(publicKey), unixTime, 1, [], content];
    let data = array![0, public_key.to_string(), unix_time, 1, [], content.to_string()];

    // hash data
    let mut hasher = Sha256::new();
    // dump turns it to string, as bytes turns it to byte array
    hasher.update(data.dump().as_bytes());
    let event_id = hasher.finalize();    
    let event_id_hex = hex::encode(event_id);
    println!("{}", event_id_hex);
    println!("{}", data.dump());

    // // Sign a variable length message
    // let message = Message::<Public>::plain("the-times-of-london", b"Chancellor on brink of second bailout for banks");
    // // Sign the message with our keypair
    // let signature = schnorr.sign(&keypair, message);
    // // Get the verifier's key
    // let verification_key = keypair.verification_key();
    // // Check it's valid 🍿
    // assert!(schnorr.verify(&verification_key, message, &signature));

}
