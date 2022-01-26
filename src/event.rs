use schnorr_fun::{
fun::{marker::*, Scalar, nonce},
    Schnorr,
    Message
};
use hex;
use sha2::{Sha256, Digest};
use rand::rngs::ThreadRng;
use json::{array, object};

// struct Event {
//     id: String,
//     pubkey: String,
//     created_at: u32,
//     kind: u32,
//     tags: [String; 0],
//     content: String,
//     sig: String
// }

pub fn create_event(content: String) -> String {
    // steps:
    // 1. generate key
    // 2. hash data (as aligned in nip-01)
    // 3. get event id
    // 4. get sig
    // 5. create struct, return it
    
    // time should be generated
    let unix_time = 1643198791;
    
    // generate key
    let nonce_gen = nonce::Synthetic::<Sha256, nonce::GlobalRng<ThreadRng>>::default();
    let schnorr = Schnorr::<Sha256, _>::new(nonce_gen.clone());
    // Generate your public/private key-pair
    let keypair = schnorr.new_keypair(Scalar::random(&mut rand::thread_rng()));
    let (secret_key, public_key) = keypair.as_tuple();

    // create data
    // [0, toHexString(publicKey), unixTime, 1, [], content];
    let data = array![0, public_key.to_string(), unix_time, 1, [], content.to_string()];
    let data_string = data.dump();

    // hash data
    let mut hasher = Sha256::new();
    hasher.update(data_string.as_bytes());
    let event_id = hasher.finalize();    
    let event_id_hex = hex::encode(event_id);

    let message = Message::<Public>::raw(data_string.as_bytes());
    let signature = schnorr.sign(&keypair, message); // this signature isn't hex
    let signature_bytes = signature.to_bytes();
    let signature_hex = hex::encode(signature_bytes);

    let event = object!{
        id: event_id_hex,
        pubkey: public_key.to_string(),
        created_at: unix_time,
        kind: 1,
        tags: [],
        content: content.to_string(),
        sig: signature_hex
    };
    
    println!("{}", event.dump());
    return event.dump();
}
