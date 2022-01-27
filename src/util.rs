use std::fs;
use serde_json;

pub fn get_privkey() -> String {
    let data = fs::read_to_string("clust.json").expect("Unable to read file");
    let json_data: serde_json::Value = serde_json::from_str(&data).expect("Fail to parse");

    return json_data["privkey"].to_string();
}

pub fn set_privkey(privkey: String) {
    let data = fs::read_to_string("clust.json").expect("Unable to read file");
    let mut json_data: serde_json::Value = serde_json::from_str(&data).expect("Fail to parse");

    json_data["privkey"] = serde_json::Value::String(privkey);
    fs::write("clust.json", json_data.to_string());
}

pub fn add_relay() {
    // add a relay to .clustrc
}

pub fn remove_relay() {
    // remove a relay to .clustrc
}
