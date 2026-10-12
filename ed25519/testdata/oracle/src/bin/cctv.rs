use ed25519_dalek_v1::ed25519::signature::Signature as _;
use ed25519_dalek_v1::{PublicKey, Signature};
use serde_json::Value;
fn main() {
    let path = std::env::args().nth(1).expect("path to original CCTV JSON");
    let mut data: Value =
        serde_json::from_slice(&std::fs::read(path).expect("read vectors")).expect("JSON vectors");
    for row in data.as_array_mut().expect("vector array") {
        let key = hex::decode(row["key"].as_str().expect("key")).expect("hex key");
        let sig = hex::decode(row["sig"].as_str().expect("sig")).expect("hex sig");
        let msg = row["msg"].as_str().expect("msg").as_bytes();
        let accepted = PublicKey::from_bytes(&key)
            .and_then(|k| Signature::from_bytes(&sig).and_then(|s| k.verify_strict(msg, &s)))
            .is_ok();
        row["dalek_strict"] = accepted.into();
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&data).expect("serialize")
    );
}
