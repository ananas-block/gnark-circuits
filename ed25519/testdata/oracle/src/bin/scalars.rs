use curve25519_dalek::{
    constants::{ED25519_BASEPOINT_POINT, EIGHT_TORSION},
    scalar::Scalar,
};
use serde_json::json;
fn main() {
    let mut rows = vec![];
    let mut values = vec![
        Scalar::ZERO,
        Scalar::ONE,
        Scalar::from(2u64),
        Scalar::from(3u64),
        -Scalar::ONE,
        -Scalar::from(2u64),
        -Scalar::from(3u64),
    ];
    for i in [31, 32, 63, 64, 127, 128, 191, 192, 250, 251, 252] {
        let mut b = [0u8; 32];
        b[i / 8] = 1 << (i % 8);
        let s = Scalar::from_bytes_mod_order(b);
        values.extend([s, s - Scalar::ONE, s + Scalar::ONE]);
    }
    for torsion in 0..8 {
        let p = ED25519_BASEPOINT_POINT + EIGHT_TORSION[torsion];
        for s in &values {
            rows.push(json!({"torsion":torsion,"key":hex::encode(p.compress().to_bytes()),"scalar":hex::encode(s.to_bytes()),"result":hex::encode((p*s).compress().to_bytes()),"r_for_s5":hex::encode((ED25519_BASEPOINT_POINT*Scalar::from(5u64)-p*s).compress().to_bytes())}));
        }
    }
    println!("{}", serde_json::to_string_pretty(&rows).unwrap());
}
