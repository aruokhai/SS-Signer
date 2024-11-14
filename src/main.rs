use std::{fs, path::Path};

use bitcoin::{consensus::encode::deserialize_hex, witness, Witness};
use k256::elliptic_curve::PublicKey;
use serde::Deserialize;
use silentpayments::utils::receiving::get_pubkey_from_input;

mod  dleq;

#[derive(Deserialize, Debug, Clone)]
struct TestVector {
    comment: String,
    sending: Vec<SendingTest>,
    receiving: Vec<ReceivingTest>,
}

#[derive(Deserialize, Debug, Clone)]
struct SendingTest {
    given: GivenData,
    expected: ExpectedOutputs,
}

#[derive(Deserialize, Debug, Clone)]
struct ReceivingTest {
    given: GivenData,
    expected: ExpectedAddresses,
}

#[derive(Deserialize, Debug, Clone)]
struct GivenData {
    vin: Vec<Vin>,
    recipients: Option<Vec<String>>,  // For sending tests
    outputs: Option<Vec<String>>,     // For receiving tests
    key_material: Option<KeyMaterial>,
    labels: Option<Vec<String>>,
}

#[derive(Deserialize, Debug, Clone)]
struct Vin {
    txid: String,
    vout: u32,
    scriptSig: String,
    txinwitness: String,
    prevout: PrevOut,
    private_key: Option<String>,  // For sending tests
}

#[derive(Deserialize, Debug, Clone)]
struct PrevOut {
    scriptPubKey: ScriptPubKey,
}

#[derive(Deserialize, Debug, Clone)]
struct ScriptPubKey {
    hex: String,
}

#[derive(Deserialize, Debug, Clone)]
struct KeyMaterial {
    spend_priv_key: String,
    scan_priv_key: String,
}

#[derive(Deserialize, Debug, Clone)]
struct ExpectedOutputs {
    outputs: Vec<Vec<String>>,
}

#[derive(Deserialize, Debug, Clone)]
struct ExpectedAddresses {
    addresses: Vec<String>,
    outputs: Vec<OutputDetails>,
}

#[derive(Deserialize, Debug, Clone)]
struct OutputDetails {
    priv_key_tweak: String,
    pub_key: String,
    signature: String,
}


fn get_public_key() {

}

pub fn process_silent_payment_vectors_from_file<P: AsRef<Path>>(file_path: P) {
    let json_data = fs::read_to_string(file_path).expect("Failed to read JSON file");
    let vectors: Vec<TestVector> = serde_json::from_str(&json_data).expect("Failed to parse JSON test vectors");
    let first_output = vectors[0].sending[0].clone();
    let together_key = first_output.given.vin.into_iter().map(|data| {
        let pubkey = hex::decode(data.prevout.scriptPubKey.hex).unwrap();
        let witness_data = deserialize_hex::<Witness>(&data.txinwitness).unwrap().to_vec();
        let script_sig = hex::decode(data.scriptSig).unwrap();
        let public_key = get_pubkey_from_input(&script_sig, &witness_data, pubkey.as_slice()).unwrap().unwrap();
        return  public_key;
    }). reduce(|acc, ecc| {
        return  acc.combine(&ecc).unwrap();
    }).unwrap();
    
}




fn main() {
    println!("Hello, world!");
}
