use std::io::{self, Cursor, Read};
use std::{fs, path::Path};

use bitcoin::{consensus::encode::deserialize_hex, witness, Witness};
use dleq::DLEQProof;
use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::elliptic_curve::{PublicKey};
use k256::{EncodedPoint, ProjectivePoint, Scalar};
use serde::Deserialize;
use k256::elliptic_curve::{Field, PrimeField};

use silentpayments::utils::receiving::get_pubkey_from_input;
use silentpayments::utils::SilentPaymentAddress;

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


fn deser_compact_size(f: &mut Cursor<&Vec<u8>>) -> io::Result<u64> {
    let mut buf = [0; 8];
    f.read_exact(&mut buf[..1])?;
    match buf[0] {
        0xfd => {
            f.read_exact(&mut buf[..2])?;
            Ok(u16::from_le_bytes(buf[..2].try_into().unwrap()) as u64)
        }
        0xfe => {
            f.read_exact(&mut buf[..4])?;
            Ok(u32::from_le_bytes(buf[..4].try_into().unwrap()) as u64)
        }
        0xff => {
            f.read_exact(&mut buf)?;
            Ok(u64::from_le_bytes(buf))
        }
        _ => Ok(buf[0] as u64),
    }
}

fn deser_string(f: &mut Cursor<&Vec<u8>>) -> io::Result<Vec<u8>> {
    let size = deser_compact_size(f)? as usize;
    let mut buf = vec![0; size];
    f.read_exact(&mut buf)?;
    Ok(buf)
}

pub fn deser_string_vector(f: &mut Cursor<&Vec<u8>>) -> io::Result<Vec<Vec<u8>>> {
    // Check if the buffer is empty before attempting to deserialize the size
    if f.get_ref().is_empty() {
        return Ok(Vec::new()); // Return an empty vector if the buffer is empty
    }
    let size = deser_compact_size(f)? as usize;
    let mut vec = Vec::with_capacity(size);
    for _ in 0..size {
        vec.push(deser_string(f)?);
    }
    Ok(vec)
}

pub fn process_silent_payment_vectors_from_file<P: AsRef<Path>>(file_path: P) -> (Scalar, ProjectivePoint, ProjectivePoint, ProjectivePoint) {
    let json_data = fs::read_to_string(file_path).expect("Failed to read JSON file");
    let vectors: Vec<TestVector> = serde_json::from_str(&json_data).expect("Failed to parse JSON test vectors");
    let first_output = vectors[0].sending[0].clone();

    let together_public_key_p = first_output.clone().given.vin.clone().into_iter().map(|data| {
        let pubkey = hex::decode(data.prevout.scriptPubKey.hex).unwrap();
        let txinwitness_bytes = hex::decode(&data.txinwitness).unwrap();
        let mut cursor = Cursor::new(&txinwitness_bytes);
        let txinwitness = deser_string_vector(&mut cursor).unwrap();
        let script_sig = hex::decode(data.scriptSig).unwrap();
        let public_key = get_pubkey_from_input(&script_sig, &txinwitness, pubkey.as_slice()).unwrap().unwrap();
        return  public_key;
    }). reduce(|acc, ecc| {
        return  acc.combine(&ecc).unwrap();
    }).unwrap().serialize();

    let together_public_key_p = ProjectivePoint::from_encoded_point(&EncodedPoint::from_bytes(together_public_key_p).unwrap()).unwrap();



    let together_private_key = first_output.clone().given.vin.into_iter().map(|data| {
        let priv_key = hex::decode(data.private_key.unwrap()).unwrap();
        let transformed_priv_key: [u8; 32]  = priv_key.try_into().expect("Vector should have 32 bytes");
        let scalar_priv_key =  Scalar::from_repr(transformed_priv_key.into()).expect("Failed to create scalar from hash");
        return scalar_priv_key
    }). reduce(|acc, ecc| {
        return  acc + ecc;
    }).unwrap();

    let recipient_address = first_output.given.recipients.clone().unwrap()[0].clone();
    let silent_payment_address = SilentPaymentAddress::try_from(recipient_address).unwrap();
    let scan_key = silent_payment_address.get_scan_key().serialize();
    let scan_tweak_pub = ProjectivePoint::from_encoded_point(&EncodedPoint::from_bytes(scan_key).unwrap()).unwrap();

    let together_public_key_q =  scan_tweak_pub * together_private_key;

    return (together_private_key, scan_tweak_pub,together_public_key_p, together_public_key_q);
    
}




fn main() {
    
    let enc = process_silent_payment_vectors_from_file("./test_vectors.json");
     
    let proof: DLEQProof = DLEQProof::generate(&enc.0 ,&ProjectivePoint::GENERATOR, &enc.1, &enc.2, &enc.3);
    let result = proof.verify(&ProjectivePoint::GENERATOR, &enc.1, &enc.2, &enc.3);
    print!("{}",result)

}
