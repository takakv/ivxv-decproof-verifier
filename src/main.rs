use std::fs;

use base64::{engine::general_purpose, Engine};
use p384::{
    elliptic_curve::{
        bigint::Encoding,
        sec1::{FromEncodedPoint, ToEncodedPoint},
        Curve, PrimeField,
    },
    EncodedPoint, NistP384, ProjectivePoint, Scalar, U384,
};
use rasn::types::{IntegerType, OctetString};
use serde::Deserialize;
use sha2::{digest::Update, Digest, Sha256};
use tokio::sync::mpsc;

use asn1::structs::{
    DecryptionProof, ECPublicKey, EncryptedBallot, ProofSeed, SubjectPublicKeyInfo,
};

mod asn1;

const NUM_BYTES: usize = (Scalar::NUM_BITS / 8) as usize;

#[derive(Deserialize)]
struct ProofPackage {
    ciphertext: String,
    message: String,
    proof: String,
}

#[derive(Deserialize)]
struct DecryptionProofs {
    election: String,
    proofs: Vec<ProofPackage>,
}

#[derive(Clone)]
pub struct PublicKey {
    pub point: ProjectivePoint,
    pub spki: SubjectPublicKeyInfo,
}

fn bytes_to_int(b: &[u8]) -> U384 {
    U384::from_be_slice(b)
}

fn asn1int_to_scalar(i: rasn::types::Integer) -> Scalar {
    // We know that the bytes are unsigned.
    // However, if the first bit is set, i.to_unsigned_bytes_be() will prepend a 0-byte.
    // This will cause Scalar::from_slice() to panic due to an incompatible length.
    // There is also a small probability that there are 8 or more leading 0-bits.
    let (bytes, len) = i.to_unsigned_bytes_be();
    let slice = bytes.as_ref();

    match len.cmp(&NUM_BYTES) {
        std::cmp::Ordering::Equal => Scalar::from_slice(slice).unwrap(),
        std::cmp::Ordering::Greater => Scalar::from_slice(&slice[1..]).unwrap(),
        std::cmp::Ordering::Less => {
            let mut buf = [0u8; NUM_BYTES];
            buf[NUM_BYTES - len..].copy_from_slice(&slice[..len]);
            Scalar::from_slice(&buf).unwrap()
        }
    }
}

fn der_to_point(octets: &[u8]) -> ProjectivePoint {
    let point: OctetString = rasn::der::decode(octets).unwrap();
    octets_to_point(&point)
}

fn octets_to_point(octets: &[u8]) -> ProjectivePoint {
    let encoded = EncodedPoint::from_bytes(octets).unwrap();
    ProjectivePoint::from_encoded_point(&encoded).unwrap()
}

fn b64decode(s: String) -> Vec<u8> {
    return general_purpose::STANDARD.decode(s).unwrap();
}

fn derive_seed(
    spki: &SubjectPublicKeyInfo,
    eb: &EncryptedBallot,
    dec: &Vec<u8>,
    dp: &DecryptionProof,
) -> Vec<u8> {
    let ni_proof = ProofSeed {
        ni_proof_domain: rasn::types::GeneralString::try_from(String::from("DECRYPTION")).unwrap(),
        public_key: spki.clone(),
        ciphertext: eb.clone(),
        decrypted: rasn::types::OctetString::from(dec.clone()),
        msg_commitment: dp.msg_commitment.clone(),
        key_commitment: dp.key_commitment.clone(),
    };

    rasn::der::encode(&ni_proof).unwrap()
}

fn compute_challenge(seed: &Vec<u8>, upper_bound: U384) -> Scalar {
    const BLOCK_LEN: usize = 32; // SHA-256 has a digest size of 32 bytes.
    const BUFFER_CAPACITY: usize = (NUM_BYTES + BLOCK_LEN - 1) / BLOCK_LEN; // ceil(NUM_BYTES / BLOCK_LEN)

    let mut counter: u64 = 0;
    let mut buffer = Vec::with_capacity(BUFFER_CAPACITY);
    let mut num = upper_bound;

    while num >= upper_bound {
        // Minimum number of hashes needed to meet the required byte-count.
        // ceil(BOUND_SIZE - buffer.len() / BLOCK_LEN)
        let blocks_needed: usize = (NUM_BYTES - buffer.len() + BLOCK_LEN - 1) / BLOCK_LEN;

        for _ in 0..blocks_needed {
            counter += 1;
            let digest = Sha256::new()
                .chain(counter.to_be_bytes())
                .chain(seed)
                .finalize();
            buffer.extend_from_slice(&digest);
        }

        num = bytes_to_int(&buffer[..NUM_BYTES]);
        buffer.drain(..NUM_BYTES);
    }

    Scalar::from_slice(&num.to_be_bytes()).unwrap()
}

fn verify_proof(package: ProofPackage, pubkey: PublicKey) -> bool {
    let ciphertext_bin = b64decode(package.ciphertext);
    let message_bin = b64decode(package.message);
    let proof_bin = b64decode(package.proof);

    let ciphertext_asn1: EncryptedBallot = rasn::der::decode(&ciphertext_bin).unwrap();
    let proof_asn1: DecryptionProof = rasn::der::decode(&proof_bin).unwrap();

    let decrypted = der_to_point(&message_bin);
    let decrypted_bin = decrypted.to_encoded_point(false);

    let seed = derive_seed(
        &pubkey.spki,
        &ciphertext_asn1,
        &decrypted_bin.as_bytes().to_vec(),
        &proof_asn1,
    );

    let k = compute_challenge(&seed, NistP384::ORDER);

    let u = octets_to_point(&ciphertext_asn1.cipher.u);
    let v = octets_to_point(&ciphertext_asn1.cipher.v);
    let a = octets_to_point(&proof_asn1.msg_commitment);
    let b = octets_to_point(&proof_asn1.key_commitment);
    let s = asn1int_to_scalar(proof_asn1.response);

    let lhs1 = u * s;
    let rhs1 = a + (v - decrypted) * k;

    if !lhs1.eq(&rhs1) {
        return false;
    }

    let lhs2 = ProjectivePoint::GENERATOR * s;
    let rhs2 = b + pubkey.point * k;

    lhs2.eq(&rhs2)
}

fn parse_pubkey(pubkey_bin: &[u8]) -> PublicKey {
    let spki: SubjectPublicKeyInfo = rasn::der::decode(pubkey_bin).unwrap();
    let encapsulated_pk_bin = spki.subject_public_key.as_raw_slice();
    // let params_bin = spki.algorithm.parameters.clone().unwrap().into_bytes();

    // let params: IVXVPublicKeyParams = rasn::der::decode(&params_bin).unwrap();
    let pkref: ECPublicKey = rasn::der::decode(encapsulated_pk_bin).unwrap();

    PublicKey {
        point: octets_to_point(&pkref.ec_point),
        spki,
    }
}

#[tokio::main]
async fn main() {
    const ELECTION_ID: &str = "DUMMYGEN_01";
    let pubkey_pem_bin =
        fs::read(format!("{ELECTION_ID}-pub.pem")).expect("Unable to read from file");
    let pubkey_pem = pem::parse(pubkey_pem_bin).unwrap();
    let pubkey = parse_pubkey(pubkey_pem.contents());

    let proofs_json_str: String =
        fs::read_to_string(format!("{ELECTION_ID}-proof")).expect("Unable to read from file");
    let proofs_json: DecryptionProofs =
        serde_json::from_str(&proofs_json_str).expect("Unable to parse JSON");

    println!(
        "Verifying proofs of correct decryption for election: '{}'.",
        proofs_json.election
    );
    println!();

    let (tx, mut rx) = mpsc::unbounded_channel();
    let mut handles = vec![];

    for package in proofs_json.proofs {
        let pubkey = pubkey.clone();
        let tx = tx.clone();

        handles.push(tokio::spawn(async move {
            tx.send(verify_proof(package, pubkey)).unwrap();
        }));
    }
    drop(tx);

    futures::future::join_all(handles).await;

    let mut success_count = 0;
    let mut failure_count = 0;

    while let Some(msg) = rx.recv().await {
        if msg {
            success_count += 1;
        } else {
            failure_count += 1;
        }
    }

    println!("Successful verifications: {}", success_count);
    println!("Failed verifications    : {}", failure_count);
}
