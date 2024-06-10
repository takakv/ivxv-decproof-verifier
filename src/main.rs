use std::{
    cmp::Ordering,
    fs,
    ops::{Deref, Shr},
};

use base64::{engine::general_purpose, Engine};
use rug::integer::Order;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

use asn1::structs::{
    DecryptionProof, ElGamalParamsIVXV, ElGamalPublicKey, EncryptedBallot, ProofSeed,
    SubjectPublicKeyInfo,
};

mod asn1;

const BYTE_ORDER: Order = Order::Msf;

#[derive(Deserialize)]
struct ProofPackage {
    ciphertext: String,
    message: String,
    proof: String,
}

#[derive(Deserialize)]
struct DecryptionProofs {
    #[allow(dead_code)]
    election: String,
    proofs: Vec<ProofPackage>,
}

#[derive(Clone)]
pub struct PublicKey {
    pub p: asn1::integer::Integer,
    pub q: asn1::integer::Integer,
    pub g: asn1::integer::Integer,
    pub h: asn1::integer::Integer,
    pub spki: SubjectPublicKeyInfo,
}

fn bytes_to_int(b: &[u8]) -> rug::Integer {
    return rug::Integer::from_digits(b, BYTE_ORDER);
}

fn rasn_to_rug(i: rasn::types::Integer) -> rug::Integer {
    return rug::Integer::from_digits(i.to_signed_bytes_be().deref(), BYTE_ORDER);
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
        ni_proof_domain: rasn::types::GeneralString::try_from(String::from("DECRYPTION"))
            .expect("failed to create GeneralString"),
        public_key: spki.clone(),
        ciphertext: eb.clone(),
        decrypted: rasn::types::OctetString::from(dec.clone()),
        msg_commitment: dp.msg_commitment.clone(),
        key_commitment: dp.key_commitment.clone(),
    };

    return rasn::der::encode(&ni_proof).unwrap();
}

fn compute_challenge(seed: &Vec<u8>, ub: rug::Integer) -> rug::Integer {
    let mut counter: u64 = 1;

    loop {
        let mut hash_bytes: Vec<u8> = vec![];

        // SHA256 has a digest size of 32 bytes.
        // 12 * (32 * 8) = 3072
        for _ in 1..=12 {
            let mut in_bytes: Vec<u8> = vec![];
            in_bytes.extend_from_slice(&counter.to_be_bytes());
            in_bytes.extend(seed);

            let hash = Sha256::digest(&in_bytes);
            hash_bytes.extend(hash.as_slice());
            counter += 1;
        }

        if hash_bytes[0] >= 128 {
            hash_bytes[0] -= 128
        }

        let num = bytes_to_int(&hash_bytes);
        if num.cmp(&ub) == Ordering::Less {
            return num;
        }
    }
}

fn verify_proof(package: ProofPackage, pubkey: PublicKey) -> bool {
    let ciphertext_bin = b64decode(package.ciphertext);
    let message_bin = b64decode(package.message);
    let proof_bin = b64decode(package.proof);

    let ciphertext_asn1: EncryptedBallot = rasn::der::decode(&ciphertext_bin).unwrap();
    let proof_asn1: DecryptionProof = rasn::der::decode(&proof_bin).unwrap();

    let seed = derive_seed(&pubkey.spki, &ciphertext_asn1, &message_bin, &proof_asn1);
    let k = compute_challenge(&seed, pubkey.q.clone());

    let u = ciphertext_asn1.cipher.u;
    let v = ciphertext_asn1.cipher.v;
    let a = proof_asn1.msg_commitment;
    let b = proof_asn1.key_commitment;
    let s = proof_asn1.response;
    let mut m = bytes_to_int(&message_bin);

    // By Euler, m is a QR if m^q = 1 (mod p).
    let e = m.clone().pow_mod(&pubkey.q, &pubkey.p).unwrap();
    if e.cmp(rug::Integer::ONE) != Ordering::Equal {
        m = &pubkey.p - m;
    }
    let m_inv = m.invert(&pubkey.p).unwrap();

    let lhs1 = u.pow_mod(&s, &pubkey.p).unwrap();
    let rhs1 = (a * (v * m_inv).pow_mod(&k, &pubkey.p).unwrap()) % &pubkey.p;

    if !lhs1.eq(&rhs1) {
        return false;
    }

    let lhs2 = &pubkey.g.pow_mod(&s, &pubkey.p).unwrap();
    let rhs2 = (b * &pubkey.h.pow_mod(&k, &pubkey.p).unwrap()) % &pubkey.p;
    return lhs2.eq(&rhs2);
}

fn parse_pubkey(pubkey_bin: &Vec<u8>) -> PublicKey {
    let spki: SubjectPublicKeyInfo = rasn::der::decode(pubkey_bin).unwrap();
    let encapsulated_pk_bin = spki.subject_public_key.as_raw_slice();
    let params_bin = spki.algorithm.parameters.clone().unwrap().into_bytes();

    let params: ElGamalParamsIVXV = rasn::der::decode(&params_bin).unwrap();
    let pkref: ElGamalPublicKey = rasn::der::decode(encapsulated_pk_bin).unwrap();

    let pubkey = PublicKey {
        p: params.p.clone(),
        q: (params.p - 1).shr(1),
        g: params.g,
        h: pkref.h,
        spki,
    };

    return pubkey;
}

#[tokio::main]
async fn main() {
    let pubkey_der_bin = fs::read("EP_2024-pub.der").expect("Unable to read from file");
    let pubkey = parse_pubkey(&pubkey_der_bin);

    let proofs_json_str: String =
        fs::read_to_string("./EP_2024-proof").expect("Unable to read from file");
    let proofs_json: DecryptionProofs =
        serde_json::from_str(&proofs_json_str).expect("Unable to parse JSON");

    let (tx, mut rx) = mpsc::unbounded_channel();
    let mut handles = Vec::new();

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
