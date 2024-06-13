use std::{
    cmp::Ordering,
    fs,
    ops::{Deref, Shr},
};

use base64::{engine::general_purpose, Engine};
use der::{
    asn1::{OctetStringRef, Utf8StringRef},
    Decode, Encode,
};
use pem::Pem;
use rug::{integer::Order, Integer};
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
pub struct PublicKey<'a> {
    pub p: Integer,
    pub q: Integer,
    pub g: Integer,
    pub h: Integer,
    pub spki: SubjectPublicKeyInfo<'a>,
}

fn bytes_to_int(b: &[u8]) -> Integer {
    return Integer::from_digits(b, BYTE_ORDER);
}

fn asn1int_to_int(i: rasn::types::Integer) -> Integer {
    return Integer::from_digits(i.to_signed_bytes_be().deref(), BYTE_ORDER);
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
        ni_proof_domain: Utf8StringRef::new("DECRYPTION").expect("failed to create Utf8StringRef"),
        public_key: spki.clone(),
        ciphertext: eb.clone(),
        decrypted: OctetStringRef::new(dec).expect("failed to create OctetStringRef"),
        msg_commitment: dp.msg_commitment,
        key_commitment: dp.key_commitment,
    };

    // The library does not support the GeneralString string type,
    // so we need to transform the UTF-8 string into a general string.
    let mut seed = ni_proof.to_der().unwrap();
    seed[4] = 0x1B;

    return seed;
}

fn compute_challenge(seed: &Vec<u8>, ub: &Integer) -> Integer {
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
        if num.cmp(ub) == Ordering::Less {
            return num;
        }
    }
}

fn verify_proof(package: ProofPackage, pubkey: PublicKey) -> bool {
    let ciphertext_bin = b64decode(package.ciphertext);
    let message_bin = b64decode(package.message);
    let proof_bin = b64decode(package.proof);

    let ciphertext_asn1 = EncryptedBallot::from_der(&ciphertext_bin).unwrap();
    let proof_asn1 = DecryptionProof::from_der(&proof_bin).unwrap();

    let seed = derive_seed(&pubkey.spki, &ciphertext_asn1, &message_bin, &proof_asn1);
    let k = compute_challenge(&seed, &pubkey.q);

    // Convert between arbitrary precision integer types for performance.
    let u = bytes_to_int(ciphertext_asn1.cipher.u.as_bytes());
    let v = bytes_to_int(ciphertext_asn1.cipher.v.as_bytes());
    let a = bytes_to_int(proof_asn1.msg_commitment.as_bytes());
    let b = bytes_to_int(proof_asn1.key_commitment.as_bytes());
    let s = bytes_to_int(proof_asn1.response.as_bytes());
    let mut m = bytes_to_int(&message_bin);

    // By Euler, m is a QR if m^q = 1 (mod p).
    let e = m.clone().pow_mod(&pubkey.q, &pubkey.p).unwrap();
    if e.cmp(Integer::ONE) != Ordering::Equal {
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

fn parse_pubkey<'a>(pem_bin: &'a [u8]) -> PublicKey<'a> {
    let spki = SubjectPublicKeyInfo::from_der(&pem_bin).unwrap();
    let encapsulated_pk_bin = spki.subject_public_key.as_bytes().unwrap();

    // The library does not support the GeneralString string type,
    // so we need to transform the GeneralString into an UTF8String.
    let mut params_bin = spki.algorithm.parameters.unwrap().to_der().unwrap();
    let general_string_idx = params_bin.iter().rposition(|&x| x == 0x1B).unwrap();
    params_bin[general_string_idx] = 0x0C;

    let params = ElGamalParamsIVXV::from_der(&params_bin).unwrap();
    let pkref = ElGamalPublicKey::from_der(encapsulated_pk_bin).unwrap().h;

    // Convert between arbitrary precision integer types for performance.
    let pub_mod = bytes_to_int(params.p.as_bytes());
    let pubkey = PublicKey {
        p: pub_mod.clone(),
        q: Integer::from(pub_mod - 1).shr(1),
        g: bytes_to_int(params.g.as_bytes()),
        h: bytes_to_int(pkref.as_bytes()),
        spki: spki.clone(),
    };

    return pubkey;
}

#[tokio::main]
async fn main() {
    let pubkey_pem_bin = fs::read("EP_2024-pub.pem").expect("Unable to read from file");
    let pubkey_pem= pem::parse(pubkey_pem_bin).unwrap();
    let tmp = pubkey_pem.contents();
    let pubkey = parse_pubkey(tmp);

    let proofs_json_str: String =
        fs::read_to_string("./EP_2024-proof").expect("Unable to read from file");
    let proofs_json: DecryptionProofs =
        serde_json::from_str(&proofs_json_str).expect("Unable to parse JSON");

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
