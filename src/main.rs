use std::{
    fs,
    sync::atomic::{AtomicUsize, Ordering},
    time::Instant,
};

use base64::{engine::general_purpose, Engine};
use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use ivxv::{
    election::ElectionPublicKey,
    proofs::decryption::{DecryptionContext, DecryptionVerifyError},
    ParseError,
};
use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};
use serde::Deserialize;

#[derive(Debug, thiserror::Error)]
enum ProofError {
    #[error("malformed base64: {0}")]
    MalformedBase64(#[from] base64::DecodeError),

    #[error(transparent)]
    Parse(#[from] ParseError),

    #[error(transparent)]
    Verify(#[from] DecryptionVerifyError),
}

#[derive(Parser)]
struct Args {
    public_key: String,
    proofs: String,
}

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

fn b64decode(s: &str) -> Result<Vec<u8>, ProofError> {
    Ok(general_purpose::STANDARD.decode(s)?)
}

fn verify_proof(package: &ProofPackage, ctx: &DecryptionContext) -> Result<(), ProofError> {
    Ok(ctx.verify_der(
        &b64decode(&package.ciphertext)?,
        &b64decode(&package.message)?,
        &b64decode(&package.proof)?,
    )?)
}

fn main() {
    let args = Args::parse();

    let pubkey_pem = fs::read_to_string(&args.public_key).expect("Unable to read key from file");
    let pubkey = ElectionPublicKey::from_pem(&pubkey_pem).expect("Unable to parse public key");

    let proofs_json_str =
        fs::read_to_string(&args.proofs).expect("Unable to read proofs from file");
    let proofs_json: DecryptionProofs =
        serde_json::from_str(&proofs_json_str).expect("Unable to parse JSON");

    println!(
        "Verifying proofs of correct decryption for election: '{}'.",
        proofs_json.election
    );

    if proofs_json.election != pubkey.election_id() {
        println!(
            "WARNING: the key is for election '{}', but the proofs claim '{}'.",
            pubkey.election_id(),
            proofs_json.election
        );
    }

    let total = proofs_json.proofs.len() as u64;
    let pb = ProgressBar::new(total);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({percent}%)")
            .expect("Invalid template")
            .progress_chars("=>-"),
    );

    let ctx = DecryptionContext::new(&pubkey);
    let success_count = AtomicUsize::new(0);
    let failure_count = AtomicUsize::new(0);

    let start = Instant::now();
    proofs_json
        .proofs
        .into_par_iter()
        .enumerate()
        .for_each(|(i, package)| {
            match verify_proof(&package, &ctx) {
                Ok(()) => {
                    success_count.fetch_add(1, Ordering::Relaxed);
                }
                Err(e) => {
                    failure_count.fetch_add(1, Ordering::Relaxed);
                    pb.println(format!("Proof {i}: {e}"));
                }
            }
            pb.inc(1);
        });
    pb.finish();

    let duration = start.elapsed();

    println!("\n");
    println!(
        "Successful verifications: {}",
        success_count.load(Ordering::Relaxed)
    );
    println!(
        "Failed verifications. . : {}",
        failure_count.load(Ordering::Relaxed)
    );
    println!("Verification took . . . : {:?}", duration);
}
