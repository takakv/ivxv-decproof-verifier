use rasn::{AsnType, Decode, Encode, types::*};

#[derive(AsnType, Clone, Decode, Encode)]
pub struct AlgorithmIdentifier {
    pub algorithm: ObjectIdentifier,
    pub parameters: Option<Any>,
}

#[derive(AsnType, Clone, Decode, Encode)]
pub struct ElGamalParamsIVXV {
    pub p: Integer,
    pub g: Integer,
    pub election_identifier: GeneralString,
}

#[derive(AsnType, Clone, Decode, Encode)]
pub struct ElGamalPublicKey {
    pub h: Integer,
}

#[derive(AsnType, Clone, Decode, Encode)]
pub struct SubjectPublicKeyInfo {
    pub algorithm: AlgorithmIdentifier,
    pub subject_public_key: BitString,
}

#[derive(AsnType, Clone, Decode, Encode)]
pub struct ElGamalEncryptedMessage {
    pub u: Integer,
    pub v: Integer,
}

#[derive(AsnType, Clone, Decode, Encode)]
pub struct EncryptedBallot {
    pub algorithm: AlgorithmIdentifier,
    pub cipher: ElGamalEncryptedMessage,
}

#[derive(AsnType, Clone, Decode, Encode)]
pub struct DecryptionProof {
    pub msg_commitment: Integer,
    pub key_commitment: Integer,
    pub response: Integer,
    // These are not part of the proof in practice.
    // The specification does not specify explicit tags either.
    // #[rasn(tag(0))]
    // pub intermediate_k: Option<Integer>,
    // #[rasn(tag(1))]
    // pub intermediate_seed: Option<Integer>,
}

#[derive(AsnType, Clone, Decode, Encode)]
pub struct ProofSeed {
    pub ni_proof_domain: GeneralString,
    pub public_key: SubjectPublicKeyInfo,
    pub ciphertext: EncryptedBallot,
    pub decrypted: OctetString,
    pub msg_commitment: Integer,
    pub key_commitment: Integer,
}
