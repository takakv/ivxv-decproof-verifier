use rasn::{types::*, AsnType, Decode, Decoder, Encode};

#[derive(AsnType, Clone, Decode, Encode)]
pub struct AlgorithmIdentifier {
    pub algorithm: ObjectIdentifier,
    pub parameters: Option<Any>,
}

// #[derive(AsnType, Clone, Decode, Encode)]
// pub struct IVXVPublicKeyParams {
//     pub curve_name: GeneralString,
//     pub election_identifier: GeneralString,
// }

#[derive(AsnType, Clone, Decode, Encode)]
pub struct ECPublicKey {
    pub ec_point: OctetString,
}

#[derive(AsnType, Clone, Decode, Encode)]
pub struct SubjectPublicKeyInfo {
    pub algorithm: AlgorithmIdentifier,
    pub subject_public_key: BitString,
}

#[derive(AsnType, Clone, Decode, Encode)]
pub struct ElGamalEncryptedMessage {
    pub u: OctetString,
    pub v: OctetString,
}

#[derive(AsnType, Clone, Decode, Encode)]
pub struct EncryptedBallot {
    pub algorithm: AlgorithmIdentifier,
    pub cipher: ElGamalEncryptedMessage,
}

#[derive(AsnType, Clone, Decode, Encode)]
pub struct DecryptionProof {
    pub msg_commitment: OctetString,
    pub key_commitment: OctetString,
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
    pub msg_commitment: OctetString,
    pub key_commitment: OctetString,
}
