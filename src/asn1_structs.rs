use der::{
    asn1::{AnyRef, BitStringRef, ObjectIdentifier, OctetStringRef, UintRef, Utf8StringRef},
    Sequence,
};

#[derive(Copy, Clone, Debug, Eq, PartialEq, Sequence)]
pub struct AlgorithmIdentifier<'a> {
    pub algorithm: ObjectIdentifier,
    pub parameters: Option<AnyRef<'a>>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Sequence)]
pub struct ElGamalParamsIVXV<'a> {
    pub p: UintRef<'a>,
    pub g: UintRef<'a>,
    pub election_identifier: Utf8StringRef<'a>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Sequence)]
pub struct ElGamalPublicKey<'a> {
    pub h: UintRef<'a>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Sequence)]
pub struct SubjectPublicKeyInfo<'a> {
    pub algorithm: AlgorithmIdentifier<'a>,
    pub subject_public_key: BitStringRef<'a>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Sequence)]
pub struct ElGamalEncryptedMessage<'a> {
    pub u: UintRef<'a>,
    pub v: UintRef<'a>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Sequence)]
pub struct EncryptedBallot<'a> {
    pub algorithm: AlgorithmIdentifier<'a>,
    pub cipher: ElGamalEncryptedMessage<'a>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Sequence)]
pub struct DecryptionProof<'a> {
    pub msg_commitment: UintRef<'a>,
    pub key_commitment: UintRef<'a>,
    pub response: UintRef<'a>,
    pub intermediate_k: Option<UintRef<'a>>,
    pub intermediate_seed: Option<UintRef<'a>>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Sequence)]
pub struct ProofSeed<'a> {
    pub ni_proof_domain: Utf8StringRef<'a>,
    pub public_key: SubjectPublicKeyInfo<'a>,
    pub ciphertext: EncryptedBallot<'a>,
    pub decrypted: OctetStringRef<'a>,
    pub msg_commitment: UintRef<'a>,
    pub key_commitment: UintRef<'a>,
}