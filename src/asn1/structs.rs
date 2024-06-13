use der::{
    asn1::{Any, BitStringRef, ObjectIdentifier, OctetStringRef, UintRef, Uint, Utf8StringRef},
    Sequence,
};

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct AlgorithmIdentifier {
    pub algorithm: ObjectIdentifier,
    pub parameters: Option<Any>,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct ElGamalParamsIVXV {
    pub p: Uint,
    pub g: Uint,
    pub election_identifier: Utf8StringRef<'static>,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct ElGamalPublicKey {
    pub h: Uint,
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