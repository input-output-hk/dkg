//! Structures related to the broadcast messages
use crate::cryptography::elgamal::SymmetricKey;
use crate::cryptography::{
    commitment::CommitmentKey, correct_hybrid_decryption_key::CorrectHybridDecrKeyZkp,
    elgamal::HybridCiphertext,
};
use crate::dkg::committee::MembersFetchedState1;
use crate::dkg::procedure_keys::{MemberCommunicationKey, MemberCommunicationPublicKey};
use crate::errors::DkgError;
use crate::traits::{PrimeGroupElement, Scalar};
use rand_core::{CryptoRng, RngCore};

/// Type that contains the index of the receiver, and its two encrypted
/// shares.
pub type IndexedEncryptedShares<G> = (usize, HybridCiphertext<G>, HybridCiphertext<G>);

/// Type that contains the index of the receiver and its two decrypted
/// shares, together with the corresponding blinding commitment.
pub type IndexedDecryptedShares<G> = (
    usize,
    <G as PrimeGroupElement>::CorrespondingScalar,
    <G as PrimeGroupElement>::CorrespondingScalar,
    Vec<G>,
);

/// Type that contains misbehaving parties detected in round 1. These
/// consist of the misbehaving member's index, the error which failed,
/// and a proof of correctness of the misbehaviour claim.
pub type MisbehavingPartiesState1<G> = (usize, DkgError, ProofOfMisbehaviour<G>);

pub struct BroadcastPhase1<G: PrimeGroupElement> {
    pub committed_coefficients: Vec<G>,
    pub encrypted_shares: Vec<IndexedEncryptedShares<G>>,
}

pub struct BroadcastPhase2<G: PrimeGroupElement> {
    pub misbehaving_parties: Vec<MisbehavingPartiesState1<G>>,
}

pub struct BroadcastPhase3<G: PrimeGroupElement> {
    pub committed_coefficients: Vec<G>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofOfMisbehaviour<G: PrimeGroupElement> {
    symm_key_1: SymmetricKey<G>,
    symm_key_2: SymmetricKey<G>,
    encrypted_shares: IndexedEncryptedShares<G>,
    proof_decryption_1: CorrectHybridDecrKeyZkp<G>,
    proof_decryption_2: CorrectHybridDecrKeyZkp<G>,
}

impl<G: PrimeGroupElement> ProofOfMisbehaviour<G> {
    pub(crate) fn generate<R>(
        encrypted_shares: &IndexedEncryptedShares<G>,
        secret_key: &MemberCommunicationKey<G>,
        rng: &mut R,
    ) -> Self
    where
        R: CryptoRng + RngCore,
    {
        let symm_key_1 = secret_key.0.recover_symmetric_key(&encrypted_shares.1);
        let symm_key_2 = secret_key.0.recover_symmetric_key(&encrypted_shares.2);

        let proof_decryption_1 = CorrectHybridDecrKeyZkp::generate(
            &encrypted_shares.1,
            &secret_key.to_public(),
            &symm_key_1,
            secret_key,
            rng,
        );
        let proof_decryption_2 = CorrectHybridDecrKeyZkp::generate(
            &encrypted_shares.2,
            &secret_key.to_public(),
            &symm_key_2,
            secret_key,
            rng,
        );

        Self {
            symm_key_1,
            symm_key_2,
            encrypted_shares: encrypted_shares.clone(),
            proof_decryption_1,
            proof_decryption_2,
        }
    }

    // todo: we probably want to make the verifier input the Hybrid ctxt.
    pub fn verify(
        &self,
        complaining_pk: &MemberCommunicationPublicKey<G>,
        fetched_data: &MembersFetchedState1<G>,
        commitment_key: &CommitmentKey<G>,
        plaintiff_index: usize,
        threshold: usize,
    ) -> Result<(), DkgError> {
        let proof1_is_err = self
            .proof_decryption_1
            .verify(
                &fetched_data.indexed_shares.1,
                &self.symm_key_1,
                complaining_pk,
            )
            .is_err();

        let proof2_is_err = self
            .proof_decryption_2
            .verify(
                &fetched_data.indexed_shares.2,
                &self.symm_key_2,
                complaining_pk,
            )
            .is_err();

        if proof1_is_err || proof2_is_err {
            return Err(DkgError::InvalidProofOfMisbehaviour);
        }

        let plaintext_1 = <G::CorrespondingScalar as Scalar>::from_bytes(
            &self.symm_key_1.process(&self.encrypted_shares.1.e2),
        )
        .ok_or(DkgError::DecodingToScalarFailed)?;

        let plaintext_2 = <G::CorrespondingScalar as Scalar>::from_bytes(
            &self.symm_key_2.process(&self.encrypted_shares.2.e2),
        )
        .ok_or(DkgError::DecodingToScalarFailed)?;

        let index_pow = <G::CorrespondingScalar as Scalar>::from_u64(plaintiff_index as u64)
            .exp_iter()
            .take(threshold + 1);

        let check_element = commitment_key.h * plaintext_1 + G::generator() * plaintext_2;
        let multi_scalar =
            G::vartime_multiscalar_multiplication(index_pow, fetched_data.clone().committed_coeffs);

        if check_element != multi_scalar {
            return Ok(());
        }

        Err(DkgError::InvalidProofOfMisbehaviour)
    }
}
