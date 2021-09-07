//! Structures related to the broadcast messages
use crate::cryptography::elgamal::SymmetricKey;
use crate::cryptography::{
    correct_hybrid_decryption_key::CorrectHybridDecrKeyZkp, elgamal::HybridCiphertext,
};
use crate::dkg::committee::Environment;
use crate::dkg::procedure_keys::{MemberCommunicationKey, MemberCommunicationPublicKey};
use crate::errors::DkgError;
use crate::traits::{PrimeGroupElement, Scalar};
use rand_core::{CryptoRng, RngCore};

/// Struct that contains the index of the receiver, and its two encrypted
/// shares. In particular, `encrypted_share`//( = \texttt{Enc}(f_i(\texttt{recipient_index}))//),
/// while `encrypted_randomness`//( = \texttt{Enc}(f_i'(\texttt{recipient_index}))//).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptedShares<G: PrimeGroupElement> {
    pub recipient_index: usize,
    pub encrypted_share: HybridCiphertext<G>,
    pub encrypted_randomness: HybridCiphertext<G>,
}

/// Struct that contains two decrypted shares, together with the blinding commitment
/// of the coefficients of the associated polynomial.
/// todo: ok not linking an index to the share? I think its fine, as this is handled locally
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecryptedShares<G: PrimeGroupElement> {
    pub decrypted_share: <G as PrimeGroupElement>::CorrespondingScalar,
    pub decrypted_randomness: <G as PrimeGroupElement>::CorrespondingScalar,
    pub committed_coefficients: Vec<G>,
}

/// Struct that contains misbehaving parties detected in round 1. These
/// consist of the misbehaving member's index, the error which failed,
/// and a `ProofOfMisbehaviour`, which contains the invalid encrypted shares
/// and a proof of correct decryption. A single valid
/// complaint disqualifies the accused member.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MisbehavingPartiesRound1<G: PrimeGroupElement> {
    pub(crate) accused_index: usize,
    pub(crate) accusation_error: DkgError,
    pub(crate) proof_accusation: ProofOfMisbehaviour<G>,
}

impl<G: PrimeGroupElement> MisbehavingPartiesRound1<G> {
    /// Function to validate that a complaint against a given participant is valid. To validate
    /// a complaint from phase one, the verifier needs to check that the decrypted shares
    /// in `proof_accusation` are indeed the decryption of the encrypted indices sent by party
    /// `accused_index` to party `accuser_index`. Then it verifies that the decrypted shares
    /// do not correspond to the evaluation of the committed polynomial at value `accuser_index`.
    pub fn verify(
        &self,
        environment: &Environment<G>,
        accuser_index: usize,
        accuser_pk: &MemberCommunicationPublicKey<G>,
        accused_broadcast: &BroadcastPhase1<G>,
    ) -> Result<(), DkgError> {
        let respective_shares = accused_broadcast.encrypted_shares[accuser_index - 1].clone();
        // First we verify the proof
        self.proof_accusation.verify(
            environment,
            accuser_pk,
            &respective_shares,
            accused_broadcast.committed_coefficients.clone(),
            accuser_index,
        )?;

        // Now we check equality does not hold.
        let randomness = <G::CorrespondingScalar as Scalar>::from_bytes(
            &self
                .proof_accusation
                .randomness_key
                .process(&respective_shares.encrypted_randomness.e2),
        )
        .ok_or(DkgError::ScalarOutOfBounds)?;
        let share = <G::CorrespondingScalar as Scalar>::from_bytes(
            &self
                .proof_accusation
                .share_key
                .process(&respective_shares.encrypted_share.e2),
        )
        .ok_or(DkgError::ScalarOutOfBounds)?;

        let index_pow = <G::CorrespondingScalar as Scalar>::from_u64(accuser_index as u64)
            .exp_iter()
            .take(environment.threshold + 1);

        let check_element = environment.commitment_key.h * randomness + G::generator() * share;
        let multi_scalar = G::vartime_multiscalar_multiplication(
            index_pow,
            accused_broadcast.committed_coefficients.clone(),
        );

        if check_element == multi_scalar {
            return Err(DkgError::FalseClaimedInequality);
        }

        Ok(())
    }
}

/// Struct that contains misbehaving parties detected in round 3. These consist of the misbehaving
/// member's index, and the two decrypted shares which are used to validate misbehaviour.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MisbehavingPartiesRound3<G: PrimeGroupElement> {
    pub(crate) accused_index: usize,
    pub(crate) decrypted_share: <G as PrimeGroupElement>::CorrespondingScalar,
    pub(crate) decrypted_randomness: <G as PrimeGroupElement>::CorrespondingScalar,
}

impl<G: PrimeGroupElement> MisbehavingPartiesRound3<G> {
    pub fn verify(
        &self,
        environment: &Environment<G>,
        accuser_index: usize,
        randomised_committed_coefficients: &Vec<G>,
        committed_coefficients: &Vec<G>,
    ) -> Result<(), DkgError> {
        let index_pow = <G::CorrespondingScalar as Scalar>::from_u64(accuser_index as u64)
            .exp_iter()
            .take(environment.threshold + 1);

        let failing_check = G::generator() * self.decrypted_share;
        let failing_multi_scalar =
            G::vartime_multiscalar_multiplication(index_pow, committed_coefficients.clone());

        let index_pow = <G::CorrespondingScalar as Scalar>::from_u64(accuser_index as u64)
            .exp_iter()
            .take(environment.threshold + 1);
        let passing_check = G::generator() * self.decrypted_share
            + environment.commitment_key.h * self.decrypted_randomness;
        let passing_multi_scalar = G::vartime_multiscalar_multiplication(
            index_pow,
            randomised_committed_coefficients.clone(),
        );

        // todo: invalid complaints should be interpreted as misbehaviour from qualified members?
        if passing_check != passing_multi_scalar {
            return Err(DkgError::FalseClaimedEquality);
        } else if failing_check == failing_multi_scalar {
            return Err(DkgError::FalseClaimedInequality);
        }
        Ok(())
    }
}

/// If some party proves valid complaints against other qualified members, all other parties
/// need to disclose the decrypted share of the accused party.
pub type MisbehavingPartiesRound4<G> = <G as PrimeGroupElement>::CorrespondingScalar;

/// Structure representing the broadcast messages of `Phase1`. The `committed_coefficients` are
/// randomised commitments of the parties VSS polynomials. `encrypted_shares` is a vector
/// of size `n` (where `n` is the number of parties), (todo: we want to check this as well somewhere)
/// where `encrypted_share[i]` represents the encrypted shares of party `i`.  
#[derive(Clone)]
pub struct BroadcastPhase1<G: PrimeGroupElement> {
    pub committed_coefficients: Vec<G>,
    pub encrypted_shares: Vec<EncryptedShares<G>>,
}

#[derive(Clone)]
pub struct BroadcastPhase2<G: PrimeGroupElement> {
    pub misbehaving_parties: Vec<MisbehavingPartiesRound1<G>>,
}

#[derive(Clone)]
pub struct BroadcastPhase3<G: PrimeGroupElement> {
    pub committed_coefficients: Vec<G>,
}

#[derive(Clone)]
pub struct BroadcastPhase4<G: PrimeGroupElement> {
    pub misbehaving_parties: Vec<MisbehavingPartiesRound3<G>>,
}

#[derive(Clone)]
pub struct BroadcastPhase5<G: PrimeGroupElement> {
    pub misbehaving_parties: Vec<Option<MisbehavingPartiesRound4<G>>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofOfMisbehaviour<G: PrimeGroupElement> {
    share_key: SymmetricKey<G>,
    randomness_key: SymmetricKey<G>,
    proof_decryption_1: CorrectHybridDecrKeyZkp<G>,
    proof_decryption_2: CorrectHybridDecrKeyZkp<G>,
}

impl<G: PrimeGroupElement> ProofOfMisbehaviour<G> {
    pub(crate) fn generate<R>(
        encrypted_shares: &EncryptedShares<G>,
        secret_key: &MemberCommunicationKey<G>,
        rng: &mut R,
    ) -> Self
    where
        R: CryptoRng + RngCore,
    {
        let symm_key_1 = secret_key
            .0
            .recover_symmetric_key(&encrypted_shares.encrypted_share);
        let symm_key_2 = secret_key
            .0
            .recover_symmetric_key(&encrypted_shares.encrypted_randomness);

        let proof_decryption_1 = CorrectHybridDecrKeyZkp::generate(
            &encrypted_shares.encrypted_share,
            &secret_key.to_public(),
            &symm_key_1,
            secret_key,
            rng,
        );
        let proof_decryption_2 = CorrectHybridDecrKeyZkp::generate(
            &encrypted_shares.encrypted_randomness,
            &secret_key.to_public(),
            &symm_key_2,
            secret_key,
            rng,
        );

        Self {
            share_key: symm_key_1,
            randomness_key: symm_key_2,
            proof_decryption_1,
            proof_decryption_2,
        }
    }

    pub fn verify(
        &self,
        environment: &Environment<G>,
        complaining_pk: &MemberCommunicationPublicKey<G>,
        encrypted_shares: &EncryptedShares<G>,
        committed_coeffs: Vec<G>,
        accuser_index: usize,
    ) -> Result<(), DkgError> {
        let proof1_is_err = self
            .proof_decryption_1
            .verify(
                &encrypted_shares.encrypted_share,
                &self.share_key,
                complaining_pk,
            )
            .is_err();

        let proof2_is_err = self
            .proof_decryption_2
            .verify(
                &encrypted_shares.encrypted_randomness,
                &self.randomness_key,
                complaining_pk,
            )
            .is_err();

        if proof1_is_err || proof2_is_err {
            return Err(DkgError::InvalidProofOfMisbehaviour);
        }

        let plaintext_1 = <G::CorrespondingScalar as Scalar>::from_bytes(
            &self.share_key.process(&encrypted_shares.encrypted_share.e2),
        )
        .ok_or(DkgError::DecodingToScalarFailed)?;

        let plaintext_2 = <G::CorrespondingScalar as Scalar>::from_bytes(
            &self
                .randomness_key
                .process(&encrypted_shares.encrypted_randomness.e2),
        )
        .ok_or(DkgError::DecodingToScalarFailed)?;

        let index_pow = <G::CorrespondingScalar as Scalar>::from_u64(accuser_index as u64)
            .exp_iter()
            .take(environment.threshold + 1);

        let check_element =
            environment.commitment_key.h * plaintext_1 + G::generator() * plaintext_2;
        let multi_scalar = G::vartime_multiscalar_multiplication(index_pow, committed_coeffs);

        if check_element != multi_scalar {
            return Ok(());
        }

        Err(DkgError::InvalidProofOfMisbehaviour)
    }
}
