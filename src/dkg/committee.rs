//! Implementation of the distributed key generation (DKG)
//! procedure presented by Gennaro, Jarecki, Krawczyk and Rabin in
//! ["Secure distributed key generation for discrete-log based cryptosystems."](https://link.springer.com/article/10.1007/s00145-006-0347-3).
//! The distinction with the original protocol lies in the use of hybrid
//! encryption. We use the description and notation presented in the technical
//! [spec](https://github.com/input-output-hk/treasury-crypto/blob/master/docs/voting_protocol_spec/Treasury_voting_protocol_spec.pdf),
//! written by Dmytro Kaidalov.

use super::broadcast::{BroadcastPhase1, BroadcastPhase2};
pub use super::broadcast::{IndexedDecryptedShares, IndexedEncryptedShares};
use super::procedure_keys::{
    MemberCommunicationKey, MemberCommunicationPublicKey, MemberPublicShare, MemberSecretShare,
};
use crate::cryptography::commitment::CommitmentKey;
use crate::dkg::broadcast::{MisbehavingPartiesState1, ProofOfMisbehaviour};
use crate::errors::DkgError;
use crate::polynomial::Polynomial;
use crate::traits::{PrimeGroupElement, Scalar};
use rand_core::{CryptoRng, RngCore};
use std::marker::PhantomData;

/// Environment parameters of the distributed key generation procedure.
#[derive(Clone)]
pub struct Environment<G: PrimeGroupElement> {
    threshold: usize,
    nr_members: usize,
    commitment_key: CommitmentKey<G>,
}

/// Private state, generated over the protocol
#[derive(Clone)]
pub struct IndividualState<G: PrimeGroupElement> {
    index: usize,
    environment: Environment<G>,
    communication_sk: MemberCommunicationKey<G>,
    final_share: Option<MemberSecretShare<G>>,
    public_share: Option<MemberPublicShare<G>>,
    indexed_received_shares: Option<Vec<IndexedDecryptedShares<G>>>,
    indexed_committed_shares: Option<Vec<(usize, Vec<G>)>>,
}

/// Definition of a phase
pub struct Phase<G: PrimeGroupElement, Phase> {
    pub state: Box<IndividualState<G>>,
    pub phase: PhantomData<Phase>,
}

impl<G: PrimeGroupElement> Environment<G> {
    pub fn init(threshold: usize, nr_members: usize, commitment_key: CommitmentKey<G>) -> Self {
        assert!(threshold <= nr_members);
        assert!(threshold > nr_members / 2);

        Self {
            threshold,
            nr_members,
            commitment_key,
        }
    }
}

pub struct Initialise {}
pub struct Round1 {}
pub struct Round2 {}
pub struct Round3 {}
pub struct Round4 {}

pub type DistributedKeyGeneration<G> = Phase<G, Initialise>;
impl<G: PrimeGroupElement> Phase<G, Initialise> {
    /// Generate a new member state from random. This is round 1 of the protocol. Receives as
    /// input the threshold `t`, the expected number of participants, `n`, common reference string
    /// `crs`, `committee_pks`, and the party's index `my`. Initiates a Pedersen-VSS as a dealer,
    /// and returns the committed coefficients of its polynomials, together with encryption of the
    /// shares of the other different members.
    pub fn init<R: RngCore + CryptoRng>(
        rng: &mut R,
        environment: &Environment<G>,
        secret_key: &MemberCommunicationKey<G>,
        committee_pks: &[MemberCommunicationPublicKey<G>],
        my: usize,
    ) -> (Phase<G, Round1>, BroadcastPhase1<G>) {
        assert_eq!(committee_pks.len(), environment.nr_members);
        assert!(my <= environment.nr_members);

        let pcomm = Polynomial::<G::CorrespondingScalar>::random(rng, environment.threshold);
        let pshek = Polynomial::<G::CorrespondingScalar>::random(rng, environment.threshold);

        let mut apubs = Vec::with_capacity(environment.threshold + 1);
        let mut coeff_comms = Vec::with_capacity(environment.threshold + 1);

        for (ai, &bi) in pshek.get_coefficients().zip(pcomm.get_coefficients()) {
            let apub = G::generator() * ai;
            let coeff_comm = (environment.commitment_key.h * bi) + apub;
            apubs.push(apub);
            coeff_comms.push(coeff_comm);
        }

        let mut encrypted_shares: Vec<IndexedEncryptedShares<G>> =
            Vec::with_capacity(environment.nr_members - 1);
        #[allow(clippy::needless_range_loop)]
        for i in 0..environment.nr_members {
            // don't generate share for self
            if i == my - 1 {
                continue;
            } else {
                let idx = <G::CorrespondingScalar as Scalar>::from_u64((i + 1) as u64);
                let share_comm = pcomm.evaluate(&idx);
                let share_shek = pshek.evaluate(&idx);

                let pk = &committee_pks[i];

                let ecomm = pk.hybrid_encrypt(&share_comm.to_bytes(), rng);
                let eshek = pk.hybrid_encrypt(&share_shek.to_bytes(), rng);

                encrypted_shares.push((i + 1, ecomm, eshek));
            }
        }

        let state = IndividualState {
            index: my,
            environment: environment.clone(),
            communication_sk: secret_key.clone(),
            final_share: None,
            public_share: None,
            indexed_received_shares: None,
            indexed_committed_shares: None,
        };

        (
            Phase::<G, Round1> {
                state: Box::new(state),
                phase: PhantomData,
            },
            BroadcastPhase1 {
                committed_coefficients: coeff_comms,
                encrypted_shares,
            },
        )
    }
}

impl<G: PrimeGroupElement> Phase<G, Round1> {
    /// Function to proceed to phase 2. It checks and keeps track of misbehaving parties. If this
    /// step does not validate, the member is not allowed to proceed to phase 3.
    pub fn to_phase_2<R>(
        &self,
        environment: &Environment<G>,
        members_state: &[MembersFetchedState1<G>],
        rng: &mut R,
    ) -> (
        Result<Phase<G, Round2>, DkgError>,
        Option<BroadcastPhase2<G>>,
    )
    where
        R: CryptoRng + RngCore,
    {
        let mut misbehaving_parties: Vec<MisbehavingPartiesState1<G>> = Vec::new();
        let mut decrypted_shares: Vec<IndexedDecryptedShares<G>> =
            Vec::with_capacity(members_state.len());
        for fetched_data in members_state {
            if fetched_data.get_index() != self.state.index {
                return (Err(DkgError::FetchedInvalidData), None);
            }

            if let (Some(comm), Some(shek)) = self
                .state
                .communication_sk
                .decrypt_shares(fetched_data.indexed_shares.clone())
            {
                let index_pow =
                    <G::CorrespondingScalar as Scalar>::from_u64(self.state.index as u64)
                        .exp_iter()
                        .take(environment.threshold + 1);

                let check_element = environment.commitment_key.h * comm + G::generator() * shek;
                let multi_scalar = G::vartime_multiscalar_multiplication(
                    index_pow,
                    fetched_data.committed_coeffs.clone(),
                );

                if check_element != multi_scalar {
                    let proof = ProofOfMisbehaviour::generate(
                        &fetched_data.indexed_shares,
                        &self.state.communication_sk,
                        rng,
                    );
                    // todo: should we instead store the sender's index?
                    misbehaving_parties.push((
                        fetched_data.sender_index,
                        DkgError::ShareValidityFailed,
                        proof,
                    ));

                    decrypted_shares.push((
                        fetched_data.sender_index,
                        comm,
                        shek,
                        fetched_data.committed_coeffs.clone(),
                    ));
                }
            } else {
                // todo: handle the proofs. Might not be the most optimal way of handling these two
                let proof = ProofOfMisbehaviour::generate(
                    &fetched_data.indexed_shares,
                    &self.state.communication_sk,
                    rng,
                );
                misbehaving_parties.push((
                    fetched_data.sender_index,
                    DkgError::ScalarOutOfBounds,
                    proof,
                ));
            }
        }

        if misbehaving_parties.len() >= environment.threshold {
            return (
                Err(DkgError::MisbehaviourHigherThreshold),
                Some(BroadcastPhase2 {
                    misbehaving_parties,
                }),
            );
        }

        let updated_state = IndividualState {
            index: self.state.index,
            environment: self.state.environment.clone(),
            communication_sk: self.state.communication_sk.clone(),
            final_share: None,
            public_share: None,
            indexed_received_shares: Some(decrypted_shares),
            indexed_committed_shares: None,
        };

        let broadcast_message = if misbehaving_parties.is_empty() {
            None
        } else {
            Some(BroadcastPhase2 {
                misbehaving_parties,
            })
        };

        (
            Ok(Phase::<G, Round2> {
                state: Box::new(updated_state),
                phase: PhantomData,
            }),
            broadcast_message,
        )
    }
}

/// State of the members after round 1. This structure contains the indexed encrypted
/// shares of every other participant, `indexed_shares`, and the committed coefficients
/// of the generated polynomials, `committed_coeffs`.
#[derive(Clone)]
pub struct MembersFetchedState1<G: PrimeGroupElement> {
    pub(crate) sender_index: usize,
    pub(crate) indexed_shares: IndexedEncryptedShares<G>,
    pub(crate) committed_coeffs: Vec<G>,
}

impl<G: PrimeGroupElement> MembersFetchedState1<G> {
    fn get_index(&self) -> usize {
        self.indexed_shares.0
    }

    // pub fn from_member_state(member_state: &BroadcastPhase1<G>) -> Self {
    //     Self {
    //         indexed_shares: member_state.clone().encrypted_shares[0],
    //         committed_coeffs: member_state.committed_coefficients,
    //     }
    // }
}

#[cfg(test)]
mod tests {
    use super::*;

    use curve25519_dalek::ristretto::RistrettoPoint;
    use rand_core::OsRng;

    #[test]
    fn valid_phase_2() {
        let mut rng = OsRng;

        let mut shared_string = b"Example of a shared string.".to_owned();
        let h = CommitmentKey::<RistrettoPoint>::generate(&mut shared_string);
        let threshold = 2;
        let nr_members = 2;
        let environment = Environment::init(threshold, nr_members, h);

        let mc1 = MemberCommunicationKey::<RistrettoPoint>::new(&mut rng);
        let mc2 = MemberCommunicationKey::<RistrettoPoint>::new(&mut rng);
        let mc = [mc1.to_public(), mc2.to_public()];

        let (m1, _broadcast1) =
            DistributedKeyGeneration::<RistrettoPoint>::init(&mut rng, &environment, &mc1, &mc, 1);
        let (_m2, broadcast2) =
            DistributedKeyGeneration::<RistrettoPoint>::init(&mut rng, &environment, &mc2, &mc, 2);

        // Now, party one fetches the state of the other parties, mainly party two and three
        let fetched_state = vec![MembersFetchedState1 {
            sender_index: 2,
            indexed_shares: broadcast2.encrypted_shares[0].clone(),
            committed_coeffs: broadcast2.committed_coefficients.clone(),
        }];

        let phase_2 = m1.to_phase_2(&environment, &fetched_state, &mut rng);
        if let Some(_data) = phase_2.1 {
            // broadcast the `data`
        }

        phase_2.0.unwrap();
        // assert!(phase_2.0.is_ok());
    }

    #[test]
    fn invalid_phase_2() {
        let mut rng = OsRng;

        let mut shared_string = b"Example of a shared string.".to_owned();
        let h = CommitmentKey::<RistrettoPoint>::generate(&mut shared_string);
        let threshold = 2;
        let nr_members = 3;
        let environment = Environment::init(threshold, nr_members, h);

        let mc1 = MemberCommunicationKey::<RistrettoPoint>::new(&mut rng);
        let mc2 = MemberCommunicationKey::<RistrettoPoint>::new(&mut rng);
        let mc3 = MemberCommunicationKey::<RistrettoPoint>::new(&mut rng);
        let mc = [mc1.to_public(), mc2.to_public(), mc3.to_public()];

        let (m1, _broad_1) =
            DistributedKeyGeneration::<RistrettoPoint>::init(&mut rng, &environment, &mc1, &mc, 1);
        let (_m2, broad_2) =
            DistributedKeyGeneration::<RistrettoPoint>::init(&mut rng, &environment, &mc2, &mc, 2);
        let (_m3, broad_3) =
            DistributedKeyGeneration::<RistrettoPoint>::init(&mut rng, &environment, &mc3, &mc, 3);

        // Now, party one fetches invalid state of the other parties, mainly party two and three
        let fetched_state = vec![
            MembersFetchedState1 {
                sender_index: 2,
                indexed_shares: broad_2.encrypted_shares[0].clone(),
                committed_coeffs: vec![PrimeGroupElement::zero(); 3],
            },
            MembersFetchedState1 {
                sender_index: 3,
                indexed_shares: broad_3.encrypted_shares[0].clone(),
                committed_coeffs: vec![PrimeGroupElement::zero(); 3],
            },
        ];

        // Given that there is a number of misbehaving parties higher than the threshold, proceeding
        // to step 2 should fail.
        let phase_2_faked = m1.to_phase_2(&environment, &fetched_state, &mut rng);
        assert!(phase_2_faked.0.is_err());

        // And there should be data to broadcast
        assert!(phase_2_faked.1.is_some())
    }

    #[test]
    fn misbehaving_parties() {
        let mut rng = OsRng;

        let mut shared_string = b"Example of a shared string.".to_owned();
        let h = CommitmentKey::<RistrettoPoint>::generate(&mut shared_string);

        let threshold = 2;
        let nr_members = 3;
        let environment = Environment::init(threshold, nr_members, h);

        let mc1 = MemberCommunicationKey::<RistrettoPoint>::new(&mut rng);
        let mc2 = MemberCommunicationKey::<RistrettoPoint>::new(&mut rng);
        let mc3 = MemberCommunicationKey::<RistrettoPoint>::new(&mut rng);
        let mc = [mc1.to_public(), mc2.to_public(), mc3.to_public()];

        let (m1, _broad_1) =
            DistributedKeyGeneration::<RistrettoPoint>::init(&mut rng, &environment, &mc1, &mc, 1);
        let (_m2, broad_2) =
            DistributedKeyGeneration::<RistrettoPoint>::init(&mut rng, &environment, &mc2, &mc, 2);
        let (_m3, broad_3) =
            DistributedKeyGeneration::<RistrettoPoint>::init(&mut rng, &environment, &mc3, &mc, 3);

        // Now, party one fetches invalid state of a single party, mainly party two
        let fetched_state = vec![
            MembersFetchedState1 {
                sender_index: 2,
                indexed_shares: broad_2.encrypted_shares[0].clone(),
                committed_coeffs: broad_2.committed_coefficients.clone(),
            },
            MembersFetchedState1 {
                sender_index: 3,
                indexed_shares: broad_3.encrypted_shares[0].clone(),
                committed_coeffs: vec![PrimeGroupElement::zero(); 3],
            },
        ];

        // Given that party 3 submitted encrypted shares which do not correspond to the
        // committed_coeffs, but party 2 submitted valid shares, phase 2 should be successful for
        // party 1, and there should be logs of misbehaviour of party 3

        let (phase_2, broadcast_data) = m1.to_phase_2(&environment, &fetched_state, &mut rng);

        assert!(phase_2.is_ok());
        assert!(broadcast_data.is_some());

        let bd = broadcast_data.unwrap();

        // Party 2 should be good
        assert_eq!(bd.misbehaving_parties.len(), 1);

        // Party 3 should fail
        assert_eq!(bd.misbehaving_parties[0].0, 3);
        assert_eq!(bd.misbehaving_parties[0].1, DkgError::ShareValidityFailed);
        // and the complaint should be valid
        assert!(bd.misbehaving_parties[0]
            .2
            .verify(&mc1.to_public(), &fetched_state[1], &h, 2, 2)
            .is_err());
    }
}
