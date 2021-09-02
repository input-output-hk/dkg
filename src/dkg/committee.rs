#![allow(clippy::type_complexity)]

use super::broadcast::{BroadcastPhase1, BroadcastPhase2};
pub use super::broadcast::{IndexedDecryptedShares, IndexedEncryptedShares};
use super::procedure_keys::{
    MemberCommunicationKey, MemberCommunicationPublicKey, MemberPublicShare, MemberSecretShare,
};
use crate::cryptography::commitment::CommitmentKey;
use crate::cryptography::elgamal::PublicKey;
use crate::dkg::broadcast::{
    BroadcastPhase3, BroadcastPhase4, BroadcastPhase5, MisbehavingPartiesState1,
    MisbehavingPartiesState3, MisbehavingPartiesState4, ProofOfMisbehaviour,
};
use crate::dkg::procedure_keys::MasterPublicKey;
use crate::errors::DkgError;
use crate::polynomial::{lagrange_interpolation, Polynomial};
use crate::traits::{PrimeGroupElement, Scalar};
use rand_core::{CryptoRng, RngCore};
use std::fmt::{Debug, Formatter};
use std::marker::PhantomData;

/// Environment parameters of the distributed key generation procedure.
#[derive(Clone, Debug, PartialEq)]
pub struct Environment<G: PrimeGroupElement> {
    threshold: usize,
    nr_members: usize,
    commitment_key: CommitmentKey<G>,
}

/// Private state, generated over the protocol
#[derive(Clone, Debug, PartialEq)]
pub struct IndividualState<G: PrimeGroupElement> {
    index: usize,
    environment: Environment<G>,
    communication_sk: MemberCommunicationKey<G>,
    final_share: Option<MemberSecretShare<G>>,
    public_share: Option<MemberPublicShare<G>>,
    master_public_key: Option<MemberPublicShare<G>>,
    indexed_received_shares: Option<Vec<Option<IndexedDecryptedShares<G>>>>,
    indexed_committed_shares: Vec<Option<Vec<G>>>,
    /// Set of parties whose secret needs to be reconstructed
    reconstructable_set: Vec<usize>,
    qualified_set: Vec<usize>,
}

/// Definition of a phase
pub struct Phases<G: PrimeGroupElement, Phase> {
    pub state: Box<IndividualState<G>>,
    pub phase: PhantomData<Phase>,
}

impl<G: PrimeGroupElement, P> Debug for Phases<G, P> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Phase").field("state", &self.state).finish()
    }
}

impl<G: PrimeGroupElement, P> PartialEq for Phases<G, P> {
    fn eq(&self, other: &Self) -> bool {
        self.state == other.state
    }
}

impl<G: PrimeGroupElement> Environment<G> {
    /// Initialise the Distributed Key Generation environment. As input is given the `threshold`,
    /// `nr_members` and the bytes used to generated the commitment key, `ck_gen_bytes`.
    ///
    /// # Panics
    ///
    /// Panics if `threshold` is greater to `nr_members` or smaller than `nr_members / 2`.
    pub fn init(threshold: usize, nr_members: usize, ck_gen_bytes: &[u8]) -> Self {
        assert!(threshold <= nr_members);
        assert!(threshold > nr_members / 2);

        let commitment_key = CommitmentKey::generate(ck_gen_bytes);

        Self {
            threshold,
            nr_members,
            commitment_key,
        }
    }
}

pub type DistributedKeyGeneration<G> = Phases<G, Initialise>;

#[doc(hidden)]
pub struct Initialise {}
#[doc(hidden)]
pub struct Phase1 {}
#[doc(hidden)]
pub struct Phase2 {}
#[doc(hidden)]
pub struct Phase3 {}
#[doc(hidden)]
pub struct Phase4 {}
#[doc(hidden)]
pub struct Phase5 {}

impl<G: PrimeGroupElement> Phases<G, Initialise> {
    /// Generate a new member state from random. This is round 1 of the protocol. Receives as
    /// input the `environment`, the initializer's private communication key, `secret_key`,
    /// the participants public keys, `committee_pks`, and the initializer's index `my`.
    /// Initiates a Pedersen-VSS as a dealer and returns the committed coefficients of its
    /// polynomials, together with encryption of the shares of the other different members.
    ///
    /// In particular, the dealer, with `my = i`, generates two polynomials,
    ///
    /// \\( f_i(x) = \sum_{l = 0}^t a_{i, l} x^l \\) and \\( f_i'(x) = \sum_{l = 0}^t b_{i, l} x^l .\\)
    ///
    /// Then, it posts a commitment all of the polynomial coefficients. Specifically, it publishes
    /// $E_{i,l} = g^{a_{i,l}}h^{b_{i,l}}$ for $l\in\lbrace0,\ldots, t\rbrace$. It then sends the shares of
    /// its secret ($a_{i,0}$) to the other participants. To send a share to party $j$, it
    /// evaluates both polynomials at those points, encrypts them under the recipient's public
    /// key, and broadcasts the message. In particular, it first computes $s_{i,j} = f_i(j)$ and
    /// $s_{i,j}' = f_i'(j)$, then encrypts them, $e_{i,j} = \texttt{Enc}(s_{i,j}, pk_j)$ and
    /// $e_{i,j}' = \texttt{Enc}(s_{i,j}', pk_j)$, and broadcasts the values.
    ///
    /// # Panics
    ///
    /// This function panics if the number of participants public keys is not the same as
    /// `nr_members` in the `environment`. It also fails if `my` is higher than `nr_members`.
    /// todo: this function could define the ordering of the public keys.
    pub fn init<R: RngCore + CryptoRng>(
        rng: &mut R,
        environment: &Environment<G>,
        secret_key: &MemberCommunicationKey<G>,
        committee_pks: &[MemberCommunicationPublicKey<G>],
        my: usize,
    ) -> (Phases<G, Phase1>, BroadcastPhase1<G>) {
        assert_eq!(committee_pks.len(), environment.nr_members);
        assert!(my <= environment.nr_members);

        // We initialise the vector of committed shares, to which we include the share of the party
        // initialising
        let mut committed_shares = vec![None; environment.nr_members];

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

        let qualified_set = vec![1; environment.nr_members];
        let reconstructable_set = vec![0; environment.nr_members];
        committed_shares[my - 1] = Some(apubs);

        let state = IndividualState {
            index: my,
            environment: environment.clone(),
            communication_sk: secret_key.clone(),
            final_share: None,
            public_share: None,
            master_public_key: None,
            indexed_received_shares: None,
            indexed_committed_shares: committed_shares,
            reconstructable_set,
            qualified_set,
        };

        (
            Phases::<G, Phase1> {
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

impl<G: PrimeGroupElement> Phases<G, Phase1> {
    /// Function to proceed to phase 2. It takes as input the `environment`, and the fetched data
    /// from phase 1, `members_state`, directed at the fetching party. It checks that the received
    /// shares correspond with the
    /// commitment of the corresponding polynomial. In particular, party $i$ fetches all committed
    /// polynomials $E_{j,l}$, and its
    /// corresponding encrypted shares $e_{j, i}, e_{i,j}'$, for $j\in\lbrace1,\ldots,n\rbrace$ and
    /// $l\in\lbrace0,\ldots,t\rbrace$. It decrypts the shares, and verifies their correctness by evaluating
    /// the polynomial in the exponent. In particular, it checks the following:
    /// \\( g^{s_{j,i}}h^{s_{j,i}'} = \prod_{l=0}^t E_{j,l}^{i^l}. \\)
    ///
    /// If any of these check fails it broadcasts a proof of misbehaviour, and removes the
    /// misbehaving party from the qualified set. If no misbehaviour happens, no data is broadcast.
    ///
    /// # Errors
    ///
    /// If this function is given as input a `MembersFetchedState1` which was not directed to
    /// `self.state.index`, and error will be returned. Similarly, if decryption of any of
    /// the shares fails, an error is returned. Finally, if there are more misbehaving parties
    /// than the number allowed by the threshold, the phase transition fails.
    pub fn proceed<R>(
        mut self,
        environment: &Environment<G>,
        members_state: &[MembersFetchedState1<G>],
        rng: &mut R,
    ) -> (
        Result<Phases<G, Phase2>, DkgError>,
        Option<BroadcastPhase2<G>>,
    )
    where
        R: CryptoRng + RngCore,
    {
        let mut qualified_set = self.state.qualified_set.clone();
        let mut misbehaving_parties: Vec<MisbehavingPartiesState1<G>> = Vec::new();
        let mut decrypted_shares: Vec<Option<IndexedDecryptedShares<G>>> =
            vec![None; self.state.environment.nr_members];
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

                decrypted_shares[fetched_data.sender_index - 1] =
                    Some((comm, shek, fetched_data.committed_coeffs.clone()));

                if check_element != multi_scalar {
                    let proof = ProofOfMisbehaviour::generate(
                        &fetched_data.indexed_shares,
                        &self.state.communication_sk,
                        rng,
                    );
                    qualified_set[fetched_data.sender_index - 1] = 0;
                    misbehaving_parties.push((
                        fetched_data.sender_index,
                        DkgError::ShareValidityFailed,
                        proof,
                    ));
                }
            } else {
                // todo: handle the proofs. Might not be the most optimal way of handling these two
                let proof = ProofOfMisbehaviour::generate(
                    &fetched_data.indexed_shares,
                    &self.state.communication_sk,
                    rng,
                );
                qualified_set[fetched_data.sender_index - 1] = 0;
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

        self.state.indexed_received_shares = Some(decrypted_shares);
        self.state.qualified_set = qualified_set;

        let broadcast_message = if misbehaving_parties.is_empty() {
            None
        } else {
            Some(BroadcastPhase2 {
                misbehaving_parties,
            })
        };

        (
            Ok(Phases::<G, Phase2> {
                state: self.state,
                phase: PhantomData,
            }),
            broadcast_message,
        )
    }
}

impl<G: PrimeGroupElement> Phases<G, Phase2> {
    fn compute_qualified_set(&mut self, broadcast_complaints: &[BroadcastPhase2<G>]) {
        for broadcast in broadcast_complaints {
            for misbehaving_parties in &broadcast.misbehaving_parties {
                self.state.qualified_set[misbehaving_parties.0 - 1] &= 0;
            }
        }
    }

    /// This function takes as input the broadcast complaints from the previous phase,
    /// `broadcast_complaints`, and updates the qualified set. A single valid complaint
    /// disqualifies a member. Then it publishes a commitment to the polynomial coefficients
    /// $a_{i,l}$ without any randomness. In particular, each member $i$ broadcasts
    /// $A_{i,l} = g^{a_{i,l}}$ for $l\in\lbrace 0,\ldots,l}$.
    ///
    /// Errors
    ///
    /// If there is less qualified members than the threshold, the function fails and does not
    /// proceed to the following phase.
    /// todo: we can probably compute here the final shares
    pub fn proceed(
        mut self,
        broadcast_complaints: &[BroadcastPhase2<G>],
    ) -> (
        Result<Phases<G, Phase3>, DkgError>,
        Option<BroadcastPhase3<G>>,
    ) {
        self.compute_qualified_set(broadcast_complaints);
        if self.state.qualified_set.len() < self.state.environment.threshold {
            return (Err(DkgError::MisbehaviourHigherThreshold), None);
        }

        let broadcast = Some(BroadcastPhase3 {
            committed_coefficients: self.state.indexed_committed_shares[self.state.index - 1].clone().expect("owns committed coefficient is always existent"),
        });

        (
            Ok(Phases::<G, Phase3> {
                state: self.state,
                phase: PhantomData,
            }),
            broadcast,
        )
    }
}

impl<G: PrimeGroupElement> Phases<G, Phase3> {
    /// Each participant fetches the commitment of the polynomials of the previous round, and
    /// verifies that it corresponds with the polynomial committed initially. In particular player
    /// $i$ checks that
    /// \\(g^{s_{j,i}} = \prod_{l = 0}^tA_{j,l}^{i^l} \\). If the check fails it publishes a proof
    /// of misbehaviour.
    ///
    /// Errors
    ///
    /// This function fails if the number of qualified members minus the misbehaving parties of
    /// this round is smaller than the threshold.
    pub fn proceed(
        mut self,
        fetched_state_3: &[MembersFetchedState3<G>],
    ) -> (
        Result<Phases<G, Phase4>, DkgError>,
        Option<BroadcastPhase4<G>>,
    ) {
        let mut honest = vec![0usize; self.state.environment.nr_members];
        honest[self.state.index - 1] |= 1; /* self is considered honest */
        let received_shares = self
            .state
            .indexed_received_shares
            .clone()
            .expect("We shouldn't be here if we have not received shares");
        let mut misbehaving_parties: Vec<MisbehavingPartiesState3<G>> = Vec::new();

        for fetched_commitments in fetched_state_3 {
            // if the fetched commitment is from a disqualified player, we skip
            if self.state.qualified_set[fetched_commitments.sender_index - 1] != 0 {
                // We store the indexed committed coefficients
                self.state.indexed_committed_shares[fetched_commitments.sender_index - 1] = Some(fetched_commitments.committed_coefficients.clone());

                let index_pow =
                    <G::CorrespondingScalar as Scalar>::from_u64(self.state.index as u64)
                        .exp_iter()
                        .take(self.state.environment.threshold + 1);

                let indexed_shares = received_shares[fetched_commitments.sender_index - 1]
                    .clone()
                    .expect("If it is part of honest members, their shares should be recorded");

                let check_element = G::generator() * indexed_shares.1;
                let multi_scalar = G::vartime_multiscalar_multiplication(
                    index_pow,
                    fetched_commitments.committed_coefficients.clone(),
                );

                if check_element != multi_scalar {
                    misbehaving_parties.push((
                        fetched_commitments.sender_index,
                        indexed_shares.0,
                        indexed_shares.1,
                    ));
                    continue;
                }

                honest[fetched_commitments.sender_index - 1] |= 1;
            }
        }

        let broadcast = if misbehaving_parties.is_empty() {
            None
        } else {
            Some(BroadcastPhase4 {
                misbehaving_parties,
            })
        };

        if honest.iter().sum::<usize>() < self.state.environment.threshold {
            return (Err(DkgError::MisbehaviourHigherThreshold), broadcast);
        }

        // todo: set the reconstructable set

        (
            Ok(Phases::<G, Phase4> {
                state: self.state,
                phase: PhantomData,
            }),
            broadcast,
        )
    }
}

impl<G: PrimeGroupElement> Phases<G, Phase4> {
    /// This functions takes as input the broadcast complaints of the previous phase. The
    /// misbehaving parties are still part of the qualified set, and the master public key will
    /// use their shares. However, they no longer participate in the protocol, and instead the
    /// remaining parties reconstruct the shares. To do so, this function keeps track, in
    /// `self.state.reconstructable_set` of all parties whose secret needs to be reconstructed.
    /// This function broadcasts the shares of the parties that misbehaved in the previous phase,
    /// and whose secret needs to be reconstructed.
    ///
    /// # Errors
    ///
    /// This function fails if the broadcast complaints accuse more parties than that allowed by
    /// the threshold.
    pub fn proceed(
        mut self,
        broadcast_complaints: Option<&[BroadcastPhase4<G>]>,
    ) -> (
        Result<Phases<G, Phase5>, DkgError>,
        Option<BroadcastPhase5<G>>,
    ) {
        // todo: handle reconstrubtable set as `to_phse_4`
        // misbehaving parties will have their shares disclosed to generate the master public key
        let mut reconstruct_shares: Vec<Option<MisbehavingPartiesState4<G>>> =
            vec![None; self.state.environment.nr_members];
        let received_shares = self
            .state
            .indexed_received_shares
            .clone()
            .expect("We shouldn't be here if we have not received shares");


        if let Some(complaints) = broadcast_complaints {
            for fetched_complaints in complaints {
                for state in &fetched_complaints.misbehaving_parties {
                    // If party is disqualified, we ignore it
                    if self.state.qualified_set[state.0 - 1] != 0 {
                        let indexed_shares = received_shares[state.0 - 1]
                            .as_ref()
                            .expect("If it is part of honest members, their shares should be recorded");
                        reconstruct_shares[state.0] = Some(indexed_shares.1);
                        self.state.reconstructable_set[state.0 - 1] |= 1;
                    }
                }
            }
        }

        let total_honest = self.state.qualified_set.iter().sum::<usize>()
            - self.state.reconstructable_set.iter().sum::<usize>();
        if total_honest < self.state.environment.threshold {
            return (Err(DkgError::MisbehaviourHigherThreshold), None);
        }

        (
            Ok(Phases::<G, Phase5> {
                state: self.state,
                phase: PhantomData,
            }),
            Some(BroadcastPhase5 {
                misbehaving_parties: reconstruct_shares,
            }),
        )
    }
}

impl<G: PrimeGroupElement> Phases<G, Phase5> {
    /// This phase transition finalises the DKG protocol. It takes as input the broadcast complaints
    /// from the previous phase, and returns the master public key using the key shares of the
    /// honest parties, and reconstructing the shares of the misbehaving parties. This last point
    /// is the main essence of this function, as we need to perform the lagrange interpolation for
    /// the members that are part of the `qualified_set` but that have misbehaved in Phase 3. The
    /// shares shared in Phase 4 are used to reconstruct such shares. During reconstruction, we need
    /// at least `t` points for every secret to reconstruct, and therefore require the participation
    /// in Phase 4 of at least `t` honest parties.
    ///
    /// The function first defines the `final_parties`, which are those in the `qualified_set`
    /// which are not in the `reconstructable_set`. Let `p(0)` be the polynomial value that we
    /// want to interpolate. The points over which the polynomial is
    /// evaluated are those where there is a `1` in `final_parties`, and the `p(i)`s need to be
    /// recovered from the `broadcast_complaints` from the previous section, and the
    /// `indexed_received_shares` stores in the `state`.
    ///
    /// # Errors
    ///
    /// If `final_parties` is smaller than the threshold, it returns an error.
    pub fn finalise(
        self,
        broadcast_complaints: Option<&[MembersFetchedState5<G>]>,
    ) -> Result<MasterPublicKey<G>, DkgError> {
        let mut master_key = G::zero();
        // set of qualified without counting the misbehaving of the last round. We need this to
        // compute the lagrange interpolation of the misbehaving parties.
        let final_parties: Vec<usize> = self
            .state
            .qualified_set
            .iter()
            .zip(self.state.reconstructable_set.iter())
            .map(|(i, j)| i ^ j)
            .collect();

        let committed_shares = self
            .state
            .indexed_committed_shares;

        let received_shares = self
            .state
            .indexed_received_shares
            .expect("This should exist if we are at this stage");

        for i in 0..self.state.environment.nr_members {
            if self.state.reconstructable_set[i] == 1 && self.state.qualified_set[i] != 1 {
                panic!("Only qualified members should be reconstructed");
            } else if self.state.reconstructable_set[i] == 1 {
                // Then we need to reconstruct, using the data from the broadcast_complaints
                // For that we perform the lagrange interpolation
                let mut indices: Vec<G::CorrespondingScalar> = Vec::new();
                let mut evaluated_points: Vec<G::CorrespondingScalar> = Vec::new();

                // We first include the parties index and share
                indices.push(G::CorrespondingScalar::from_u64(self.state.index as u64));
                evaluated_points.push(
                    received_shares[i]
                        .as_ref()
                        .expect("There should be a share for a qualified member")
                        .1,
                );

                if let Some(complaint) = broadcast_complaints {
                    for disclosed_shares in complaint {
                        // if it is not within the final parties, we ignore it
                        if final_parties[disclosed_shares.sender_index] == 1 {
                            if let Some(share) =
                            disclosed_shares.disclosed_shares.misbehaving_parties[i]
                            {
                                indices.push(G::CorrespondingScalar::from_u64(
                                    disclosed_shares.sender_index as u64,
                                ));
                                evaluated_points.push(share);
                            }
                        }
                    }
                }

                // Now we check if we have sufficient shares to reconstruct the secret. Note that
                // the size of `indices` and that of `evaluated_points` is the same.
                if indices.len() < self.state.environment.threshold {
                    return Err(DkgError::InsufficientSharesForRecovery(i));
                }

                // If we have sufficient, then we interpolate at zero
                let recovered_secret = lagrange_interpolation(
                    G::CorrespondingScalar::zero(),
                    &evaluated_points,
                    &indices,
                );
                master_key = master_key + G::generator() * recovered_secret;
            } else {
                master_key = master_key
                    + committed_shares[i]
                        .as_ref()
                        .expect("If it is part of honest members, their shares should be recorded")
                        [0];
            }
        }

        Ok(MasterPublicKey(PublicKey { pk: master_key }))
    }
}

/// State of the members after round 1. This structure contains the indexed encrypted
/// shares of every other participant, `indexed_shares`, and the committed coefficients
/// of the generated polynomials, `committed_coeffs`.
#[derive(Clone)]
pub struct MembersFetchedState1<G: PrimeGroupElement> {
    pub sender_index: usize,
    pub indexed_shares: IndexedEncryptedShares<G>,
    pub committed_coeffs: Vec<G>,
}

impl<G: PrimeGroupElement> MembersFetchedState1<G> {
    fn get_index(&self) -> usize {
        self.indexed_shares.0
    }
}

#[derive(Clone)]
pub struct MembersFetchedState3<G: PrimeGroupElement> {
    pub sender_index: usize,
    pub committed_coefficients: Vec<G>,
}

#[derive(Clone)]
pub struct MembersFetchedState5<G: PrimeGroupElement> {
    pub sender_index: usize,
    pub disclosed_shares: BroadcastPhase5<G>,
}

#[cfg(test)]
mod tests {
    use super::*;

    use curve25519_dalek::ristretto::RistrettoPoint;
    use rand_core::OsRng;

    #[test]
    fn valid_phase_2() {
        let mut rng = OsRng;

        let shared_string = b"Example of a shared string.".to_owned();
        let threshold = 2;
        let nr_members = 2;
        let environment = Environment::init(threshold, nr_members, &shared_string);

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

        let phase_2 = m1.proceed(&environment, &fetched_state, &mut rng);
        if let Some(_data) = phase_2.1 {
            // broadcast the `data`
        }

        phase_2.0.unwrap();
        // assert!(phase_2.0.is_ok());
    }

    #[test]
    fn invalid_phase_2() {
        let mut rng = OsRng;

        let shared_string = b"Example of a shared string.".to_owned();
        let threshold = 2;
        let nr_members = 3;
        let environment = Environment::init(threshold, nr_members, &shared_string);

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
        let phase_2_faked = m1.proceed(&environment, &fetched_state, &mut rng);
        assert_eq!(phase_2_faked.0, Err(DkgError::MisbehaviourHigherThreshold));

        // And there should be data to broadcast
        assert!(phase_2_faked.1.is_some())
    }

    #[test]
    fn misbehaving_parties() {
        let mut rng = OsRng;

        let shared_string = b"Example of a shared string.".to_owned();

        let threshold = 2;
        let nr_members = 3;
        let environment = Environment::init(threshold, nr_members, &shared_string);

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

        // Now, party one fetches invalid state of a single party, mainly party three
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

        let (phase_2, broadcast_data) = m1.proceed(&environment, &fetched_state, &mut rng);

        assert!(phase_2.is_ok());
        let unwrapped_phase = phase_2.unwrap();

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
            .verify(
                &mc1.to_public(),
                &fetched_state[1],
                &environment.commitment_key,
                2,
                2
            )
            .is_ok());

        // The qualified set should be [1, 1, 0]
        let (phase_3, _broadcast_data_3) = unwrapped_phase.proceed(&[bd]);
        assert!(phase_3.is_ok());
        assert_eq!(phase_3.unwrap().state.qualified_set, [1, 1, 0])
    }

    #[test]
    fn phase_4_tests() {
        let mut rng = OsRng;

        let shared_string = b"Example of a shared string.".to_owned();

        let threshold = 2;
        let nr_members = 3;
        let environment = Environment::init(threshold, nr_members, &shared_string);

        let mc1 = MemberCommunicationKey::<RistrettoPoint>::new(&mut rng);
        let mc2 = MemberCommunicationKey::<RistrettoPoint>::new(&mut rng);
        let mc3 = MemberCommunicationKey::<RistrettoPoint>::new(&mut rng);
        let mc = [mc1.to_public(), mc2.to_public(), mc3.to_public()];

        let (m1, broad_1) =
            DistributedKeyGeneration::<RistrettoPoint>::init(&mut rng, &environment, &mc1, &mc, 1);
        let (m2, broad_2) =
            DistributedKeyGeneration::<RistrettoPoint>::init(&mut rng, &environment, &mc2, &mc, 2);
        let (_m3, broad_3) =
            DistributedKeyGeneration::<RistrettoPoint>::init(&mut rng, &environment, &mc3, &mc, 3);

        // Fetched state of party 1
        let fetched_state_1 = vec![
            MembersFetchedState1 {
                sender_index: 2,
                indexed_shares: broad_2.encrypted_shares[0].clone(),
                committed_coeffs: broad_2.committed_coefficients.clone(),
            },
            MembersFetchedState1 {
                sender_index: 3,
                indexed_shares: broad_3.encrypted_shares[0].clone(),
                committed_coeffs: broad_3.committed_coefficients.clone(),
            },
        ];

        // Fetched state of party 2
        let fetched_state_2 = vec![
            MembersFetchedState1 {
                sender_index: 1,
                indexed_shares: broad_1.encrypted_shares[0].clone(),
                committed_coeffs: broad_1.committed_coefficients.clone(),
            },
            MembersFetchedState1 {
                sender_index: 3,
                indexed_shares: broad_3.encrypted_shares[1].clone(),
                committed_coeffs: broad_3.committed_coefficients.clone(),
            },
        ];

        // Now we proceed to phase two.
        let (party_1_phase_2, _party_1_phase_2_broadcast_data) =
            m1.proceed(&environment, &fetched_state_1, &mut rng);
        let (party_2_phase_2, _party_2_phase_2_broadcast_data) =
            m2.proceed(&environment, &fetched_state_2, &mut rng);

        assert!(party_1_phase_2.is_ok());
        assert!(party_2_phase_2.is_ok());

        // We proceed to phase three
        let (party_1_phase_3, _party_1_broadcast_data_3) = party_1_phase_2.unwrap().proceed(&[]);
        let (party_2_phase_3, party_2_broadcast_data_3) = party_2_phase_2.unwrap().proceed(&[]);

        assert!(party_1_phase_3.is_ok() && party_2_phase_3.is_ok());

        // Fetched state of party 1. We have mimic'ed that party three stopped participating.
        let party_1_fetched_state_phase_3 = vec![MembersFetchedState3 {
            sender_index: 2,
            committed_coefficients: party_2_broadcast_data_3.unwrap().committed_coefficients,
        }];

        // The protocol should finalise, given that we have two honest parties finalising the protocol
        // which is higher than the threshold
        assert!(party_1_phase_3
            .unwrap()
            .proceed(&party_1_fetched_state_phase_3)
            .0
            .is_ok());

        // If party three stops participating, and party 1 misbehaves, the protocol fails for party
        // 2, and there should be the proof of misbehaviour of party 1.
        let party_2_fetched_state_phase_3 = vec![MembersFetchedState3::<RistrettoPoint> {
            sender_index: 1,
            committed_coefficients: vec![PrimeGroupElement::generator(); threshold + 1],
        }];

        let failing_phase = party_2_phase_3
            .unwrap()
            .proceed(&party_2_fetched_state_phase_3);
        assert!(failing_phase.0.is_err());
        assert!(failing_phase.1.is_some());
    }

    fn full_run() -> Result<(), DkgError> {
        let mut rng = OsRng;

        let shared_string = b"Example of a shared string.".to_owned();

        let threshold = 2;
        let nr_members = 3;
        let environment = Environment::init(threshold, nr_members, &shared_string);

        let mc1 = MemberCommunicationKey::<RistrettoPoint>::new(&mut rng);
        let mc2 = MemberCommunicationKey::<RistrettoPoint>::new(&mut rng);
        let mc3 = MemberCommunicationKey::<RistrettoPoint>::new(&mut rng);
        let mc = [mc1.to_public(), mc2.to_public(), mc3.to_public()];

        let (m1, broad_1) =
            DistributedKeyGeneration::<RistrettoPoint>::init(&mut rng, &environment, &mc1, &mc, 1);
        let (m2, broad_2) =
            DistributedKeyGeneration::<RistrettoPoint>::init(&mut rng, &environment, &mc2, &mc, 2);
        let (m3, broad_3) =
            DistributedKeyGeneration::<RistrettoPoint>::init(&mut rng, &environment, &mc3, &mc, 3);

        // Parties 1, 2, and 3 publish broad_1, broad_2, and broad_3 respectively in the
        // blockchain. All parties fetched the data.

        // Fetched state of party 1
        let fetched_state_1 = vec![
            MembersFetchedState1 {
                sender_index: 2,
                indexed_shares: broad_2.encrypted_shares[0].clone(),
                committed_coeffs: broad_2.committed_coefficients.clone(),
            },
            MembersFetchedState1 {
                sender_index: 3,
                indexed_shares: broad_3.encrypted_shares[0].clone(),
                committed_coeffs: broad_3.committed_coefficients.clone(),
            },
        ];

        // Fetched state of party 2
        let fetched_state_2 = vec![
            MembersFetchedState1 {
                sender_index: 1,
                indexed_shares: broad_1.encrypted_shares[0].clone(),
                committed_coeffs: broad_1.committed_coefficients.clone(),
            },
            MembersFetchedState1 {
                sender_index: 3,
                indexed_shares: broad_3.encrypted_shares[1].clone(),
                committed_coeffs: broad_3.committed_coefficients.clone(),
            },
        ];

        // Fetched state of party 3
        let fetched_state_3 = vec![
            MembersFetchedState1 {
                sender_index: 1,
                indexed_shares: broad_1.encrypted_shares[1].clone(),
                committed_coeffs: broad_1.committed_coefficients.clone(),
            },
            MembersFetchedState1 {
                sender_index: 2,
                indexed_shares: broad_2.encrypted_shares[1].clone(),
                committed_coeffs: broad_2.committed_coefficients.clone(),
            },
        ];

        // Now we proceed to phase two.
        let (party_1_phase_2, party_1_phase_2_broadcast_data) =
            m1.proceed(&environment, &fetched_state_1, &mut rng);
        let (party_2_phase_2, party_2_phase_2_broadcast_data) =
            m2.proceed(&environment, &fetched_state_2, &mut rng);
        let (party_3_phase_2, party_3_phase_2_broadcast_data) =
            m3.proceed(&environment, &fetched_state_3, &mut rng);

        if party_1_phase_2_broadcast_data.is_some()
            || party_2_phase_2_broadcast_data.is_some()
            || party_3_phase_2_broadcast_data.is_some()
        {
            // then they publish the data.
        }

        // We proceed to phase three (with no input because there was no misbehaving parties).
        let (party_1_phase_3, party_1_broadcast_data_3) = party_1_phase_2?.proceed(&[]);
        let (party_2_phase_3, party_2_broadcast_data_3) = party_2_phase_2?.proceed(&[]);
        let (party_3_phase_3, party_3_broadcast_data_3) = party_3_phase_2?.proceed(&[]);

        // A valid run of phase 3 will always output a broadcast message. The parties fetch it,
        // and use it to proceed to phase 4.
        let committed_coefficients_1 = party_1_broadcast_data_3
            .expect("valid runs returns something")
            .committed_coefficients;
        let committed_coefficients_2 = party_2_broadcast_data_3
            .expect("valid runs returns something")
            .committed_coefficients;
        let committed_coefficients_3 = party_3_broadcast_data_3
            .expect("valid runs returns something")
            .committed_coefficients;

        // Fetched state of party 1.
        let fetched_state_1_phase_3 = vec![
            MembersFetchedState3 {
                sender_index: 2,
                committed_coefficients: committed_coefficients_2.clone(),
            },
            MembersFetchedState3 {
                sender_index: 3,
                committed_coefficients: committed_coefficients_3.clone(),
            },
        ];

        // Fetched state of party 1.
        let fetched_state_2_phase_3 = vec![
            MembersFetchedState3 {
                sender_index: 1,
                committed_coefficients: committed_coefficients_1.clone(),
            },
            MembersFetchedState3 {
                sender_index: 3,
                committed_coefficients: committed_coefficients_3,
            },
        ];

        // Fetched state of party 1.
        let fetched_state_3_phase_3 = vec![
            MembersFetchedState3 {
                sender_index: 2,
                committed_coefficients: committed_coefficients_2,
            },
            MembersFetchedState3 {
                sender_index: 1,
                committed_coefficients: committed_coefficients_1,
            },
        ];

        // We proceed to phase four with the fetched state of the previous phase.
        let (party_1_phase_4, _party_1_broadcast_data_4) =
            party_1_phase_3?.proceed(&fetched_state_1_phase_3);
        let (party_2_phase_4, _party_2_broadcast_data_4) =
            party_2_phase_3?.proceed(&fetched_state_2_phase_3);
        let (party_3_phase_4, _party_3_broadcast_data_4) =
            party_3_phase_3?.proceed(&fetched_state_3_phase_3);

        // Now we proceed to phase five, where we disclose the shares of the qualified, misbehaving
        // parties. There is no misbehaving parties, so broadcast of phase 4 is None.

        let (party_1_phase_5, _party_1_broadcast_data_5) = party_1_phase_4?.proceed(None);
        let (party_2_phase_5, _party_2_broadcast_data_5) = party_2_phase_4?.proceed(None);
        let (party_3_phase_5, _party_3_broadcast_data_5) = party_3_phase_4?.proceed(None);

        // Finally, the different parties generate the master public key. No misbehaving parties, so
        // broadcast of phase 5 is None.
        let mk_1 = party_1_phase_5?.finalise(None);
        let mk_2 = party_2_phase_5?.finalise(None);
        let mk_3 = party_3_phase_5?.finalise(None);

        if mk_1 != mk_2 || mk_2 != mk_3 { return Err(DkgError::InconsistentMasterKey) }

        Ok(())
    }
    #[test]
    fn full_valid_run() {
        let run: Result<(), DkgError> = full_run();

        assert!(run.is_ok());
    }
}
