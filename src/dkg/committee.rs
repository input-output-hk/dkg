#![allow(clippy::type_complexity)]

pub use super::broadcast::{DecryptedShares, EncryptedShares};
use super::procedure_keys::{
    MemberCommunicationKey, MemberCommunicationPublicKey, MemberPublicShare, MemberSecretShare,
};
use crate::cryptography::commitment::CommitmentKey;
use crate::cryptography::elgamal::{PublicKey, SecretKey};
use crate::dkg::broadcast::{
    BroadcastPhase1, BroadcastPhase2, BroadcastPhase3, BroadcastPhase4, BroadcastPhase5,
    MisbehavingPartiesRound1, MisbehavingPartiesRound3, MisbehavingPartiesRound4,
    ProofOfMisbehaviour,
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
    pub(crate) threshold: usize,
    nr_members: usize,
    pub(crate) commitment_key: CommitmentKey<G>,
}

/// Private state, generated over the protocol
#[derive(Clone, Debug, PartialEq)]
pub struct IndividualState<G: PrimeGroupElement> {
    index: usize,
    environment: Environment<G>,
    communication_sk: MemberCommunicationKey<G>,
    members_pks: Vec<MemberCommunicationPublicKey<G>>,
    final_share: Option<MemberSecretShare<G>>,
    public_share: Option<MemberPublicShare<G>>,
    master_public_key: Option<MemberPublicShare<G>>,
    indexed_received_shares: Vec<Option<DecryptedShares<G>>>,
    indexed_committed_shares: Vec<Option<Vec<G>>>,
    /// Set of parties whose secret needs to be reconstructed
    reconstructable_set: Vec<usize>,
    qualified_set: Vec<usize>,
}

/// Definition of a phase
pub struct Phases<G: PrimeGroupElement, Phase> {
    state: IndividualState<G>,
    phase: PhantomData<Phase>,
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
    /// Panics if `threshold` is greater or equal to `nr_members / 2`.
    pub fn init(threshold: usize, nr_members: usize, ck_gen_bytes: &[u8]) -> Self {
        assert!(threshold < (nr_members + 1) / 2);

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
    ) -> (Phases<G, Phase1>, BroadcastPhase1<G>) {
        assert_eq!(committee_pks.len(), environment.nr_members);

        let mut ordered_pks = committee_pks.clone().to_vec();
        ordered_pks.sort();

        // indices start at zero
        let my = ordered_pks
            .iter()
            .position(|x| *x == secret_key.to_public())
            .expect("Own public key must be part of the committee_pks")
            + 1;

        // We initialise the vector of committed and decrypted shares, to which we include
        // the shares of the party initialising
        let mut committed_shares = vec![None; environment.nr_members];
        let mut decrypted_shares: Vec<Option<DecryptedShares<G>>> =
            vec![None; environment.nr_members];

        let hiding_polynomial =
            Polynomial::<G::CorrespondingScalar>::random(rng, environment.threshold);
        let sharing_polynomial =
            Polynomial::<G::CorrespondingScalar>::random(rng, environment.threshold);

        let mut apubs = Vec::with_capacity(environment.threshold + 1);
        let mut coeff_comms = Vec::with_capacity(environment.threshold + 1);

        for (ai, &bi) in sharing_polynomial
            .get_coefficients()
            .zip(hiding_polynomial.get_coefficients())
        {
            let apub = G::generator() * *ai;
            let coeff_comm = (environment.commitment_key.h * bi) + apub;
            apubs.push(apub);
            coeff_comms.push(coeff_comm);
        }

        let mut encrypted_shares: Vec<EncryptedShares<G>> =
            Vec::with_capacity(environment.nr_members - 1);
        #[allow(clippy::needless_range_loop)]
        for i in 0..environment.nr_members {
            let idx = <G::CorrespondingScalar as Scalar>::from_u64((i + 1) as u64);
            let randomness = hiding_polynomial.evaluate(&idx);
            let share = sharing_polynomial.evaluate(&idx);

            let pk = &ordered_pks[i];

            let encrypted_randomness = pk.hybrid_encrypt(&randomness.to_bytes(), rng);
            let encrypted_share = pk.hybrid_encrypt(&share.to_bytes(), rng);

            encrypted_shares.push(EncryptedShares {
                recipient_index: i + 1,
                encrypted_share,
                encrypted_randomness,
            });
            if i == my - 1 {
                decrypted_shares[my - 1] = Some(DecryptedShares {
                    decrypted_share: share,
                    decrypted_randomness: randomness,
                    committed_coefficients: coeff_comms.clone(),
                });
            }
        }

        let qualified_set = vec![1; environment.nr_members];
        let reconstructable_set = vec![0; environment.nr_members];
        committed_shares[my - 1] = Some(apubs);

        let state = IndividualState {
            index: my,
            environment: environment.clone(),
            communication_sk: secret_key.clone(),
            members_pks: ordered_pks.to_vec(),
            final_share: None,
            public_share: None,
            master_public_key: None,
            indexed_received_shares: decrypted_shares,
            indexed_committed_shares: committed_shares,
            reconstructable_set,
            qualified_set,
        };

        (
            Phases::<G, Phase1> {
                state,
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
    /// Function that takes as input the broadcast data from the initialisation and proceeds to
    /// phase 1.
    pub fn proceed_with_broadcast<R>(
        self,
        broadcast_messages: &[Option<BroadcastPhase1<G>>],
        rng: &mut R,
    ) -> (
        Result<Phases<G, Phase2>, DkgError>,
        Option<BroadcastPhase2<G>>,
    )
    where
        R: CryptoRng + RngCore,
    {
        let processed_data = MembersFetchedState1::from_broadcast(
            &self.state.environment,
            self.state.index,
            broadcast_messages,
        );

        self.proceed(&processed_data, rng)
    }
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
        let mut misbehaving_parties: Vec<MisbehavingPartiesRound1<G>> = Vec::new();
        for fetched_data in members_state {
            let sender_index = self
                .state
                .members_pks
                .iter()
                .position(|x| *x == fetched_data.sender_pk)
                .o
                + 1;
            if let (Some(indexed_shares), Some(commited_coeffs)) =
                fetched_data.get_shares_and_coeffs()
            {
                // If recipient indexed does not correspond with ones self, abort.
                if indexed_shares.recipient_index != self.state.index {
                    return (Err(DkgError::FetchedInvalidData), None);
                }

                if let (Some(decrypted_share), Some(decrypted_randomness)) = self
                    .state
                    .communication_sk
                    .decrypt_shares(indexed_shares.clone())
                {
                    let index_pow =
                        <G::CorrespondingScalar as Scalar>::from_u64(self.state.index as u64)
                            .exp_iter()
                            .take(self.state.environment.threshold + 1);

                    let check_element = self.state.environment.commitment_key.h
                        * decrypted_randomness
                        + G::generator() * decrypted_share;
                    let multi_scalar =
                        G::vartime_multiscalar_multiplication(index_pow, commited_coeffs.clone());

                    self.state.indexed_received_shares[fetched_data.sender_pk - 1] =
                        Some(DecryptedShares {
                            decrypted_share,
                            decrypted_randomness,
                            committed_coefficients: commited_coeffs,
                        });

                    if check_element != multi_scalar {
                        let proof = ProofOfMisbehaviour::generate(
                            &indexed_shares.clone(),
                            &self.state.communication_sk,
                            rng,
                        );
                        qualified_set[fetched_data.sender_pk - 1] = 0;
                        misbehaving_parties.push(MisbehavingPartiesRound1 {
                            accused_index: fetched_data.sender_pk,
                            accusation_error: DkgError::ShareValidityFailed,
                            proof_accusation: proof,
                        });
                    }
                } else {
                    // todo: handle the proofs. Might not be the most optimal way of handling these two
                    let proof = ProofOfMisbehaviour::generate(
                        &indexed_shares.clone(),
                        &self.state.communication_sk,
                        rng,
                    );
                    qualified_set[fetched_data.sender_pk - 1] = 0;
                    misbehaving_parties.push(MisbehavingPartiesRound1 {
                        accused_index: fetched_data.sender_pk,
                        accusation_error: DkgError::ScalarOutOfBounds,
                        proof_accusation: proof,
                    });
                }
            } else {
                // We simply disqualify the member. All honest members would arrive to the
                // same conclusion, due to the way these values are defined as None.
                // todo: test
                qualified_set[fetched_data.sender_pk - 1] = 0;
            }
        }

        if misbehaving_parties.len() > self.state.environment.threshold {
            return (
                Err(DkgError::MisbehaviourHigherThreshold),
                Some(BroadcastPhase2 {
                    misbehaving_parties,
                }),
            );
        }

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
    fn compute_qualified_set(
        &mut self,
        broadcast_complaints: &[MembersFetchedState2<G>],
        broadcast_phase_1: &[Option<BroadcastPhase1<G>>],
    ) {
        for broadcast in broadcast_complaints {
            for misbehaving_parties in &broadcast.accusations.misbehaving_parties {
                // if the accused party did not public in the first round, we ignore it
                if let Some(broadcast_message) =
                    &broadcast_phase_1[misbehaving_parties.accused_index - 1]
                {
                    if misbehaving_parties
                        .verify(
                            &self.state.environment,
                            broadcast.sender_pk,
                            &self.state.members_pks[broadcast.sender_pk - 1],
                            &broadcast_message,
                        )
                        .is_ok()
                    {
                        self.state.qualified_set[misbehaving_parties.accused_index - 1] &= 0;
                    } else {
                        // todo: should we disqualify the falsely accusing member? For now we skip
                        continue;
                    }
                }
            }
        }
    }

    /// Proceed with input the broadcast data
    pub fn proceed_with_broadcast(
        self,
        broadcast_messages: &[Option<BroadcastPhase2<G>>],
        broadcast_round_1: &[Option<BroadcastPhase1<G>>],
    ) -> (
        Result<Phases<G, Phase3>, DkgError>,
        Option<BroadcastPhase3<G>>,
    ) {
        // make sure we've taken broadcast from all members
        assert_eq!(broadcast_messages.len(), broadcast_round_1.len() - 1);
        assert_eq!(broadcast_round_1.len(), self.state.environment.nr_members);
        let processed_data = MembersFetchedState2::from_broadcast(
            &self.state.environment,
            self.state.index,
            broadcast_messages,
        );

        self.proceed(&processed_data, broadcast_round_1)
    }

    /// This function takes as input the broadcast complaints from the previous phase,
    /// `broadcast_complaints`, and updates the qualified set. A single valid complaint
    /// disqualifies a member. Using the qualified set, the member generates is final secret
    /// share, and stores it, together with the public counterpart. Then it publishes a
    /// commitment to the polynomial coefficients $a_{i,l}$ without any randomness.
    /// In particular, each member $i$ broadcasts
    /// $A_{i,l} = g^{a_{i,l}}$ for $l\in\lbrace 0,\ldots,l}$.
    ///
    /// Errors
    ///
    /// If there is less qualified members than the threshold, the function fails and does not
    /// proceed to the following phase.
    pub fn proceed(
        mut self,
        broadcast_complaints: &[MembersFetchedState2<G>],
        // to verify the complaints, we need to have access to the broadcast messages of phase 1
        broadcast_round_1: &[Option<BroadcastPhase1<G>>],
    ) -> (
        Result<Phases<G, Phase3>, DkgError>,
        Option<BroadcastPhase3<G>>,
    ) {
        self.compute_qualified_set(broadcast_complaints, broadcast_round_1);
        if self.state.qualified_set.len() < self.state.environment.threshold + 1 {
            return (Err(DkgError::MisbehaviourHigherThreshold), None);
        }

        let broadcast = Some(BroadcastPhase3 {
            committed_coefficients: self.state.indexed_committed_shares[self.state.index - 1]
                .clone()
                .expect("owns committed coefficient is always existent"),
        });

        // Now that we have the qualified set, we can compute the secret share
        let mut secret_share = G::CorrespondingScalar::zero();
        for i in 0..self.state.environment.nr_members {
            if self.state.qualified_set[i] == 1 {
                secret_share += self.state.indexed_received_shares[i]
                    .as_ref()
                    .expect("Qualified member should have a share")
                    .decrypted_share;
            }
        }

        self.state.public_share = Some(MemberPublicShare(PublicKey {
            pk: G::generator() * secret_share,
        }));
        self.state.final_share = Some(MemberSecretShare(SecretKey { sk: secret_share }));

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
    /// Function that takes as input the broadcast data from the previous phase and proceeds to
    /// phase 4.
    pub fn proceed_with_broadcast(
        self,
        broadcast_messages: &[Option<BroadcastPhase3<G>>],
    ) -> (
        Result<Phases<G, Phase4>, DkgError>,
        Option<BroadcastPhase4<G>>,
    ) {
        let processed_data = MembersFetchedState3::from_broadcast(
            &self.state.environment,
            self.state.index,
            broadcast_messages,
        );

        self.proceed(&processed_data)
    }

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
        let received_shares = self.state.indexed_received_shares.clone();
        let mut misbehaving_parties: Vec<MisbehavingPartiesRound3<G>> = Vec::new();

        for fetched_commitments in fetched_state_3 {
            // if the fetched commitment is from a disqualified player, we skip
            if self.state.qualified_set[fetched_commitments.sender_pk - 1] != 0 {
                let indexed_shares = received_shares[fetched_commitments.sender_pk - 1]
                    .clone()
                    .expect("If it is part of honest members, their shares should be recorded");
                // We proceed only if there are coefficients.
                if let Some(coefficients) = &fetched_commitments.committed_coefficients {
                    // We store the indexed committed coefficients
                    self.state.indexed_committed_shares[fetched_commitments.sender_pk - 1] =
                        Some(coefficients.clone());

                    let index_pow =
                        <G::CorrespondingScalar as Scalar>::from_u64(self.state.index as u64)
                            .exp_iter()
                            .take(self.state.environment.threshold + 1);

                    let check_element = G::generator() * indexed_shares.decrypted_share;
                    let multi_scalar =
                        G::vartime_multiscalar_multiplication(index_pow, coefficients.clone());

                    if check_element != multi_scalar {
                        misbehaving_parties.push(MisbehavingPartiesRound3 {
                            accused_index: fetched_commitments.sender_pk,
                            decrypted_share: indexed_shares.decrypted_share,
                            decrypted_randomness: indexed_shares.decrypted_randomness,
                        });
                        continue;
                    }

                    honest[fetched_commitments.sender_pk - 1] |= 1;
                } else {
                    misbehaving_parties.push(MisbehavingPartiesRound3 {
                        accused_index: fetched_commitments.sender_pk,
                        decrypted_share: indexed_shares.decrypted_share,
                        decrypted_randomness: indexed_shares.decrypted_randomness,
                    });
                }
            }
        }

        let broadcast = if misbehaving_parties.is_empty() {
            None
        } else {
            Some(BroadcastPhase4 {
                misbehaving_parties,
            })
        };

        if honest.iter().sum::<usize>() < self.state.environment.threshold + 1 {
            return (Err(DkgError::MisbehaviourHigherThreshold), broadcast);
        }

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
    /// Function that takes as input the broadcast data from the previous phase and proceeds to
    /// phase 5.
    pub fn proceed_with_broadcast<'a>(
        self,
        broadcast_messages: &[Option<BroadcastPhase4<G>>],
        // For qualified members, there should always be broadacst of phase 1. Otherwise the
        // party should not be qualified.
        broadcasts_phase_1: &[&'a BroadcastPhase1<G>],
        // A qualified member might not broadcast in phase 3.
        broadcasts_phase_3: &[&'a Option<BroadcastPhase3<G>>],
    ) -> (
        Result<Phases<G, Phase5>, DkgError>,
        Option<BroadcastPhase5<G>>,
    ) {
        let processed_data = MembersFetchedState4::from_broadcast(
            &self.state.environment,
            self.state.index,
            broadcast_messages,
        );

        let processed_complaints = FetchedMisbehaviourComplaints::from_broadcasts_4(
            &processed_data,
            broadcasts_phase_1,
            broadcasts_phase_3,
        );

        self.proceed(&processed_complaints)
    }
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
    /// todo: revisit this function
    pub fn proceed(
        mut self,
        broadcast_complaints: &[FetchedMisbehaviourComplaints<'_, G>],
    ) -> (
        Result<Phases<G, Phase5>, DkgError>,
        Option<BroadcastPhase5<G>>,
    ) {
        // misbehaving parties will have their shares disclosed to generate the master public key
        let mut reconstruct_shares: Vec<Option<MisbehavingPartiesRound4<G>>> =
            vec![None; self.state.environment.nr_members];
        let received_shares = self.state.indexed_received_shares.clone();

        for fetched_complaints in broadcast_complaints {
            // If accused party is disqualified, we ignore it
            if self.state.qualified_set[fetched_complaints.misbehaving_party.accused_index - 1] != 0
            {
                // Now we verify that the complaint is valid. If the broadcast of phase 3
                // is None, then the complaint is valid.
                if let Some(broadcast_phase_3) = fetched_complaints.accused_broadcast_phase_3 {
                    if fetched_complaints
                        .misbehaving_party
                        .verify(
                            &self.state.environment,
                            fetched_complaints.accuser_index,
                            &fetched_complaints
                                .accused_broadcast_phase_1
                                .committed_coefficients,
                            &broadcast_phase_3.committed_coefficients,
                        )
                        .is_err()
                    {
                        // todo: what do we do? for the moment, we simply ignore the complaint
                        continue;
                    };
                }
                // If the tests pass, then we disclose the shares of the misbehaving party,
                // and include it in the data we will broadcast.
                let indexed_shares = received_shares
                    [fetched_complaints.misbehaving_party.accused_index - 1]
                    .as_ref()
                    .expect("If it is part of honest members, their shares should be recorded");
                reconstruct_shares[fetched_complaints.misbehaving_party.accused_index - 1] =
                    Some(indexed_shares.decrypted_share);
                self.state.reconstructable_set
                    [fetched_complaints.misbehaving_party.accused_index - 1] |= 1;
            }
        }

        let total_honest = self.state.qualified_set.iter().sum::<usize>()
            - self.state.reconstructable_set.iter().sum::<usize>();
        if total_honest <= self.state.environment.threshold {
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
    /// Function that takes as input the broadcast data from the previous phase and finalises
    /// the protocol.
    pub fn finalise_with_broadcast(
        self,
        broadcast_messages: &[Option<BroadcastPhase5<G>>],
    ) -> Result<(MasterPublicKey<G>, MemberSecretShare<G>), DkgError> {
        let processed_data = MembersFetchedState5::from_broadcast(
            &self.state.environment,
            self.state.index,
            broadcast_messages,
        );

        self.finalise(&processed_data)
    }

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
        broadcast_complaints: &[MembersFetchedState5<G>],
    ) -> Result<(MasterPublicKey<G>, MemberSecretShare<G>), DkgError> {
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

        let committed_shares = self.state.indexed_committed_shares;

        let received_shares = self.state.indexed_received_shares;

        for i in 0..self.state.environment.nr_members {
            if self.state.reconstructable_set[i] == 1 && self.state.qualified_set[i] != 1 {
                panic!("Only qualified members should be reconstructed");
            } else if self.state.reconstructable_set[i] == 1 && self.state.qualified_set[i] == 1 {
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
                        .decrypted_share,
                );

                for disclosed_shares in broadcast_complaints {
                    // if it is not within the final parties, we ignore it
                    if final_parties[disclosed_shares.sender_pk - 1] == 1 {
                        if let Some(share) =
                            disclosed_shares.disclosed_shares.misbehaving_parties[i]
                        {
                            indices.push(G::CorrespondingScalar::from_u64(
                                disclosed_shares.sender_pk as u64,
                            ));
                            evaluated_points.push(share);
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

        Ok((
            MasterPublicKey(PublicKey { pk: master_key }),
            self.state
                .final_share
                .expect("At this point, we should have it."),
        ))
    }
}

/// State of the members after round 1. This structure contains the indexed encrypted
/// shares of every other participant, `indexed_shares`, and the committed coefficients
/// of the generated polynomials, `committed_coeffs`.
#[derive(Clone)]
pub struct MembersFetchedState1<G: PrimeGroupElement> {
    sender_pk: MemberCommunicationPublicKey<G>,
    indexed_shares: Option<EncryptedShares<G>>,
    committed_coeffs: Option<Vec<G>>,
}

impl<G: PrimeGroupElement> MembersFetchedState1<G> {
    fn get_shares_and_coeffs(&self) -> (Option<EncryptedShares<G>>, Option<Vec<G>>) {
        (self.indexed_shares.clone(), self.committed_coeffs.clone())
    }
    /// Given as input all broadcast messages in an ordered vector, returns a vector of indexed
    /// fetched states. If some party does not broadcast in Round 1, then the entry should be
    /// filled with `None`. The broadcast messages must be ordered from low index to high index.
    pub fn from_broadcast(
        environment: &Environment<G>,
        recipient_index: usize,
        broadcast_messages: &[Option<BroadcastPhase1<G>>],
    ) -> Vec<Self> {
        // We should have broadcasters for ALL other participants
        assert!(recipient_index > 0 && recipient_index <= environment.nr_members);
        assert_eq!(broadcast_messages.len(), environment.nr_members - 1);

        let mut broadcaster_indices: Vec<usize> = (1..(environment.nr_members + 1)).collect();
        broadcaster_indices.remove(recipient_index - 1);

        let mut output = Vec::new();
        for (&index, message) in broadcaster_indices.iter().zip(broadcast_messages.iter()) {
            if let Some(broadcast_message) = message {
                // We first check that the party sent messages to all participants, and that
                // the number of committed coefficients corresponds with the expected degree of
                // the polynomial. If that is not the case, then no fetched data is recorded
                // for this party, and will disqualify it in the next round.
                if broadcast_message.committed_coefficients.len() != environment.threshold + 1
                    || broadcast_message.encrypted_shares.len() != environment.nr_members
                {
                    output.push(MembersFetchedState1 {
                        sender_pk: index,
                        indexed_shares: None,
                        committed_coeffs: None,
                    });
                    continue;
                }

                output.push(MembersFetchedState1 {
                    sender_pk: index,
                    indexed_shares: Some(
                        broadcast_message.encrypted_shares[recipient_index - 1].clone(),
                    ),
                    committed_coeffs: Some(broadcast_message.committed_coefficients.clone()),
                });
            } else {
                output.push(MembersFetchedState1 {
                    sender_pk: index,
                    indexed_shares: None,
                    committed_coeffs: None,
                })
            }
        }
        output
    }
}

/// State of the members after round 1. This structure contains the indexed encrypted
/// shares of every other participant, `indexed_shares`, and the committed coefficients
/// of the generated polynomials, `committed_coeffs`.
#[derive(Clone)]
pub struct MembersFetchedState2<G: PrimeGroupElement> {
    sender_pk: MemberCommunicationPublicKey<G>,
    accusations: BroadcastPhase2<G>,
}

impl<G: PrimeGroupElement> MembersFetchedState2<G> {
    /// Given as input all broadcast messages in an ordered vector, returns a vector of indexed
    /// fetched states.
    pub fn from_broadcast(
        environment: &Environment<G>,
        recipient_index: usize,
        broadcast_messages: &[Option<BroadcastPhase2<G>>],
    ) -> Vec<Self> {
        // We should have broadcasters for ALL other participants
        assert!(recipient_index > 0 && recipient_index <= environment.nr_members);
        assert_eq!(broadcast_messages.len(), environment.nr_members - 1);

        let mut broadcaster_indices: Vec<usize> = (1..(environment.nr_members + 1)).collect();
        broadcaster_indices.remove(recipient_index - 1);

        let mut output = Vec::new();
        for (&index, message) in broadcaster_indices.iter().zip(broadcast_messages.iter()) {
            if let Some(broadcast_message) = message {
                output.push(MembersFetchedState2 {
                    sender_pk: index,
                    accusations: broadcast_message.clone(),
                });
            }
        }
        output
    }
}

#[derive(Clone)]
pub struct MembersFetchedState3<G: PrimeGroupElement> {
    sender_pk: MemberCommunicationPublicKey<G>,
    /// Party might have not sent the value.
    committed_coefficients: Option<Vec<G>>,
}

impl<G: PrimeGroupElement> MembersFetchedState3<G> {
    /// The order of broadcast_messages needs to be from low to high index.
    /// todo: change this requirement.
    pub fn from_broadcast(
        environment: &Environment<G>,
        recipient_index: usize,
        broadcast_messages: &[Option<BroadcastPhase3<G>>],
    ) -> Vec<Self> {
        // We should have broadcasters for ALL other participants
        assert!(recipient_index > 0 && recipient_index <= environment.nr_members);
        assert_eq!(broadcast_messages.len(), environment.nr_members - 1);

        let mut broadcaster_indices: Vec<usize> = (1..(environment.nr_members + 1)).collect();
        broadcaster_indices.remove(recipient_index - 1);

        let mut output = Vec::new();
        for (&index, message) in broadcaster_indices.iter().zip(broadcast_messages.iter()) {
            if let Some(broadcast_message) = message {
                // We first check that the party sent messages to all participants, and that
                // the number of committed coefficients corresponds with the expected degree of
                // the polynomial. If that is not the case, then no fetched data is recorded
                // for this party, and will disqualify it in the next round.
                if broadcast_message.committed_coefficients.len() != environment.threshold + 1 {
                    output.push(MembersFetchedState3 {
                        sender_pk: index,
                        committed_coefficients: None,
                    });
                    continue;
                }

                output.push(MembersFetchedState3 {
                    sender_pk: index,
                    committed_coefficients: Some(broadcast_message.clone().committed_coefficients),
                });
            } else {
                output.push(MembersFetchedState3 {
                    sender_pk: index,
                    committed_coefficients: None,
                })
            }
        }
        output
    }
}

#[derive(Clone)]
pub struct MembersFetchedState4<G: PrimeGroupElement> {
    sender_pk: MemberCommunicationPublicKey<G>,
    accusation: BroadcastPhase4<G>,
}

impl<G: PrimeGroupElement> MembersFetchedState4<G> {
    pub fn from_broadcast(
        environment: &Environment<G>,
        recipient_index: usize,
        broadcast_messages: &[Option<BroadcastPhase4<G>>],
    ) -> Vec<Self> {
        assert!(recipient_index > 0 && recipient_index <= environment.nr_members);
        assert_eq!(broadcast_messages.len(), environment.nr_members - 1);

        let mut broadcaster_indices: Vec<usize> = (1..(environment.nr_members + 1)).collect();
        broadcaster_indices.remove(recipient_index - 1);

        let mut output = Vec::new();
        for (&index, message) in broadcaster_indices.iter().zip(broadcast_messages.iter()) {
            if let Some(broadcast_message) = message {
                output.push(Self {
                    sender_pk: index,
                    accusation: broadcast_message.clone(),
                })
            }
        }
        output
    }
}

#[derive(Clone)]
pub struct MembersFetchedState5<G: PrimeGroupElement> {
    sender_pk: MemberCommunicationPublicKey<G>,
    disclosed_shares: BroadcastPhase5<G>,
}

impl<G: PrimeGroupElement> MembersFetchedState5<G> {
    pub fn from_broadcast(
        environment: &Environment<G>,
        recipient_index: usize,
        broadcast_messages: &[Option<BroadcastPhase5<G>>],
    ) -> Vec<Self> {
        assert!(recipient_index > 0 && recipient_index <= environment.nr_members);
        assert_eq!(broadcast_messages.len(), environment.nr_members - 1);

        let mut broadcaster_indices: Vec<usize> = (1..(environment.nr_members + 1)).collect();
        broadcaster_indices.remove(recipient_index - 1);

        let mut output = Vec::new();
        for (&index, message) in broadcaster_indices.iter().zip(broadcast_messages.iter()) {
            if let Some(broadcast_message) = message {
                output.push(Self {
                    sender_pk: index,
                    disclosed_shares: broadcast_message.clone(),
                })
            }
        }
        output
    }
}

#[derive(Clone)]
// todo: ensure lifetime of 'a is as long as the struct
pub struct FetchedMisbehaviourComplaints<'a, G: PrimeGroupElement> {
    accuser_index: usize,
    misbehaving_party: MisbehavingPartiesRound3<G>,
    accused_broadcast_phase_1: &'a BroadcastPhase1<G>,
    // A qualified member could not broadcast anything in phase 3, and that should
    // be stored in the complaint.
    accused_broadcast_phase_3: &'a Option<BroadcastPhase3<G>>,
}

impl<'a, G: PrimeGroupElement> FetchedMisbehaviourComplaints<'a, G> {
    /// `broadcasts_phase_1` and `broadcasts_phase_3` need to be vectors with entries for every
    /// other participant. If a participant did not broadcast data in a particular phase, then
    /// we need to define it with `None`.
    pub fn from_broadcasts_4(
        accusations: &[MembersFetchedState4<G>],
        // For qualified members, there should always be broadcast of phase 1. Otherwise the
        // party should not be qualified.
        broadcasts_phase_1: &[&'a BroadcastPhase1<G>],
        // A qualified member might not broadcast in phase 3.
        broadcasts_phase_3: &[&'a Option<BroadcastPhase3<G>>],
    ) -> Vec<Self> {
        // todo: with capacity?
        let mut complaints = Vec::new();
        for grouped_accusation in accusations {
            for single_accusation in &grouped_accusation.accusation.misbehaving_parties {
                complaints.push(FetchedMisbehaviourComplaints {
                    accuser_index: grouped_accusation.sender_pk,
                    misbehaving_party: single_accusation.clone(),
                    // If the accused party did not broadcast any data during phase 1 it should
                    // be disqualified.
                    accused_broadcast_phase_1: broadcasts_phase_1
                        [single_accusation.accused_index - 1],
                    accused_broadcast_phase_3: broadcasts_phase_3
                        [single_accusation.accused_index - 1],
                })
            }
        }
        complaints
    }
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
        let threshold = 0;
        let nr_members = 2;
        let environment = Environment::init(threshold, nr_members, &shared_string);

        let mc1 = MemberCommunicationKey::<RistrettoPoint>::new(&mut rng);
        let mc2 = MemberCommunicationKey::<RistrettoPoint>::new(&mut rng);
        let mc = [mc1.to_public(), mc2.to_public()];

        let (m1, _broadcast1) =
            DistributedKeyGeneration::<RistrettoPoint>::init(&mut rng, &environment, &mc1, &mc);
        let (_m2, broadcast2) =
            DistributedKeyGeneration::<RistrettoPoint>::init(&mut rng, &environment, &mc2, &mc);

        // Now, party one fetches the state of the other party, mainly party two
        let fetched_state =
            MembersFetchedState1::from_broadcast(&environment, 1, &[Some(broadcast2)]);

        let phase_2 = m1.proceed(&fetched_state, &mut rng);
        if let Some(_data) = phase_2.1 {
            // broadcast the `data`
        }

        assert!(phase_2.0.is_ok());
    }

    #[test]
    fn invalid_phase_2() {
        let mut rng = OsRng;

        let shared_string = b"Example of a shared string.".to_owned();
        let threshold = 1;
        let nr_members = 3;
        let environment = Environment::init(threshold, nr_members, &shared_string);

        let mc1 = MemberCommunicationKey::<RistrettoPoint>::new(&mut rng);
        let mc2 = MemberCommunicationKey::<RistrettoPoint>::new(&mut rng);
        let mc3 = MemberCommunicationKey::<RistrettoPoint>::new(&mut rng);
        let mc = [mc1.to_public(), mc2.to_public(), mc3.to_public()];

        let (m1, _broad_1) =
            DistributedKeyGeneration::<RistrettoPoint>::init(&mut rng, &environment, &mc1, &mc);
        let (_m2, mut broad_2) =
            DistributedKeyGeneration::<RistrettoPoint>::init(&mut rng, &environment, &mc2, &mc);
        let (_m3, mut broad_3) =
            DistributedKeyGeneration::<RistrettoPoint>::init(&mut rng, &environment, &mc3, &mc);

        // Now, party one fetches invalid state of the other parties, mainly party two and three
        broad_2.committed_coefficients = vec![PrimeGroupElement::zero(); threshold + 1];
        broad_3.committed_coefficients = vec![PrimeGroupElement::zero(); threshold + 1];

        let fetched_state = MembersFetchedState1::from_broadcast(
            &environment,
            1,
            &[Some(broad_2.clone()), Some(broad_3.clone())],
        );

        // Given that there is a number of misbehaving parties higher than the threshold, proceeding
        // to step 2 should fail.
        let phase_2_faked = m1.proceed(&fetched_state, &mut rng);
        assert_eq!(phase_2_faked.0, Err(DkgError::MisbehaviourHigherThreshold));

        // And there should be data to broadcast.
        assert!(phase_2_faked.1.is_some());

        let broadcast_data = phase_2_faked.1.unwrap().clone();

        // In particular, the broadcast data should be valid complaints.
        let complaint_1 = broadcast_data.misbehaving_parties[0].clone();
        let complaint_2 = broadcast_data.misbehaving_parties[1].clone();

        assert!(complaint_1
            .verify(&environment, 1, &mc[0], &broad_2)
            .is_ok());

        assert!(complaint_2
            .verify(&environment, 1, &mc[0], &broad_3)
            .is_ok());
    }

    #[test]
    fn misbehaving_parties() {
        let mut rng = OsRng;

        let shared_string = b"Example of a shared string.".to_owned();

        let threshold = 1;
        let nr_members = 3;
        let environment = Environment::init(threshold, nr_members, &shared_string);

        let mc1 = MemberCommunicationKey::<RistrettoPoint>::new(&mut rng);
        let mc2 = MemberCommunicationKey::<RistrettoPoint>::new(&mut rng);
        let mc3 = MemberCommunicationKey::<RistrettoPoint>::new(&mut rng);
        let mc = [mc1.to_public(), mc2.to_public(), mc3.to_public()];

        let (m1, broad_1) =
            DistributedKeyGeneration::<RistrettoPoint>::init(&mut rng, &environment, &mc1, &mc);
        let (_m2, broad_2) =
            DistributedKeyGeneration::<RistrettoPoint>::init(&mut rng, &environment, &mc2, &mc);
        let (_m3, mut broad_3) =
            DistributedKeyGeneration::<RistrettoPoint>::init(&mut rng, &environment, &mc3, &mc);

        let broadcast_data_phase_1 = [
            Some(broad_1.clone()),
            Some(broad_2.clone()),
            Some(broad_3.clone()),
        ];

        // Now, party one fetches invalid state of a single party, mainly party three
        broad_3.committed_coefficients = vec![PrimeGroupElement::zero(); threshold + 1];
        let fetched_state = MembersFetchedState1::from_broadcast(
            &environment,
            1,
            &[Some(broad_2), Some(broad_3.clone())],
        );

        // Given that party 3 submitted encrypted shares which do not correspond to the
        // committed_coeffs, but party 2 submitted valid shares, phase 2 should be successful for
        // party 1, and there should be logs of misbehaviour only for party 3

        let (phase_2, broadcast_data) = m1.proceed(&fetched_state, &mut rng);

        assert!(phase_2.is_ok());
        let unwrapped_phase = phase_2.unwrap();

        assert!(broadcast_data.is_some());
        let bd = broadcast_data.unwrap();

        // Party 2 should be good, so there should be a single complaint
        assert_eq!(bd.misbehaving_parties.len(), 1);

        // Party 3 should be the accused party
        assert_eq!(bd.misbehaving_parties[0].accused_index, 3);
        assert_eq!(
            bd.misbehaving_parties[0].accusation_error,
            DkgError::ShareValidityFailed
        );
        // and the complaint should be valid
        assert!(bd.misbehaving_parties[0]
            .verify(&environment, 1, &mc[0], &broad_3)
            .is_ok());

        // The qualified set should be [1, 1, 0]. Note: to validate the complaints, we need to input
        // the broadcast data of phase 1.
        let (phase_3, _broadcast_data_3) =
            unwrapped_phase.proceed_with_broadcast(&[Some(bd), None], &broadcast_data_phase_1);
        assert!(phase_3.is_ok());
        assert_eq!(phase_3.unwrap().state.qualified_set, [1, 1, 0])
    }

    #[test]
    fn phase_4_tests() {
        let mut rng = OsRng;

        let shared_string = b"Example of a shared string.".to_owned();

        let threshold = 1;
        let nr_members = 3;
        let environment = Environment::init(threshold, nr_members, &shared_string);

        let mc1 = MemberCommunicationKey::<RistrettoPoint>::new(&mut rng);
        let mc2 = MemberCommunicationKey::<RistrettoPoint>::new(&mut rng);
        let mc3 = MemberCommunicationKey::<RistrettoPoint>::new(&mut rng);
        let mc = [mc1.to_public(), mc2.to_public(), mc3.to_public()];

        let (m1, broad_1) =
            DistributedKeyGeneration::<RistrettoPoint>::init(&mut rng, &environment, &mc1, &mc);
        let (m2, broad_2) =
            DistributedKeyGeneration::<RistrettoPoint>::init(&mut rng, &environment, &mc2, &mc);
        let (_m3, broad_3) =
            DistributedKeyGeneration::<RistrettoPoint>::init(&mut rng, &environment, &mc3, &mc);

        let broadcast_data_phase_1 = [
            Some(broad_1.clone()),
            Some(broad_2.clone()),
            Some(broad_3.clone()),
        ];

        // Fetched state of party 1
        let fetched_state_1 = MembersFetchedState1::from_broadcast(
            &environment,
            1,
            &[Some(broad_2), Some(broad_3.clone())],
        );

        // Fetched state of party 2
        let fetched_state_2 =
            MembersFetchedState1::from_broadcast(&environment, 2, &[Some(broad_1), Some(broad_3)]);

        // Now we proceed to phase two.
        let (party_1_phase_2, _party_1_phase_2_broadcast_data) =
            m1.proceed(&fetched_state_1, &mut rng);
        let (party_2_phase_2, _party_2_phase_2_broadcast_data) =
            m2.proceed(&fetched_state_2, &mut rng);

        assert!(party_1_phase_2.is_ok());
        assert!(party_2_phase_2.is_ok());

        // We proceed to phase three
        let (party_1_phase_3, _party_1_broadcast_data_3) = party_1_phase_2
            .unwrap()
            .proceed(&[], &broadcast_data_phase_1);
        let (party_2_phase_3, party_2_broadcast_data_3) = party_2_phase_2
            .unwrap()
            .proceed(&[], &broadcast_data_phase_1);

        assert!(party_1_phase_3.is_ok() && party_2_phase_3.is_ok());

        // Fetched state of party 1. We have mimic'ed that party three stopped participating.
        let party_1_fetched_state_phase_3 = vec![MembersFetchedState3 {
            sender_pk: 2,
            committed_coefficients: Some(party_2_broadcast_data_3.unwrap().committed_coefficients),
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
            sender_pk: 1,
            committed_coefficients: Some(vec![PrimeGroupElement::generator(); threshold + 1]),
        }];

        let failing_phase = party_2_phase_3
            .unwrap()
            .proceed(&party_2_fetched_state_phase_3);
        assert!(failing_phase.0.is_err());
        assert!(failing_phase.1.is_some());
    }

    #[test]
    fn misbehaviour_phase_4() {
        let mut rng = OsRng;

        let shared_string = b"Example of a shared string.".to_owned();

        let threshold = 1;
        let nr_members = 3;
        let environment = Environment::init(threshold, nr_members, &shared_string);

        let mc1 = MemberCommunicationKey::<RistrettoPoint>::new(&mut rng);
        let mc2 = MemberCommunicationKey::<RistrettoPoint>::new(&mut rng);
        let mc3 = MemberCommunicationKey::<RistrettoPoint>::new(&mut rng);
        let mc = [mc1.to_public(), mc2.to_public(), mc3.to_public()];

        let (m1, broad_1) =
            DistributedKeyGeneration::<RistrettoPoint>::init(&mut rng, &environment, &mc1, &mc);
        let (m2, broad_2) =
            DistributedKeyGeneration::<RistrettoPoint>::init(&mut rng, &environment, &mc2, &mc);
        let (m3, broad_3) =
            DistributedKeyGeneration::<RistrettoPoint>::init(&mut rng, &environment, &mc3, &mc);

        // Parties 1, 2, and 3 publish broad_1, broad_2, and broad_3 respectively in the
        // blockchain. All parties fetched the data.
        let broadcasts_phase_1 = [&broad_1, &broad_2, &broad_3];
        // The reason why we have option and non optional arrays, is because in the first rounds
        // it might be that parties do not submit broadcast of phase one. However, at some point of
        // the game, when handling qualified members, we need to ensure that there is a broadcast of
        // phase 1
        // todo: we are probably messing the indices somewhere. Really confusing.
        let optional_broadcasts_phase_1 = [
            Some(broad_1.clone()),
            Some(broad_2.clone()),
            Some(broad_3.clone()),
        ];

        // Fetched state of party 1
        let fetched_state_1 = MembersFetchedState1::from_broadcast(
            &environment,
            1,
            &[Some(broad_2.clone()), Some(broad_3.clone())],
        );

        // Fetched state of party 2
        let fetched_state_2 = MembersFetchedState1::from_broadcast(
            &environment,
            2,
            &[Some(broad_1.clone()), Some(broad_3.clone())],
        );

        // Fetched state of party 3
        let fetched_state_3 = MembersFetchedState1::from_broadcast(
            &environment,
            3,
            &[Some(broad_1.clone()), Some(broad_2.clone())],
        );

        // Now we proceed to phase two.
        let (party_1_phase_2, party_1_phase_2_broadcast_data) =
            m1.proceed(&fetched_state_1, &mut rng);
        let (party_2_phase_2, party_2_phase_2_broadcast_data) =
            m2.proceed(&fetched_state_2, &mut rng);
        let (party_3_phase_2, party_3_phase_2_broadcast_data) =
            m3.proceed(&fetched_state_3, &mut rng);

        if party_1_phase_2_broadcast_data.is_some()
            || party_2_phase_2_broadcast_data.is_some()
            || party_3_phase_2_broadcast_data.is_some()
        {
            // then they publish the data.
        }

        // We proceed to phase three (with no input because there was no misbehaving parties).
        let (party_1_phase_3, party_1_broadcast_data_3) = party_1_phase_2
            .unwrap()
            .proceed(&[], &optional_broadcasts_phase_1);
        let (_party_2_phase_3, _) = party_2_phase_2
            .unwrap()
            .proceed(&[], &optional_broadcasts_phase_1);
        let (party_3_phase_3, party_3_broadcast_data_3) = party_3_phase_2
            .unwrap()
            .proceed(&[], &optional_broadcasts_phase_1);

        // We mimic that party 2 misbehaves and doesn't broadcast data.
        let party_2_broadcast_data_3 = None;

        // Parties broadcast data
        let broadcasts_phase_3 = [
            &party_1_broadcast_data_3,
            &party_2_broadcast_data_3,
            &party_3_broadcast_data_3,
        ];

        // Fetched state of party 1.
        let fetched_state_1_phase_3 = MembersFetchedState3::from_broadcast(
            &environment,
            1,
            &[
                party_2_broadcast_data_3.clone(),
                party_3_broadcast_data_3.clone(),
            ],
        );

        // Fetched state of party 3.
        let fetched_state_3_phase_3 = MembersFetchedState3::from_broadcast(
            &environment,
            3,
            &[
                party_1_broadcast_data_3.clone(),
                party_2_broadcast_data_3.clone(),
            ],
        );

        // We proceed to phase four with the fetched state of the previous phase.
        let (party_1_phase_4, party_1_broadcast_data_4) =
            party_1_phase_3.unwrap().proceed(&fetched_state_1_phase_3);
        let (party_3_phase_4, party_3_broadcast_data_4) =
            party_3_phase_3.unwrap().proceed(&fetched_state_3_phase_3);

        // Given that party 2 misbehaved, party one and three publish a complaint.
        assert!(party_1_broadcast_data_4.is_some());
        assert!(party_3_broadcast_data_4.is_some());

        // Party 1 and 3 fetches it.
        let fetched_state_1_phase_4 = MembersFetchedState4::from_broadcast(
            &environment,
            1,
            &[None, party_3_broadcast_data_4],
        );

        let fetched_state_3_phase_4 = MembersFetchedState4::from_broadcast(
            &environment,
            3,
            &[party_1_broadcast_data_4, None],
        );

        // Then, party 1 and 3 need to fetch the complaint, use the broadcast data of party_2 from
        // phase 1 and phase 3, and verify the complaint.
        let fetched_complaints_1_phase_4 = FetchedMisbehaviourComplaints::from_broadcasts_4(
            &fetched_state_3_phase_4,
            &broadcasts_phase_1,
            &broadcasts_phase_3,
        );

        let fetched_complaints_3_phase_4 = FetchedMisbehaviourComplaints::from_broadcasts_4(
            &fetched_state_1_phase_4,
            &broadcasts_phase_1,
            &broadcasts_phase_3,
        );

        // Now we proceed to phase five, where we disclose the shares of the qualified, misbehaving
        // parties. Party 2 is no longer part of the protocol (even if its share will be part of the
        // master key).
        let (party_1_phase_5, party_1_broadcast_data_5) = party_1_phase_4
            .unwrap()
            .proceed(&fetched_complaints_1_phase_4);
        let (party_3_phase_5, party_3_broadcast_data_5) = party_3_phase_4
            .unwrap()
            .proceed(&fetched_complaints_3_phase_4);

        // at which point, the party 1 and 3 should broadcast the shares of party 2
        assert!(party_1_broadcast_data_5.is_some());
        assert!(party_3_broadcast_data_5.is_some());

        // This data is fetched by both parties
        let fetched_data_1_phase_5 = MembersFetchedState5::from_broadcast(
            &environment,
            1,
            &[None, party_3_broadcast_data_5],
        );

        let fetched_data_3_phase_5 = MembersFetchedState5::from_broadcast(
            &environment,
            3,
            &[party_1_broadcast_data_5, None],
        );

        // Finally, the different parties generate the master public key. To recreate the shares
        // of party two, they need to input the broadcast data.
        let (mk_1, sk_1) = party_1_phase_5
            .unwrap()
            .finalise(&fetched_data_1_phase_5)
            .unwrap();
        let (mk_3, sk_3) = party_3_phase_5
            .unwrap()
            .finalise(&fetched_data_3_phase_5)
            .unwrap();

        assert_eq!(mk_1, mk_3);

        // And finally, lets test if the lagrange interpolation of two secret shares resconstructs
        // the full secret key.
        let indices = [Scalar::from_u64(1), Scalar::from_u64(3)];
        let evaluated_points = [sk_1.0.sk, sk_3.0.sk];

        let master_key = lagrange_interpolation(Scalar::zero(), &evaluated_points, &indices);
        let interpolated_mk = MasterPublicKey(PublicKey {
            pk: RistrettoPoint::generator() * master_key,
        });

        assert_eq!(interpolated_mk, mk_1);
    }

    fn full_run() -> Result<(), DkgError> {
        let mut rng = OsRng;

        let shared_string = b"Example of a shared string.".to_owned();

        let threshold = 1;
        let nr_members = 3;
        let environment = Environment::init(threshold, nr_members, &shared_string);

        let mc1 = MemberCommunicationKey::<RistrettoPoint>::new(&mut rng);
        let mc2 = MemberCommunicationKey::<RistrettoPoint>::new(&mut rng);
        let mc3 = MemberCommunicationKey::<RistrettoPoint>::new(&mut rng);
        let mc = [mc1.to_public(), mc2.to_public(), mc3.to_public()];

        let (m1, broad_1) =
            DistributedKeyGeneration::<RistrettoPoint>::init(&mut rng, &environment, &mc1, &mc);
        let (m2, broad_2) =
            DistributedKeyGeneration::<RistrettoPoint>::init(&mut rng, &environment, &mc2, &mc);
        let (m3, broad_3) =
            DistributedKeyGeneration::<RistrettoPoint>::init(&mut rng, &environment, &mc3, &mc);

        let optional_broadcasts_phase_1 = [
            Some(broad_1.clone()),
            Some(broad_2.clone()),
            Some(broad_3.clone()),
        ];

        // Parties 1, 2, and 3 publish broad_1, broad_2, and broad_3 respectively in the
        // blockchain. All parties fetched the data.

        // Fetched state of party 1
        let fetched_state_1 = MembersFetchedState1::from_broadcast(
            &environment,
            1,
            &[Some(broad_2.clone()), Some(broad_3.clone())],
        );

        // Fetched state of party 2
        let fetched_state_2 = MembersFetchedState1::from_broadcast(
            &environment,
            2,
            &[Some(broad_1.clone()), Some(broad_3)],
        );

        // Fetched state of party 3
        let fetched_state_3 =
            MembersFetchedState1::from_broadcast(&environment, 3, &[Some(broad_1), Some(broad_2)]);

        // Now we proceed to phase two.
        let (party_1_phase_2, party_1_phase_2_broadcast_data) =
            m1.proceed(&fetched_state_1, &mut rng);
        let (party_2_phase_2, party_2_phase_2_broadcast_data) =
            m2.proceed(&fetched_state_2, &mut rng);
        let (party_3_phase_2, party_3_phase_2_broadcast_data) =
            m3.proceed(&fetched_state_3, &mut rng);

        if party_1_phase_2_broadcast_data.is_some()
            || party_2_phase_2_broadcast_data.is_some()
            || party_3_phase_2_broadcast_data.is_some()
        {
            // then they publish the data.
        }

        // We proceed to phase three (with no input because there was no misbehaving parties).
        let (party_1_phase_3, party_1_broadcast_data_3) =
            party_1_phase_2?.proceed(&[], &optional_broadcasts_phase_1);
        let (party_2_phase_3, party_2_broadcast_data_3) =
            party_2_phase_2?.proceed(&[], &optional_broadcasts_phase_1);
        let (party_3_phase_3, party_3_broadcast_data_3) =
            party_3_phase_2?.proceed(&[], &optional_broadcasts_phase_1);

        // Fetched state of party 1.
        let fetched_state_1_phase_3 = MembersFetchedState3::from_broadcast(
            &environment,
            1,
            &[
                party_2_broadcast_data_3.clone(),
                party_3_broadcast_data_3.clone(),
            ],
        );

        // Fetched state of party 2.
        let fetched_state_2_phase_3 = MembersFetchedState3::from_broadcast(
            &environment,
            2,
            &[party_1_broadcast_data_3.clone(), party_3_broadcast_data_3],
        );

        // Fetched state of party 3.
        let fetched_state_3_phase_3 = MembersFetchedState3::from_broadcast(
            &environment,
            3,
            &[party_1_broadcast_data_3, party_2_broadcast_data_3],
        );

        // We proceed to phase four with the fetched state of the previous phase.
        let (party_1_phase_4, _party_1_broadcast_data_4) =
            party_1_phase_3?.proceed(&fetched_state_1_phase_3);
        let (party_2_phase_4, _party_2_broadcast_data_4) =
            party_2_phase_3?.proceed(&fetched_state_2_phase_3);
        let (party_3_phase_4, _party_3_broadcast_data_4) =
            party_3_phase_3?.proceed(&fetched_state_3_phase_3);

        // Now we proceed to phase five, where we disclose the shares of the qualified, misbehaving
        // parties. There is no misbehaving parties, so broadcast of phase 4 is None.
        let (party_1_phase_5, _party_1_broadcast_data_5) = party_1_phase_4?.proceed(&[]);
        let (party_2_phase_5, _party_2_broadcast_data_5) = party_2_phase_4?.proceed(&[]);
        let (party_3_phase_5, _party_3_broadcast_data_5) = party_3_phase_4?.proceed(&[]);

        // Finally, the different parties generate the master public key. No misbehaving parties, so
        // broadcast of phase 5 is None.
        let (mk_1, sk_1) = party_1_phase_5?.finalise(&[])?;
        let (mk_2, sk_2) = party_2_phase_5?.finalise(&[])?;
        let (mk_3, _sk_3) = party_3_phase_5?.finalise(&[])?;

        if mk_1 != mk_2 || mk_2 != mk_3 {
            return Err(DkgError::InconsistentMasterKey);
        }

        // And finally, lets test if the lagrange interpolation of two secret shares resconstructs
        // the full secret key.
        let indices = [Scalar::from_u64(1), Scalar::from_u64(2)];
        let evaluated_points = [sk_1.0.sk, sk_2.0.sk];

        let master_key = lagrange_interpolation(Scalar::zero(), &evaluated_points, &indices);
        let interpolated_mk = MasterPublicKey(PublicKey {
            pk: RistrettoPoint::generator() * master_key,
        });

        assert_eq!(interpolated_mk, mk_1);

        Ok(())
    }
    #[test]
    fn full_valid_run() {
        let run: Result<(), DkgError> = full_run();

        assert!(run.is_ok());
    }

    fn simpler_API_full_run() -> Result<(), DkgError> {
        let mut rng = OsRng;

        let shared_string = b"Example of a shared string.".to_owned();

        let threshold = 1;
        let nr_members = 3;
        let environment = Environment::init(threshold, nr_members, &shared_string);

        let mc1 = MemberCommunicationKey::<RistrettoPoint>::new(&mut rng);
        let mc2 = MemberCommunicationKey::<RistrettoPoint>::new(&mut rng);
        let mc3 = MemberCommunicationKey::<RistrettoPoint>::new(&mut rng);
        let mc = [mc1.to_public(), mc2.to_public(), mc3.to_public()];

        let (m1, broad_1) =
            DistributedKeyGeneration::<RistrettoPoint>::init(&mut rng, &environment, &mc1, &mc);
        let (m2, broad_2) =
            DistributedKeyGeneration::<RistrettoPoint>::init(&mut rng, &environment, &mc2, &mc);
        let (m3, broad_3) =
            DistributedKeyGeneration::<RistrettoPoint>::init(&mut rng, &environment, &mc3, &mc);

        let broadcasts_phase_1 = [&broad_1, &broad_2, &broad_3];

        let optional_broadcasts_phase_1 = [
            Some(broad_1.clone()),
            Some(broad_2.clone()),
            Some(broad_3.clone()),
        ];

        // Parties 1, 2, and 3 publish broad_1, broad_2, and broad_3 respectively in the
        // blockchain. All parties fetched the data from other parties and proceed to the
        // next round.
        let (party_1_phase_2, _party_1_phase_2_broadcast_data) =
            m1.proceed_with_broadcast(&[Some(broad_2.clone()), Some(broad_3.clone())], &mut rng);
        let (party_2_phase_2, _party_2_phase_2_broadcast_data) =
            m2.proceed_with_broadcast(&[Some(broad_1.clone()), Some(broad_3.clone())], &mut rng);
        let (party_3_phase_2, _party_3_phase_2_broadcast_data) =
            m3.proceed_with_broadcast(&[Some(broad_1.clone()), Some(broad_2.clone())], &mut rng);

        // We proceed to phase three (with no input because there was no misbehaving parties).
        // todo: we want to input even if `None`.
        let (party_1_phase_3, party_1_broadcast_data_3) =
            party_1_phase_2?.proceed(&[], &optional_broadcasts_phase_1);
        let (party_2_phase_3, party_2_broadcast_data_3) =
            party_2_phase_2?.proceed(&[], &optional_broadcasts_phase_1);
        let (party_3_phase_3, party_3_broadcast_data_3) =
            party_3_phase_2?.proceed(&[], &optional_broadcasts_phase_1);

        // Parties broadcast data
        let broadcasts_phase_3 = [
            &party_1_broadcast_data_3,
            &party_2_broadcast_data_3,
            &party_3_broadcast_data_3,
        ];

        // We proceed to phase four with the fetched state of the previous phase.
        let (party_1_phase_4, party_1_broadcast_data_4) =
            party_1_phase_3?.proceed_with_broadcast(&[
                party_2_broadcast_data_3.clone(),
                party_3_broadcast_data_3.clone(),
            ]);
        let (party_2_phase_4, party_2_broadcast_data_4) =
            party_2_phase_3?.proceed_with_broadcast(&[
                party_1_broadcast_data_3.clone(),
                party_3_broadcast_data_3.clone(),
            ]);
        let (party_3_phase_4, party_3_broadcast_data_4) =
            party_3_phase_3?.proceed_with_broadcast(&[
                party_1_broadcast_data_3.clone(),
                party_2_broadcast_data_3.clone(),
            ]);

        // Now we proceed to phase five, where we disclose the shares of the qualified, misbehaving
        // parties. There is no misbehaving parties, so broadcast of phase 4 is None.
        let (party_1_phase_5, party_1_broadcast_data_5) = party_1_phase_4?.proceed_with_broadcast(
            &[
                party_2_broadcast_data_4.clone(),
                party_3_broadcast_data_4.clone(),
            ],
            &broadcasts_phase_1,
            &broadcasts_phase_3,
        );
        let (party_2_phase_5, party_2_broadcast_data_5) = party_2_phase_4?.proceed_with_broadcast(
            &[party_1_broadcast_data_4.clone(), party_3_broadcast_data_4],
            &broadcasts_phase_1,
            &broadcasts_phase_3,
        );
        let (party_3_phase_5, party_3_broadcast_data_5) = party_3_phase_4?.proceed_with_broadcast(
            &[party_1_broadcast_data_4, party_2_broadcast_data_4],
            &broadcasts_phase_1,
            &broadcasts_phase_3,
        );

        // Finally, the different parties generate the master public key. No misbehaving parties, so
        // broadcast of phase 5 is None.
        let (mk_1, sk_1) = party_1_phase_5?.finalise_with_broadcast(&[
            party_2_broadcast_data_5.clone(),
            party_3_broadcast_data_5.clone(),
        ])?;
        let (mk_2, sk_2) = party_2_phase_5?.finalise_with_broadcast(&[
            party_1_broadcast_data_5.clone(),
            party_3_broadcast_data_5.clone(),
        ])?;
        let (mk_3, _sk_3) = party_3_phase_5?.finalise_with_broadcast(&[
            party_1_broadcast_data_5.clone(),
            party_2_broadcast_data_5.clone(),
        ])?;

        if mk_1 != mk_2 || mk_2 != mk_3 {
            return Err(DkgError::InconsistentMasterKey);
        }

        // And finally, lets test if the lagrange interpolation of two secret shares resconstructs
        // the full secret key.
        let indices = [Scalar::from_u64(1), Scalar::from_u64(2)];
        let evaluated_points = [sk_1.0.sk, sk_2.0.sk];

        let master_key = lagrange_interpolation(Scalar::zero(), &evaluated_points, &indices);
        let interpolated_mk = MasterPublicKey(PublicKey {
            pk: RistrettoPoint::generator() * master_key,
        });

        assert_eq!(interpolated_mk, mk_1);

        Ok(())
    }

    #[test]
    fn simpler_API_run() {
        let run: Result<(), DkgError> = simpler_API_full_run();

        assert!(run.is_ok());
    }
}
