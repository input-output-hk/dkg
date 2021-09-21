use crate::dkg::broadcast::{
    BroadcastPhase1, BroadcastPhase2, BroadcastPhase3, BroadcastPhase4, BroadcastPhase5,
    MisbehavingPartiesRound3,
};
use crate::dkg::committee::{EncryptedShares, Environment};
use crate::dkg::procedure_keys::MemberCommunicationPublicKey;
use crate::traits::PrimeGroupElement;

/// State of the members after round 1. This structure contains the indexed encrypted
/// shares of every other participant, `indexed_shares`, and the committed coefficients
/// of the generated polynomials, `committed_coeffs`.
#[derive(Clone)]
pub struct MembersFetchedState1<G: PrimeGroupElement> {
    pub(crate) sender_pk: MemberCommunicationPublicKey<G>,
    pub(crate) indexed_shares: Option<EncryptedShares<G>>,
    pub(crate) committed_coeffs: Option<Vec<G>>,
}

impl<G: PrimeGroupElement> MembersFetchedState1<G> {
    pub(crate) fn get_shares_and_coeffs(&self) -> (Option<EncryptedShares<G>>, Option<Vec<G>>) {
        (self.indexed_shares.clone(), self.committed_coeffs.clone())
    }
    /// Given as input all broadcast messages in an ordered vector, returns a vector of indexed
    /// fetched states. If some party does not broadcast in Round 1, then the entry should be
    /// filled with `None`. The broadcast messages must be ordered from low index to high index.
    pub fn from_broadcast(
        environment: &Environment<G>,
        recipient_index: usize,
        broadcaster_pks: &[MemberCommunicationPublicKey<G>],
        broadcast_messages: &[Option<BroadcastPhase1<G>>],
    ) -> Vec<Self> {
        // We should have broadcasters for ALL other participants
        assert_eq!(broadcast_messages.len(), broadcaster_pks.len());
        assert_eq!(broadcast_messages.len(), environment.nr_members - 1);

        let mut output = Vec::new();
        for (pk, message) in broadcaster_pks.iter().zip(broadcast_messages.iter()) {
            if let Some(broadcast_message) = message {
                // We first check that the party sent messages to all participants, and that
                // the number of committed coefficients corresponds with the expected degree of
                // the polynomial. If that is not the case, then no fetched data is recorded
                // for this party, and will disqualify it in the next round.
                if broadcast_message.committed_coefficients.len() != environment.threshold + 1
                    || broadcast_message.encrypted_shares.len() != environment.nr_members
                {
                    output.push(MembersFetchedState1 {
                        sender_pk: pk.clone(),
                        indexed_shares: None,
                        committed_coeffs: None,
                    });
                    continue;
                }

                output.push(MembersFetchedState1 {
                    sender_pk: pk.clone(),
                    indexed_shares: Some(
                        broadcast_message.encrypted_shares[recipient_index - 1].clone(),
                    ),
                    committed_coeffs: Some(broadcast_message.committed_coefficients.clone()),
                });
            } else {
                output.push(MembersFetchedState1 {
                    sender_pk: pk.clone(),
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
    pub(crate) sender_pk: MemberCommunicationPublicKey<G>,
    pub(crate) accusations: BroadcastPhase2<G>,
}

impl<G: PrimeGroupElement> MembersFetchedState2<G> {
    /// Given as input all broadcast messages in an ordered vector, returns a vector of indexed
    /// fetched states.
    pub fn from_broadcast(
        environment: &Environment<G>,
        recipient_index: usize,
        broadcaster_pks: &[MemberCommunicationPublicKey<G>],
        broadcast_messages: &[Option<BroadcastPhase2<G>>],
    ) -> Vec<Self> {
        // We should have broadcasters for ALL other participants
        assert!(recipient_index > 0 && recipient_index <= environment.nr_members);
        assert_eq!(broadcast_messages.len(), environment.nr_members - 1);

        let mut output = Vec::new();
        for (pk, message) in broadcaster_pks.iter().zip(broadcast_messages.iter()) {
            if let Some(broadcast_message) = message {
                output.push(MembersFetchedState2 {
                    sender_pk: pk.clone(),
                    accusations: broadcast_message.clone(),
                });
            }
        }
        output
    }
}

#[derive(Clone)]
pub struct MembersFetchedState3<G: PrimeGroupElement> {
    pub(crate) sender_pk: MemberCommunicationPublicKey<G>,
    /// Party might have not sent the value.
    pub(crate) committed_coefficients: Option<Vec<G>>,
}

impl<G: PrimeGroupElement> MembersFetchedState3<G> {
    /// The order of broadcast_messages needs to be from low to high index.
    /// todo: change this requirement.
    pub fn from_broadcast(
        environment: &Environment<G>,
        broadcaster_pks: &[MemberCommunicationPublicKey<G>],
        broadcast_messages: &[Option<BroadcastPhase3<G>>],
    ) -> Vec<Self> {
        // We should have broadcasters for ALL other participants
        assert_eq!(broadcast_messages.len(), environment.nr_members - 1);

        let mut output = Vec::new();
        for (pk, message) in broadcaster_pks.iter().zip(broadcast_messages.iter()) {
            if let Some(broadcast_message) = message {
                // We first check that the party sent messages to all participants, and that
                // the number of committed coefficients corresponds with the expected degree of
                // the polynomial. If that is not the case, then no fetched data is recorded
                // for this party, and will disqualify it in the next round.
                if broadcast_message.committed_coefficients.len() != environment.threshold + 1 {
                    output.push(MembersFetchedState3 {
                        sender_pk: pk.clone(),
                        committed_coefficients: None,
                    });
                    continue;
                }

                output.push(MembersFetchedState3 {
                    sender_pk: pk.clone(),
                    committed_coefficients: Some(broadcast_message.clone().committed_coefficients),
                });
            } else {
                output.push(MembersFetchedState3 {
                    sender_pk: pk.clone(),
                    committed_coefficients: None,
                })
            }
        }
        output
    }
}

#[derive(Clone)]
pub struct MembersFetchedState4<G: PrimeGroupElement> {
    pub(crate) sender_pk: MemberCommunicationPublicKey<G>,
    pub(crate) accusation: BroadcastPhase4<G>,
}

impl<G: PrimeGroupElement> MembersFetchedState4<G> {
    /// Takes as input the environment, and the broadcast messages of phase 4 together with the
    /// public keys. The order of the public keys and broadcast message must be consistent.
    pub fn from_broadcast(
        environment: &Environment<G>,
        broadcaster_pks: &[MemberCommunicationPublicKey<G>],
        broadcast_messages: &[Option<BroadcastPhase4<G>>],
    ) -> Vec<Self> {
        assert_eq!(broadcast_messages.len(), environment.nr_members - 1);

        let mut output = Vec::new();
        for (pk, message) in broadcaster_pks.iter().zip(broadcast_messages.iter()) {
            if let Some(broadcast_message) = message {
                output.push(Self {
                    sender_pk: pk.clone(),
                    accusation: broadcast_message.clone(),
                })
            }
        }
        output
    }
}

#[derive(Clone)]
pub struct MembersFetchedState5<G: PrimeGroupElement> {
    pub(crate) sender_pk: MemberCommunicationPublicKey<G>,
    pub(crate) disclosed_shares: BroadcastPhase5<G>,
}

impl<G: PrimeGroupElement> MembersFetchedState5<G> {
    pub fn from_broadcast(
        environment: &Environment<G>,
        broadcaster_pks: &[MemberCommunicationPublicKey<G>],
        broadcast_messages: &[Option<BroadcastPhase5<G>>],
    ) -> Vec<Self> {
        assert_eq!(broadcast_messages.len(), environment.nr_members - 1);

        let mut output = Vec::new();
        for (pk, message) in broadcaster_pks.iter().zip(broadcast_messages.iter()) {
            if let Some(broadcast_message) = message {
                output.push(Self {
                    sender_pk: pk.clone(),
                    disclosed_shares: broadcast_message.clone(),
                })
            }
        }
        output
    }
}

#[derive(Clone)]
pub struct FetchedMisbehaviourComplaints<G: PrimeGroupElement> {
    pub(crate) accuser_pk: MemberCommunicationPublicKey<G>,
    pub(crate) misbehaving_party: MisbehavingPartiesRound3<G>,
    pub(crate) accused_broadcast_phase_1: Option<BroadcastPhase1<G>>,
    pub(crate) accused_broadcast_phase_3: Option<BroadcastPhase3<G>>,
}

impl<'a, G: PrimeGroupElement> FetchedMisbehaviourComplaints<G> {
    /// `broadcasts_phase_1` and `broadcasts_phase_3` need to be vectors with entries for every
    /// other participant. If a participant did not broadcast data in a particular phase, then
    /// we need to define it with `None`.
    pub fn from_broadcasts_4(
        accusations: &[MembersFetchedState4<G>],
        // For qualified members, there should always be broadcast of phase 1. Otherwise the
        // party should not be qualified.
        broadcasts_phase_1: &[Option<BroadcastPhase1<G>>],
        // A qualified member might not broadcast in phase 3.
        broadcasts_phase_3: &[Option<BroadcastPhase3<G>>],
        // We need these to determine the index of each accused PK
        members_pks: &[MemberCommunicationPublicKey<G>],
    ) -> Vec<Self> {
        // todo: with capacity?
        let mut complaints = Vec::new();
        for grouped_accusation in accusations {
            for single_accusation in &grouped_accusation.accusation.misbehaving_parties {
                let accused_index = single_accusation.accused_pk.get_index(members_pks);
                complaints.push(FetchedMisbehaviourComplaints {
                    accuser_pk: grouped_accusation.sender_pk.clone(),
                    misbehaving_party: single_accusation.clone(),
                    accused_broadcast_phase_1: broadcasts_phase_1[accused_index - 1].clone(),
                    accused_broadcast_phase_3: broadcasts_phase_3[accused_index - 1].clone(),
                })
            }
        }
        complaints
    }
}
