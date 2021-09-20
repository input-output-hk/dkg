//! Implementation of the distributed key generation (DKG)
//! procedure presented by [Gennaro], Jarecki, Krawczyk and Rabin in
//! "Secure distributed key generation for discrete-log based cryptosystems".
//! The distinction with the original protocol lies in the use of hybrid
//! encryption. We use the description and notation presented in the technical
//! [spec], written by Dmytro Kaidalov.
//!
//! We implement the distributed key generation procedure using the [typestate]
//! pattern, which enforces at API level the correct instantiation of the different
//! phases of the protocol. We define a structure `Phase` which stores the `state`
//! of the different phases and a phantom data type `PhantomData` to enforce the
//! distinction of the different phases. By using the `PhantomData`, we can bound
//! each different phase to its corresponding phase structure (e.g. `Phase1`). Then,
//! it phase has its corresponding associated function to proceed to the next phase
//! (e.g. `to_phase_2`), in such a way that only a valid instance of the current phase
//! can advance to the next. Every phase advance returns a tuple
//! `(Result<NewPhase, DkgError>, Option<BroadcastData>)`. The motivation for this
//! data structure is because the existense of `BroadcastData` does not necessarily
//! result in a valid `NewPhase`. There might be the case where we need to broadcast
//! `BroadcastData` but we have not successfully managed to proceed to the next phase.
//! However, the need to broadcast `BroadcastData` is not associated with a failing phase
//! as we might have a successful `NewPhase` while having to share some data.
//!
//! We now give an overview of the different phases of the
//! protocol, and proceed with a more detailed explanation in structure documentation.
//!
//! # Overview
//!
//! ## Round 1
//! Every party generates a random polynomial which is used to secret share their share
//! of the master public key. The coefficient of this polynomial are committed (with
//! some randomness) and published in the broadcast channel. Each share is sent with its
//! recipient by evaluating the polynomial at its corresponding (of the recipient) index,
//! and publishing in the broadcast channel the encryption under the recipient's public key.
//!
//! ## Round 2
//! Each party fetches their corresponding encrypted shares, together with the commitment
//! of the polynomials of other participants. Then, they proceed with the decryption of the
//! shares, and verify that they indeed correspond to the evaluation of the committed
//! polynomial at a given point. This can be done by leveraging the additive homomorphic
//! property of the commitment scheme. If this check fails, they post a complaint.
//!
//! ## Round 3
//! If there exists a valid complaint against one of the participants, the latter is
//! disqualified from the procedure. All qualified members post a commitment to their
//! coefficients. This time without any randomness.
//!
//! ## Round 4
//! Each qualified committee verifies that the non-randomised commitment is valid with
//! respected to the shares received in Round 1. Otherwise, it posts a complaint.
//!
//! ## Round 5
//! The master key is generated by adding the coefficients at position 0 (i.e. where the
//! polynomial evaluates at x = 0) of the polynomials of all qualified members. This can
//! be done again by exploiting the additive homomorphic property of the commitment
//! scheme.
//!
//! # Example
//!
//! ```rust
//! use DKG::dkg::{
//!     committee::{DistributedKeyGeneration, Environment},
//!     procedure_keys::MemberCommunicationKey,
//! };
//! use DKG::cryptography::commitment::CommitmentKey;
//! # use DKG::errors::DkgError;
//! use rand_core::OsRng;
//! use curve25519_dalek::ristretto::{RistrettoPoint};
//! # use DKG::dkg::fetched_state::{MembersFetchedState1, MembersFetchedState3};
//!
//! # fn full_run() -> Result<(), DkgError> {
//!         let mut rng = OsRng;
//!
//!         let shared_string = b"Example of a shared string.".to_owned();
//!         let threshold = 1;
//!         let nr_members = 3;
//!         let environment = Environment::init(threshold, nr_members, &shared_string);
//!
//!         let mc1 = MemberCommunicationKey::<RistrettoPoint>::new(&mut rng);
//!         let mc2 = MemberCommunicationKey::<RistrettoPoint>::new(&mut rng);
//!         let mc3 = MemberCommunicationKey::<RistrettoPoint>::new(&mut rng);
//!         let mc = [mc1.to_public(), mc2.to_public(), mc3.to_public()];
//!
//!         let (m1, broad_1) =
//!             DistributedKeyGeneration::<RistrettoPoint>::init(&mut rng, &environment, &mc1, &mc);
//!         let (m2, broad_2) =
//!             DistributedKeyGeneration::<RistrettoPoint>::init(&mut rng, &environment, &mc2, &mc);
//!         let (m3, broad_3) =
//!             DistributedKeyGeneration::<RistrettoPoint>::init(&mut rng, &environment, &mc3, &mc);
//!
//!         let m1_index = m1.get_index();
//!         let m2_index = m2.get_index();
//!         let m3_index = m3.get_index();
//!         // Parties 1, 2, and 3 publish broad_1, broad_2, and broad_3 respectively in the
//!         // blockchain. All parties fetched the data.
//!         let mut broadcasts_phase_1 = [None, None, None];
//!         broadcasts_phase_1[m1_index - 1] = Some(broad_1.clone());
//!         broadcasts_phase_1[m2_index - 1] = Some(broad_2.clone());
//!         broadcasts_phase_1[m3_index - 1] = Some(broad_3.clone());
//!
//!         // Parties 1, 2, and 3 publish broad_1, broad_2, and broad_3 respectively in the
//!         // blockchain. All parties fetched the data from other parties and proceed to the
//!         // next round.
//!         let (party_1_phase_2, _party_1_phase_2_broadcast_data) = m1.proceed_with_broadcast(
//!             &[mc[1].clone(), mc[2].clone()],
//!             &[Some(broad_2.clone()), Some(broad_3.clone())],
//!             &mut rng,
//!         );
//!         let (party_2_phase_2, _party_2_phase_2_broadcast_data) = m2.proceed_with_broadcast(
//!             &[mc[0].clone(), mc[2].clone()],
//!             &[Some(broad_1.clone()), Some(broad_3.clone())],
//!             &mut rng,
//!         );
//!         let (party_3_phase_2, _party_3_phase_2_broadcast_data) = m3.proceed_with_broadcast(
//!             &[mc[0].clone(), mc[1].clone()],
//!             &[Some(broad_1.clone()), Some(broad_2.clone())],
//!             &mut rng,
//!         );
//!
//!         // We proceed to phase three (with no input because there was no misbehaving parties).
//!         let (party_1_phase_3, party_1_broadcast_data_3) = party_1_phase_2?.proceed(&[], &broadcasts_phase_1);
//!         let (party_2_phase_3, party_2_broadcast_data_3) = party_2_phase_2?.proceed(&[], &broadcasts_phase_1);
//!         let (party_3_phase_3, party_3_broadcast_data_3) = party_3_phase_2?.proceed(&[], &broadcasts_phase_1);
//!
//!         // Parties broadcast data
//!         let mut broadcasts_phase_3 = [None, None, None];
//!         broadcasts_phase_3[m1_index - 1] = party_1_broadcast_data_3.clone();
//!         broadcasts_phase_3[m2_index - 1] = party_2_broadcast_data_3.clone();
//!         broadcasts_phase_3[m3_index - 1] = party_3_broadcast_data_3.clone();
//!
//!        // We proceed to phase four with the fetched state of the previous phase.
//!         let (party_1_phase_4, party_1_broadcast_data_4) = party_1_phase_3?.proceed_with_broadcast(
//!             &[mc[1].clone(), mc[2].clone()],
//!             &[
//!                 party_2_broadcast_data_3.clone(),
//!                 party_3_broadcast_data_3.clone(),
//!             ],
//!         );
//!         let (party_2_phase_4, party_2_broadcast_data_4) = party_2_phase_3?.proceed_with_broadcast(
//!             &[mc[0].clone(), mc[2].clone()],
//!             &[
//!                 party_1_broadcast_data_3.clone(),
//!                 party_3_broadcast_data_3.clone(),
//!             ],
//!         );
//!         let (party_3_phase_4, party_3_broadcast_data_4) = party_3_phase_3?.proceed_with_broadcast(
//!             &[mc[0].clone(), mc[1].clone()],
//!             &[
//!                 party_1_broadcast_data_3.clone(),
//!                 party_2_broadcast_data_3.clone(),
//!             ],
//!         );
//!
//!         // Now we proceed to phase five, where we disclose the shares of the qualified, misbehaving
//!         // parties. There is no misbehaving parties, so broadcast of phase 4 is None.
//!         let (party_1_phase_5, party_1_broadcast_data_5) = party_1_phase_4?.proceed_with_broadcast(
//!             &[mc[1].clone(), mc[2].clone()],
//!             &[
//!                 party_2_broadcast_data_4.clone(),
//!                 party_3_broadcast_data_4.clone(),
//!             ],
//!             &broadcasts_phase_1,
//!             &broadcasts_phase_3,
//!         );
//!         let (party_2_phase_5, party_2_broadcast_data_5) = party_2_phase_4?.proceed_with_broadcast(
//!             &[mc[0].clone(), mc[2].clone()],
//!             &[party_1_broadcast_data_4.clone(), party_3_broadcast_data_4],
//!             &broadcasts_phase_1,
//!             &broadcasts_phase_3,
//!         );
//!         let (party_3_phase_5, party_3_broadcast_data_5) = party_3_phase_4?.proceed_with_broadcast(
//!             &[mc[0].clone(), mc[1].clone()],
//!             &[party_1_broadcast_data_4, party_2_broadcast_data_4],
//!             &broadcasts_phase_1,
//!             &broadcasts_phase_3,
//!         );
//!
//!         // Finally, the different parties generate the master public key. No misbehaving parties, so
//!         // broadcast of phase 5 is None. This outputs the master public key and the secret shares.
//!         // All three mk_i are equal.
//!         let (mk_1, sk_1) = party_1_phase_5?.finalise(&[])?;
//!         let (mk_2, sk_2) = party_2_phase_5?.finalise(&[])?;
//!         let (mk_3, sk_3) = party_3_phase_5?.finalise(&[])?;
//!
//! #        if mk_1 != mk_2 || mk_2 != mk_3 {
//! #            return Err(DkgError::InconsistentMasterKey);
//! #        }
//! #
//! #        Ok(())
//! #    }
//! # fn main() { full_run().unwrap() }
//! ```
//!
//!
//! [Gennaro]: https://link.springer.com/article/10.1007/s00145-006-0347-3
//! [spec]: https://github.com/input-output-hk/treasury-crypto/blob/master/docs/voting_protocol_spec/Treasury_voting_protocol_spec.pdf
//! [typestate]: http://cliffle.com/blog/rust-typestate/

#![warn(unused, future_incompatible, nonstandard_style, rust_2018_idioms)]
#![allow(non_snake_case)]

#[macro_use]
mod macros;
pub mod cryptography;
pub mod dkg;
pub mod errors;
mod groups;
pub mod polynomial;
pub mod traits;
