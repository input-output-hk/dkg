use curve25519_dalek::ristretto::RistrettoPoint;
use dkg::dkg::committee::{DistributedKeyGeneration, Environment};
use dkg::dkg::fetched_state::{
    FetchedMisbehaviourComplaints, MembersFetchedState1, MembersFetchedState3,
    MembersFetchedState4, MembersFetchedState5,
};
use dkg::dkg::procedure_keys::MemberCommunicationKey;
use dkg::errors::DkgError;
use dkg::traits::PrimeGroupElement;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

#[test]
fn valid_phase_2() {
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);

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

    // Now, party one fetches the state of the other party, mainly party two. It fetches it
    // and links it with the sender pk.
    let fetched_state = MembersFetchedState1::from_broadcast(
        &environment,
        m1.get_index(),
        &[mc2.to_public()],
        &[Some(broadcast2)],
    );

    let phase_2 = m1.proceed(&fetched_state, &mut rng);
    if let Some(_data) = phase_2.1 {
        // broadcast the `data`
    }

    assert!(phase_2.0.is_ok());
}

#[test]
fn invalid_phase_2() {
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);

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

    let party_1_index = m1.get_index();
    // Now, party one fetches invalid state of the other parties, mainly party two and three
    broad_2.committed_coefficients = vec![PrimeGroupElement::zero(); threshold + 1];
    broad_3.committed_coefficients = vec![PrimeGroupElement::zero(); threshold + 1];

    let fetched_state = MembersFetchedState1::from_broadcast(
        &environment,
        m1.get_index(),
        &[mc[1].clone(), mc[2].clone()],
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
        .verify(&environment, party_1_index, &mc[0].clone(), &broad_2)
        .is_ok());

    assert!(complaint_2
        .verify(&environment, party_1_index, &mc[0].clone(), &broad_3)
        .is_ok());
}

#[test]
fn misbehaving_parties() {
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);

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
    let (m3, mut broad_3) =
        DistributedKeyGeneration::<RistrettoPoint>::init(&mut rng, &environment, &mc3, &mc);

    let party_1_index = m1.get_index();

    let broadcast_data_phase_1 = [
        Some(broad_1.clone()),
        Some(broad_2.clone()),
        Some(broad_3.clone()),
    ];

    // Now, party one fetches invalid state of a single party, mainly party three
    broad_3.committed_coefficients = vec![PrimeGroupElement::zero(); threshold + 1];
    let fetched_state = MembersFetchedState1::from_broadcast(
        &environment,
        m1.get_index(),
        &[mc[1].clone(), mc[2].clone()],
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
    assert_eq!(bd.misbehaving_parties[0].accused_pk, mc[2].clone());
    assert_eq!(
        bd.misbehaving_parties[0].accusation_error,
        DkgError::ShareValidityFailed
    );
    // and the complaint should be valid
    assert!(bd.misbehaving_parties[0]
        .verify(&environment, party_1_index, &mc[0].clone(), &broad_3)
        .is_ok());

    // The qualified set should have zero in the position of party 3. Note: to validate the
    // complaints, we need to input the broadcast data of phase 1.
    let (phase_3, _broadcast_data_3) = unwrapped_phase.proceed_with_broadcast(
        &[mc[1].clone(), mc[2].clone()],
        &[Some(bd), None],
        &broadcast_data_phase_1,
    );
    assert!(phase_3.is_ok());
    let mut expected_qualified_set = [1usize; 3];
    expected_qualified_set[m3.get_index() - 1] = 0;
    assert_eq!(phase_3.unwrap().get_qualified_set(), expected_qualified_set)
}

#[test]
fn phase_4_tests() {
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);

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
        m1.get_index(),
        &[mc[1].clone(), mc[2].clone()],
        &[Some(broad_2), Some(broad_3.clone())],
    );

    // Fetched state of party 2
    let fetched_state_2 = MembersFetchedState1::from_broadcast(
        &environment,
        m2.get_index(),
        &[mc[0].clone(), mc[2].clone()],
        &[Some(broad_1), Some(broad_3)],
    );

    // Now we proceed to phase two.
    let (party_1_phase_2, _party_1_phase_2_broadcast_data) = m1.proceed(&fetched_state_1, &mut rng);
    let (party_2_phase_2, _party_2_phase_2_broadcast_data) = m2.proceed(&fetched_state_2, &mut rng);

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
    let party_1_fetched_state_phase_3 = MembersFetchedState3::from_broadcast(
        &environment,
        &[mc[1].clone(), mc[2].clone()],
        &[party_2_broadcast_data_3, None],
    );

    // The protocol should finalise, given that we have two honest parties finalising the protocol
    // which is higher than the threshold
    assert!(party_1_phase_3
        .unwrap()
        .proceed(&party_1_fetched_state_phase_3)
        .0
        .is_ok());

    // If party three stops participating, and party 1 misbehaves, the protocol fails for party
    // 2, and there should be the proof of misbehaviour of party 1.
    let party_2_fetched_state_phase_3 = MembersFetchedState3::from_broadcast(
        &environment,
        &[mc[0].clone(), mc[2].clone()],
        &[None, None],
    );

    let failing_phase = party_2_phase_3
        .unwrap()
        .proceed(&party_2_fetched_state_phase_3);
    assert!(failing_phase.0.is_err());
    assert!(failing_phase.1.is_some());
}

#[test]
fn misbehaviour_phase_4() {
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);

    let shared_string = b"Example of a shared string.".to_owned();

    let threshold = 1;
    let nr_members = 3;
    let environment = Environment::init(threshold, nr_members, &shared_string);

    let mc1 = MemberCommunicationKey::<RistrettoPoint>::new(&mut rng);
    let mc2 = MemberCommunicationKey::<RistrettoPoint>::new(&mut rng);
    let mc3 = MemberCommunicationKey::<RistrettoPoint>::new(&mut rng);
    let mc = [mc1.to_public(), mc2.to_public(), mc3.to_public()];
    let mut ordered_pks = mc.clone();
    ordered_pks.sort();

    let (m1, broad_1) =
        DistributedKeyGeneration::<RistrettoPoint>::init(&mut rng, &environment, &mc1, &mc);
    let m1_index = m1.get_index();
    let (m2, broad_2) =
        DistributedKeyGeneration::<RistrettoPoint>::init(&mut rng, &environment, &mc2, &mc);
    let m2_index = m2.get_index();
    let (m3, broad_3) =
        DistributedKeyGeneration::<RistrettoPoint>::init(&mut rng, &environment, &mc3, &mc);
    let m3_index = m3.get_index();

    // Parties 1, 2, and 3 publish broad_1, broad_2, and broad_3 respectively in the
    // blockchain. All parties fetched the data.
    let mut broadcasts_phase_1 = [None, None, None];
    broadcasts_phase_1[m1_index - 1] = Some(broad_1.clone());
    broadcasts_phase_1[m2_index - 1] = Some(broad_2.clone());
    broadcasts_phase_1[m3_index - 1] = Some(broad_3.clone());

    // Fetched state of party 1
    let fetched_state_1 = MembersFetchedState1::from_broadcast(
        &environment,
        m1.get_index(),
        &[mc[1].clone(), mc[2].clone()],
        &[Some(broad_2.clone()), Some(broad_3.clone())],
    );

    // Fetched state of party 2
    let fetched_state_2 = MembersFetchedState1::from_broadcast(
        &environment,
        m2.get_index(),
        &[mc[0].clone(), mc[2].clone()],
        &[Some(broad_1.clone()), Some(broad_3.clone())],
    );

    // Fetched state of party 3
    let fetched_state_3 = MembersFetchedState1::from_broadcast(
        &environment,
        m3.get_index(),
        &[mc[0].clone(), mc[1].clone().clone()],
        &[Some(broad_1.clone()), Some(broad_2.clone())],
    );

    // Now we proceed to phase two.
    let (party_1_phase_2, party_1_phase_2_broadcast_data) = m1.proceed(&fetched_state_1, &mut rng);
    let (party_2_phase_2, party_2_phase_2_broadcast_data) = m2.proceed(&fetched_state_2, &mut rng);
    let (party_3_phase_2, party_3_phase_2_broadcast_data) = m3.proceed(&fetched_state_3, &mut rng);

    if party_1_phase_2_broadcast_data.is_some()
        || party_2_phase_2_broadcast_data.is_some()
        || party_3_phase_2_broadcast_data.is_some()
    {
        // then they publish the data.
    }

    // We proceed to phase three (with no input because there was no misbehaving parties).
    let (party_1_phase_3, party_1_broadcast_data_3) =
        party_1_phase_2.unwrap().proceed(&[], &broadcasts_phase_1);
    let (_party_2_phase_3, _) = party_2_phase_2.unwrap().proceed(&[], &broadcasts_phase_1);
    let (party_3_phase_3, party_3_broadcast_data_3) =
        party_3_phase_2.unwrap().proceed(&[], &broadcasts_phase_1);

    // We mimic that party 2 misbehaves and doesn't broadcast data.
    let party_2_broadcast_data_3 = None;

    // Parties broadcast data
    let mut broadcasts_phase_3 = [None, None, None];
    broadcasts_phase_3[m1_index - 1] = party_1_broadcast_data_3.clone();
    broadcasts_phase_3[m2_index - 1] = party_2_broadcast_data_3.clone();
    broadcasts_phase_3[m3_index - 1] = party_3_broadcast_data_3.clone();

    // Fetched state of party 1.
    let fetched_state_1_phase_3 = MembersFetchedState3::from_broadcast(
        &environment,
        &[mc[1].clone(), mc[2].clone()],
        &[
            party_2_broadcast_data_3.clone(),
            party_3_broadcast_data_3.clone(),
        ],
    );

    // Fetched state of party 3.
    let fetched_state_3_phase_3 = MembersFetchedState3::from_broadcast(
        &environment,
        &[mc[0].clone(), mc[1].clone()],
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
        &[mc[1].clone(), mc[2].clone()],
        &[None, party_3_broadcast_data_4],
    );

    let fetched_state_3_phase_4 = MembersFetchedState4::from_broadcast(
        &environment,
        &[mc[0].clone(), mc[1].clone()],
        &[party_1_broadcast_data_4, None],
    );

    // Then, party 1 and 3 need to fetch the complaint, use the broadcast data of party_2 from
    // phase 1 and phase 3, and verify the complaint.
    // Here we need an ordered list of pks because it is supposed to be an internal function
    let fetched_complaints_1_phase_4 = FetchedMisbehaviourComplaints::from_broadcasts_4(
        &fetched_state_1_phase_4,
        &broadcasts_phase_1,
        &broadcasts_phase_3,
        &ordered_pks,
    );

    let fetched_complaints_3_phase_4 = FetchedMisbehaviourComplaints::from_broadcasts_4(
        &fetched_state_3_phase_4,
        &broadcasts_phase_1,
        &broadcasts_phase_3,
        &ordered_pks,
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
        &[mc[1].clone(), mc[2].clone()],
        &[None, party_3_broadcast_data_5],
    );

    let fetched_data_3_phase_5 = MembersFetchedState5::from_broadcast(
        &environment,
        &[mc[0].clone(), mc[1].clone()],
        &[party_1_broadcast_data_5, None],
    );

    // Finally, the different parties generate the master public key. To recreate the shares
    // of party two, they need to input the broadcast data.
    let (mk_1, _sk_1) = party_1_phase_5
        .unwrap()
        .finalise(&fetched_data_1_phase_5)
        .unwrap();
    let (mk_3, _sk_3) = party_3_phase_5
        .unwrap()
        .finalise(&fetched_data_3_phase_5)
        .unwrap();

    assert_eq!(mk_1, mk_3);

    // // And finally, lets test if the lagrange interpolation of two secret shares resconstructs
    // // the full secret key.
    // let indices = [
    //     Scalar::from_u64(m1_index as u64),
    //     Scalar::from_u64(m3_index as u64),
    // ];
    // let evaluated_points = [sk_1.0.sk, sk_3.0.sk];
    //
    // let master_key = lagrange_interpolation(Scalar::zero(), &evaluated_points, &indices);
    // let interpolated_mk = MasterPublicKey(PublicKey {
    //     pk: RistrettoPoint::generator() * master_key,
    // });
    //
    // assert_eq!(interpolated_mk, mk_1);
}

fn full_run() -> Result<(), DkgError> {
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);

    let shared_string = b"Example of a shared string.".to_owned();

    let threshold = 1;
    let nr_members = 3;
    let environment = Environment::init(threshold, nr_members, &shared_string);

    let mc1 = MemberCommunicationKey::<RistrettoPoint>::new(&mut rng);
    let mc2 = MemberCommunicationKey::<RistrettoPoint>::new(&mut rng);
    let mc3 = MemberCommunicationKey::<RistrettoPoint>::new(&mut rng);
    let mc = [mc1.to_public(), mc2.to_public(), mc3.to_public()];
    let mut ordered_pks = mc.clone();
    ordered_pks.sort();

    let (m1, broad_1) =
        DistributedKeyGeneration::<RistrettoPoint>::init(&mut rng, &environment, &mc1, &mc);
    let m1_index = m1.get_index();
    let (m2, broad_2) =
        DistributedKeyGeneration::<RistrettoPoint>::init(&mut rng, &environment, &mc2, &mc);
    let m2_index = m2.get_index();
    let (m3, broad_3) =
        DistributedKeyGeneration::<RistrettoPoint>::init(&mut rng, &environment, &mc3, &mc);
    let m3_index = m3.get_index();

    let mut broadcasts_phase_1 = [None, None, None];
    broadcasts_phase_1[m1_index - 1] = Some(broad_1.clone());
    broadcasts_phase_1[m2_index - 1] = Some(broad_2.clone());
    broadcasts_phase_1[m3_index - 1] = Some(broad_3.clone());

    // Parties 1, 2, and 3 publish broad_1, broad_2, and broad_3 respectively in the
    // blockchain. All parties fetched the data.

    // Fetched state of party 1
    let fetched_state_1 = MembersFetchedState1::from_broadcast(
        &environment,
        m1.get_index(),
        &[mc[1].clone(), mc[2].clone()],
        &[Some(broad_2.clone()), Some(broad_3.clone())],
    );

    // Fetched state of party 2
    let fetched_state_2 = MembersFetchedState1::from_broadcast(
        &environment,
        m2.get_index(),
        &[mc[0].clone(), mc[2].clone()],
        &[Some(broad_1.clone()), Some(broad_3)],
    );

    // Fetched state of party 3
    let fetched_state_3 = MembersFetchedState1::from_broadcast(
        &environment,
        m3.get_index(),
        &[mc[0].clone(), mc[1].clone()],
        &[Some(broad_1), Some(broad_2)],
    );

    // Now we proceed to phase two.
    let (party_1_phase_2, party_1_phase_2_broadcast_data) = m1.proceed(&fetched_state_1, &mut rng);
    let (party_2_phase_2, party_2_phase_2_broadcast_data) = m2.proceed(&fetched_state_2, &mut rng);
    let (party_3_phase_2, party_3_phase_2_broadcast_data) = m3.proceed(&fetched_state_3, &mut rng);

    if party_1_phase_2_broadcast_data.is_some()
        || party_2_phase_2_broadcast_data.is_some()
        || party_3_phase_2_broadcast_data.is_some()
    {
        // then they publish the data.
    }

    // We proceed to phase three (with no input because there was no misbehaving parties).
    let (party_1_phase_3, party_1_broadcast_data_3) =
        party_1_phase_2?.proceed(&[], &broadcasts_phase_1);
    let (party_2_phase_3, party_2_broadcast_data_3) =
        party_2_phase_2?.proceed(&[], &broadcasts_phase_1);
    let (party_3_phase_3, party_3_broadcast_data_3) =
        party_3_phase_2?.proceed(&[], &broadcasts_phase_1);

    // Fetched state of party 1.
    let fetched_state_1_phase_3 = MembersFetchedState3::from_broadcast(
        &environment,
        &[mc[1].clone(), mc[2].clone()],
        &[
            party_2_broadcast_data_3.clone(),
            party_3_broadcast_data_3.clone(),
        ],
    );

    // Fetched state of party 2.
    let fetched_state_2_phase_3 = MembersFetchedState3::from_broadcast(
        &environment,
        &[mc[0].clone(), mc[2].clone()],
        &[party_1_broadcast_data_3.clone(), party_3_broadcast_data_3],
    );

    // Fetched state of party 3.
    let fetched_state_3_phase_3 = MembersFetchedState3::from_broadcast(
        &environment,
        &[mc[0].clone(), mc[1].clone()],
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
    let (mk_1, _sk_1) = party_1_phase_5?.finalise(&[])?;
    let (mk_2, _sk_2) = party_2_phase_5?.finalise(&[])?;
    let (mk_3, _sk_3) = party_3_phase_5?.finalise(&[])?;

    if mk_1 != mk_2 || mk_2 != mk_3 {
        return Err(DkgError::InconsistentMasterKey);
    }

    // // And finally, lets test if the lagrange interpolation of two secret shares resconstructs
    // // the full secret key.
    // let indices = [
    //     Scalar::from_u64(m1_index as u64),
    //     Scalar::from_u64(m2_index as u64),
    // ];
    // let evaluated_points = [sk_1.0.sk, sk_2.0.sk];
    //
    // let master_key = lagrange_interpolation(Scalar::zero(), &evaluated_points, &indices);
    // let interpolated_mk = MasterPublicKey(PublicKey {
    //     pk: RistrettoPoint::generator() * master_key,
    // });
    //
    // assert_eq!(interpolated_mk, mk_1);

    Ok(())
}
#[test]
fn full_valid_run() {
    let run: Result<(), DkgError> = full_run();

    assert!(run.is_ok());
}

fn simpler_api_full_run() -> Result<(), DkgError> {
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);

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

    let m1_index = m1.get_index();
    let m2_index = m2.get_index();
    let m3_index = m3.get_index();

    let mut broadcasts_phase_1 = [None, None, None];
    broadcasts_phase_1[m1_index - 1] = Some(broad_1.clone());
    broadcasts_phase_1[m2_index - 1] = Some(broad_2.clone());
    broadcasts_phase_1[m3_index - 1] = Some(broad_3.clone());

    // Parties 1, 2, and 3 publish broad_1, broad_2, and broad_3 respectively in the
    // blockchain. All parties fetched the data from other parties and proceed to the
    // next round.
    let (party_1_phase_2, _party_1_phase_2_broadcast_data) = m1.proceed_with_broadcast(
        &[mc[1].clone(), mc[2].clone()],
        &[Some(broad_2.clone()), Some(broad_3.clone())],
        &mut rng,
    );
    let (party_2_phase_2, _party_2_phase_2_broadcast_data) = m2.proceed_with_broadcast(
        &[mc[0].clone(), mc[2].clone()],
        &[Some(broad_1.clone()), Some(broad_3.clone())],
        &mut rng,
    );
    let (party_3_phase_2, _party_3_phase_2_broadcast_data) = m3.proceed_with_broadcast(
        &[mc[0].clone(), mc[1].clone()],
        &[Some(broad_1.clone()), Some(broad_2.clone())],
        &mut rng,
    );

    // We proceed to phase three (with no input because there was no misbehaving parties).
    // todo: we want to input even if `None`.
    let (party_1_phase_3, party_1_broadcast_data_3) =
        party_1_phase_2?.proceed(&[], &broadcasts_phase_1);
    let (party_2_phase_3, party_2_broadcast_data_3) =
        party_2_phase_2?.proceed(&[], &broadcasts_phase_1);
    let (party_3_phase_3, party_3_broadcast_data_3) =
        party_3_phase_2?.proceed(&[], &broadcasts_phase_1);

    // Parties broadcast data
    let mut broadcasts_phase_3 = [None, None, None];
    broadcasts_phase_3[m1_index - 1] = party_1_broadcast_data_3.clone();
    broadcasts_phase_3[m2_index - 1] = party_2_broadcast_data_3.clone();
    broadcasts_phase_3[m3_index - 1] = party_3_broadcast_data_3.clone();

    // We proceed to phase four with the fetched state of the previous phase.
    let (party_1_phase_4, party_1_broadcast_data_4) = party_1_phase_3?.proceed_with_broadcast(
        &[mc[1].clone(), mc[2].clone()],
        &[
            party_2_broadcast_data_3.clone(),
            party_3_broadcast_data_3.clone(),
        ],
    );
    let (party_2_phase_4, party_2_broadcast_data_4) = party_2_phase_3?.proceed_with_broadcast(
        &[mc[0].clone(), mc[2].clone()],
        &[
            party_1_broadcast_data_3.clone(),
            party_3_broadcast_data_3.clone(),
        ],
    );
    let (party_3_phase_4, party_3_broadcast_data_4) = party_3_phase_3?.proceed_with_broadcast(
        &[mc[0].clone(), mc[1].clone()],
        &[
            party_1_broadcast_data_3.clone(),
            party_2_broadcast_data_3.clone(),
        ],
    );

    // Now we proceed to phase five, where we disclose the shares of the qualified, misbehaving
    // parties. There is no misbehaving parties, so broadcast of phase 4 is None.
    let (party_1_phase_5, party_1_broadcast_data_5) = party_1_phase_4?.proceed_with_broadcast(
        &[mc[1].clone(), mc[2].clone()],
        &[
            party_2_broadcast_data_4.clone(),
            party_3_broadcast_data_4.clone(),
        ],
        &broadcasts_phase_1,
        &broadcasts_phase_3,
    );
    let (party_2_phase_5, party_2_broadcast_data_5) = party_2_phase_4?.proceed_with_broadcast(
        &[mc[0].clone(), mc[2].clone()],
        &[party_1_broadcast_data_4.clone(), party_3_broadcast_data_4],
        &broadcasts_phase_1,
        &broadcasts_phase_3,
    );
    let (party_3_phase_5, party_3_broadcast_data_5) = party_3_phase_4?.proceed_with_broadcast(
        &[mc[0].clone(), mc[1].clone()],
        &[party_1_broadcast_data_4, party_2_broadcast_data_4],
        &broadcasts_phase_1,
        &broadcasts_phase_3,
    );

    // Finally, the different parties generate the master public key. No misbehaving parties, so
    // broadcast of phase 5 is None.
    let (mk_1, _sk_1) = party_1_phase_5?.finalise_with_broadcast(
        &[mc[1].clone(), mc[2].clone()],
        &[
            party_2_broadcast_data_5.clone(),
            party_3_broadcast_data_5.clone(),
        ],
    )?;
    let (mk_2, _sk_2) = party_2_phase_5?.finalise_with_broadcast(
        &[mc[0].clone(), mc[2].clone()],
        &[
            party_1_broadcast_data_5.clone(),
            party_3_broadcast_data_5.clone(),
        ],
    )?;
    let (mk_3, _sk_3) = party_3_phase_5?.finalise_with_broadcast(
        &[mc[0].clone(), mc[1].clone()],
        &[
            party_1_broadcast_data_5.clone(),
            party_2_broadcast_data_5.clone(),
        ],
    )?;

    if mk_1 != mk_2 || mk_2 != mk_3 {
        return Err(DkgError::InconsistentMasterKey);
    }

    // // And finally, lets test if the lagrange interpolation of two secret shares resconstructs
    // // the full secret key.
    // let indices = [
    //     Scalar::from_u64(m1_index as u64),
    //     Scalar::from_u64(m2_index as u64),
    // ];
    // let evaluated_points = [sk_1.0.sk, sk_2.0.sk];
    //
    // let master_key = lagrange_interpolation(Scalar::zero(), &evaluated_points, &indices);
    // let interpolated_mk = MasterPublicKey(PublicKey {
    //     pk: RistrettoPoint::generator() * master_key,
    // });
    //
    // assert_eq!(interpolated_mk, mk_1);

    Ok(())
}

#[test]
fn simpler_api_run() {
    let run: Result<(), DkgError> = simpler_api_full_run();

    assert!(run.is_ok());
}
