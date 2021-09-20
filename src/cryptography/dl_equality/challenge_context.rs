use crate::traits::{PrimeGroupElement, Scalar};
use blake2::Blake2b;

/// Challenge context for Discrete Logarithm Equality proof. The common reference string
/// are two EC bases, and the statement consists of two EC points.
/// The challenge computation takes as input the two announcements
/// computed in the sigma protocol, `a1` and `a2`, and the full
/// statement.
#[derive(Debug, Clone)]
pub struct ChallengeContext(Vec<u8>);

impl ChallengeContext {
    /// Initialise the challenge context, by including the common reference string and the full statement
    pub(crate) fn new<G: PrimeGroupElement>(
        base_1: &G,
        base_2: &G,
        point_1: &G,
        point_2: &G,
    ) -> Self
    where
        [(); G::SIZE]: ,
    {
        let mut ctx: Vec<u8> = Vec::new();
        ctx.extend_from_slice(&base_1.to_bytes());
        ctx.extend_from_slice(&base_2.to_bytes());
        ctx.extend_from_slice(&point_1.to_bytes());
        ctx.extend_from_slice(&point_2.to_bytes());

        ChallengeContext(ctx)
    }

    /// Generation of the `first_challenge`. This challenge is generated after the `Announcement` is
    /// "sent". Hence, we include the latter to the challenge context and generate its
    /// corresponding scalar.
    pub(crate) fn first_challenge<G: PrimeGroupElement>(
        &mut self,
        a1: &G,
        a2: &G,
    ) -> G::CorrespondingScalar
    where
        [(); G::SIZE]: ,
    {
        self.0.extend_from_slice(&a1.to_bytes());
        self.0.extend_from_slice(&a2.to_bytes());

        <G as PrimeGroupElement>::CorrespondingScalar::hash_to_scalar::<Blake2b>(&self.clone().0)
    }
}
