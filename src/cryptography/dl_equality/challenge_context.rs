use crate::traits::{PrimeGroupElement, Scalar};
use blake2::{Blake2b, Digest};

/// Challenge context for Discrete Logarithm Equality proof. The common reference string
/// are two EC bases, and the statement consists of two EC points.
/// The challenge computation takes as input the two announcements
/// computed in the sigma protocol, `a1` and `a2`, and the full
/// statement.
#[derive(Debug, Clone)]
pub struct ChallengeContext(Blake2b);

impl ChallengeContext {
    /// Initialise the challenge context, by including the common reference string and the full statement
    pub(crate) fn new<G: PrimeGroupElement>(
        base_1: &G,
        base_2: &G,
        point_1: &G,
        point_2: &G,
    ) -> Self {
        let mut ctx = Blake2b::new();
        ctx.update(&base_1.to_bytes());
        ctx.update(&base_2.to_bytes());
        ctx.update(&point_1.to_bytes());
        ctx.update(&point_2.to_bytes());

        ChallengeContext(ctx)
    }

    /// Generation of the `first_challenge`. This challenge is generated after the `Announcement` is
    /// "sent". Hence, we include the latter to the challenge context and generate its
    /// corresponding scalar.
    pub(crate) fn first_challenge<G: PrimeGroupElement>(
        &mut self,
        a1: &G,
        a2: &G,
    ) -> G::CorrespondingScalar {
        self.0.update(&a1.to_bytes());
        self.0.update(&a2.to_bytes());

        <G as PrimeGroupElement>::CorrespondingScalar::hash_to_scalar(self.clone().0)
    }
}
