/// Represents an error in zero knowlege proofs.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "std", derive(Error))]
pub enum ProofError {
    /// This error occurs when verification fails
    #[cfg_attr(feature = "std", error("ZKP verification failed"))]
    ZkpVerificationFailed,
}

/// Represents an error in Distributed Key Generation protocol.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "std", derive(Error))]
pub enum DkgError {
    /// This error occurs when a scalar parsing failed, due to the
    /// byte-array representing a scalar out of bounds.
    #[cfg_attr(feature = "std", error("Scalar out of bounds."))]
    ScalarOutOfBounds,
    /// This error occurs when the check of validity of the shares
    /// fails.
    #[cfg_attr(feature = "std", error("Share validity check failed."))]
    ShareValidityFailed,
    /// This error occurs when too many members misbehaved.
    #[cfg_attr(feature = "std", error("Misbehaviours higher than threshold."))]
    MisbehaviourHigherThreshold,
    /// This error occurs when an invalid proof of misbehaviour is detected
    #[cfg_attr(feature = "std", error("Invalid proof of misbehaviour."))]
    InvalidProofOfMisbehaviour,
}
