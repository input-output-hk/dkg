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
    /// This error occurs when a ZKP verification failed
    #[cfg_attr(deature = "std", error("ZKP verification failed"))]
    ZkpVerificationFailed,
    /// This error occurs when parsing a byte string which should represent a
    /// scalar, fails
    #[cfg_attr(feature = "std", error("Decoding bytes to Scalar failed."))]
    DecodingToScalarFailed,
    /// This error occurs when a user fetches data which is not indexed with
    /// its identifying index
    #[cfg_attr(feature = "std", error("Fetched wrong data"))]
    FetchedInvalidData,
    /// This error occurs when we try to recover a secret without having sufficient
    /// shares (i.e. a number of shares equal or higher than the threshold)
    #[cfg_attr(feature = "std", error("Insufficient shares for recovery of index {}"))]
    InsufficientSharesForRecovery(usize),
    /// This error occurs when the local master key generation is not consistent with the public
    /// state
    #[cfg_attr(feature = "std", error("Inconsistent master key generation"))]
    InconsistentMasterKey,
    /// This error occurs when a claim of misbehaviour does not validate due to a supposed
    /// match which does not hold.
    #[cfg_attr(
        feature = "std",
        error("Complaint verification failed. False claimed equality.")
    )]
    FalseClaimedEquality,
    /// This error occurs when a claim of misbehaviour does not validate due to a supposed
    /// inequality which does not hold.
    #[cfg_attr(
        feature = "std",
        error("Complaint verification failed. False claimed inequality")
    )]
    FalseClaimedInequality,
    /// This error occurs when a member included in the qualified set should have been
    /// dismissed earlier
    #[cfg_attr(
        feature = "std",
        error("User included in the qualified set should be dismissed")
    )]
    PartyShouldBeDisqualified,
    /// This error occurs when the public key of a party is not in the list of the members'
    /// public keys.
    #[cfg_attr(feature = "std", error("Public key not found"))]
    PublicKeyNotFound,
}

impl From<ProofError> for DkgError {
    fn from(_: ProofError) -> Self {
        DkgError::ZkpVerificationFailed
    }
}
