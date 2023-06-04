use bincode;
use failure::Fail;

use crate::fault_log;
use crate::subset;
use crate::threshold_decrypt;

/// Dumbo error variants.
#[derive(Debug, Fail)]
pub enum Error {
    /// Failed to serialize contribution.
    #[fail(display = "Error serializing contribution: {}", _0)]
    ProposeBincode(bincode::ErrorKind),
    /// Failed to instantiate `Subset`.
    #[fail(display = "Failed to instantiate Subset: {}", _0)]
    CreateSubset(subset::Error),
    /// Failed to input contribution to `Subset`.
    #[fail(display = "Failed to input contribution to Subset: {}", _0)]
    InputSubset(subset::Error),
    /// Failed to handle `Subset` message.
    #[fail(display = "Failed to handle Subset message: {}", _0)]
    HandleSubsetMessage(subset::Error),
    /// Failed to decrypt a contribution.
    #[fail(display = "Threshold decryption error: {}", _0)]
    ThresholdDecrypt(threshold_decrypt::Error),
    /// Unknown sender
    #[fail(display = "Unknown sender")]
    UnknownSender,
}

/// The result of `Dumbo` handling an input or a message.
pub type Result<T> = ::std::result::Result<T, Error>;

/// Faults detectable from receiving Dumbo messages
#[derive(Clone, Debug, Fail, PartialEq)]
pub enum FaultKind {
    /// `Dumbo` received a decryption share for an unaccepted proposer.
    #[fail(display = "`Dumbo` received a decryption share for an unaccepted proposer.")]
    UnexpectedDecryptionShare,
    /// `Dumbo` was unable to deserialize a proposer's ciphertext.
    #[fail(display = "`Dumbo` was unable to deserialize a proposer's ciphertext.")]
    DeserializeCiphertext,
    /// `Dumbo` received an invalid ciphertext from the proposer.
    #[fail(display = "`Dumbo` received an invalid ciphertext from the proposer.")]
    InvalidCiphertext,
    /// `Dumbo` received a message with an invalid epoch.
    #[fail(display = "`Dumbo` received a message with an invalid epoch.")]
    UnexpectedHbMessageEpoch,
    /// `Dumbo` could not deserialize bytes (i.e. a serialized Batch) from a given proposer
    /// into a vector of transactions.
    #[fail(
        display = "`Dumbo` could not deserialize bytes (i.e. a serialized Batch) from a
                    given proposer into a vector of transactions."
    )]
    BatchDeserializationFailed,
    /// `Dumbo` received a fault from `Subset`.
    #[fail(display = "`Dumbo` received a fault from `Subset`.")]
    SubsetFault(subset::FaultKind),
    /// `Dumbo` received a fault from `ThresholdDecrypt`.
    #[fail(display = "`Dumbo` received a fault from `ThresholdDecrypt`.")]
    DecryptionFault(threshold_decrypt::FaultKind),
}

/// The type of fault log whose entries are `Dumbo` faults.
pub type FaultLog<N> = fault_log::FaultLog<N, FaultKind>;
