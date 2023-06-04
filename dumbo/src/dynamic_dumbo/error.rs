use bincode;
use failure::Fail;

use crate::dumbo;
use crate::sync_key_gen;

/// Dynamic dumbo error variants.
#[derive(Debug, Fail)]
pub enum Error {
    /// Failed to serialize a key generation message for signing.
    #[fail(display = "Error serializing a key gen message: {}", _0)]
    SerializeKeyGen(bincode::ErrorKind),
    /// Failed to serialize a vote for signing.
    #[fail(display = "Error serializing a vote: {}", _0)]
    SerializeVote(bincode::ErrorKind),
    /// Failed to propose a contribution in `Dumbo`.
    #[fail(display = "Error proposing a contribution in Dumbo: {}", _0)]
    ProposeDumbo(dumbo::Error),
    /// Failed to handle a `Dumbo` message.
    #[fail(display = "Error handling a Dumbo message: {}", _0)]
    HandleDumboMessage(dumbo::Error),
    /// Failed to handle a `SyncKeyGen` message.
    #[fail(display = "Error handling SyncKeyGen message: {}", _0)]
    SyncKeyGen(sync_key_gen::Error),
    /// Unknown sender
    #[fail(display = "Unknown sender")]
    UnknownSender,
}

/// The result of `DynamicDumbo` handling an input or message.
pub type Result<T> = ::std::result::Result<T, Error>;
/// Represents each way an an incoming message can be considered faulty.
#[derive(Clone, Debug, Fail, PartialEq)]
pub enum FaultKind {
    /// `DynamicDumbo` received a key generation message with an invalid signature.
    #[fail(
        display = "`DynamicDumbo` received a key generation message with an invalid signature."
    )]
    InvalidKeyGenMessageSignature,
    /// `DynamicDumbo` received a key generation message with an invalid era.
    #[fail(
        display = "`DynamicDumbo` received a key generation message with an invalid era."
    )]
    InvalidKeyGenMessageEra,
    /// `DynamicDumbo` received a key generation message when there was no key generation in
    /// progress.
    #[fail(
        display = "`DynamicDumbo` received a key generation message when there was no key
                    generation in progress."
    )]
    UnexpectedKeyGenMessage,
    /// `DynamicDumbo` received a signed `Ack` when no key generation in progress.
    #[fail(
        display = "`DynamicDumbo` received a signed `Ack` when no key generation in progress."
    )]
    UnexpectedKeyGenAck,
    /// `DynamicDumbo` received a signed `Part` when no key generation in progress.
    #[fail(
        display = "`DynamicDumbo` received a signed `Part` when no key generation in progress."
    )]
    UnexpectedKeyGenPart,
    /// `DynamicDumbo` received more key generation messages from the peer than expected.
    #[fail(
        display = "`DynamicDumbo` received more key generation messages from the peer than
                    expected."
    )]
    TooManyKeyGenMessages,
    /// `DynamicDumbo` received a message (Accept, Propose, or Change with an invalid
    /// signature.
    #[fail(
        display = "`DynamicDumbo` received a message (Accept, Propose, or Change
                       with an invalid signature."
    )]
    IncorrectPayloadSignature,
    /// `DynamicDumbo`/`SyncKeyGen` received an invalid `Ack` message.
    #[fail(display = "`DynamicDumbo`/`SyncKeyGen` received an invalid `Ack` message.")]
    SyncKeyGenAck(sync_key_gen::AckFault),
    /// `DynamicDumbo`/`SyncKeyGen` received an invalid `Part` message.
    #[fail(display = "`DynamicDumbo`/`SyncKeyGen` received an invalid `Part` message.")]
    SyncKeyGenPart(sync_key_gen::PartFault),
    /// `DynamicDumbo` received a change vote with an invalid signature.
    #[fail(display = "`DynamicDumbo` received a change vote with an invalid signature.")]
    InvalidVoteSignature,
    /// A validator committed an invalid vote in `DynamicDumbo`.
    #[fail(display = "A validator committed an invalid vote in `DynamicDumbo`.")]
    InvalidCommittedVote,
    /// `DynamicDumbo` received a message with an invalid era.
    #[fail(display = "`DynamicDumbo` received a message with an invalid era.")]
    UnexpectedDhbMessageEra,
    /// `DynamicDumbo` received a fault from `Dumbo`.
    #[fail(display = "`DynamicDumbo` received a fault from `Dumbo`.")]
    HbFault(dumbo::FaultKind),
}
