use std::fmt::{self, Debug};

use hex_fmt::HexFmt;
use rand::distributions::{Distribution, Standard};
use rand::{self, seq::SliceRandom, Rng};
use serde_derive::{Deserialize, Serialize};
use crate::threshold_sign::{self, Message as TsMessage, ThresholdSign, SignatureShare};
use super::merkle::{Digest, MerkleTree, Proof};

/// The three kinds of message sent during the reliable broadcast stage of the
/// consensus algorithm.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub enum Message {
    /// A share of the value, sent from the sender to another validator.
    Value(Proof<Vec<u8>>),
    /// A copy of the value received from the sender, multicast by a validator.
    Echo(TsMessage),
    /// Indicates that the sender knows that every node will eventually be able to decode.
    Ready(TsMessage),
}

#[derive(Debug)]
enum EchoState<N> {
    Enough(bool),
    InProgress(Box<ThresholdSign<N>>),
}

impl Debug for Message {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Message::Value(ref v) => f.debug_tuple("Value").field(&HexProof(v)).finish(),
            // 这里在最底层的Threshold库中已经有相关的fmt实现
            Message::Echo(ref v) => f,
            Message::Ready(ref b) => b,
        }
    }
}
/// Wrapper for a `Proof`, to print the bytes as a shortened hexadecimal number.
pub struct HexProof<'a, T: 'a>(pub &'a Proof<T>);

impl<'a, T: AsRef<[u8]>> fmt::Debug for HexProof<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Proof {{ #{}, root_hash: {:0.10}, value: {:0.10}, .. }}",
            &self.0.index(),
            HexFmt(self.0.root_hash()),
            HexFmt(self.0.value())
        )
    }
}
