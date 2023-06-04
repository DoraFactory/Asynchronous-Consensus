use std::collections::BTreeMap;
use std::sync::Arc;
use std::{fmt, result};

use byteorder::{BigEndian, ByteOrder};
use hex_fmt::{HexFmt, HexList};
use log::{debug, warn};
use rand::Rng;
use reed_solomon_erasure as rse;
use reed_solomon_erasure::{galois_8::Field as Field8, ReedSolomon};

use super::merkle::{Digest, MerkleTree, Proof};
use super::message::HexProof;
use super::{Error, FaultKind, Message, Result};
use hbbft::fault_log::Fault;
use hbbft::{ConsensusProtocol, NetworkInfo, NodeIdT, Target};
// Used to PD and RC
use crate::threshold_sign::{self, Message as TsMessage, ThresholdSign};
use std::time::{SystemTime, UNIX_EPOCH};

type RseResult<T> = result::Result<T, rse::Error>;

/// Broadcast algorithm instance.
#[derive(Debug)]
pub struct Broadcast<N> {
    /// Shared network data.
    netinfo: Arc<NetworkInfo<N>>,
    /// The ID of the sending node.
    proposer_id: N,
    /// The Reed-Solomon erasure coding configuration.
    coding: Coding,
    /// If we are the proposer: whether we have already sent the `Value` messages with the shards.
    value_sent: bool,
    /// Whether we have already multicast `Echo`. 
    echo_sent: bool,
    /// Whether we have already multicast `Ready`.
    ready_sent: bool,
    /// Whether we have already output a value.
    decided: bool,
    /// The proofs we have received via `Echo` messages, by sender ID.
    echos: BTreeMap<N, TsMessage>,
    /// The root hashes we received via `Ready` messages, by sender ID.
    readys: BTreeMap<N, TsMessage>,
    //// Threshold sign
    threshold_sign: ThresholdSign<N>,
}

/// A `Broadcast` step, containing at most one output.
pub type Step<N> = crate::CpStep<Broadcast<N>>;

impl<N: NodeIdT> ConsensusProtocol for Broadcast<N> {
    type NodeId = N;
    type Input = Vec<u8>;
    type Output = Self::Input;
    type Message = Message;
    type Error = Error;
    type FaultKind = FaultKind;

    fn handle_input<R: Rng>(&mut self, input: Self::Input, _rng: &mut R) -> Result<Step<N>> {
        self.broadcast(input)
    }

    fn handle_message<R: Rng>(
        &mut self,
        sender_id: &Self::NodeId,
        message: Message,
        _rng: &mut R,
    ) -> Result<Step<N>> {
        self.handle_message(sender_id, message)
    }

    fn terminated(&self) -> bool {
        self.decided
    }

    fn our_id(&self) -> &N {
        self.netinfo.our_id()
    }
}

impl<N: NodeIdT> Broadcast<N> {
    /// Creates a new broadcast instance to be used by node `our_id` which expects a value proposal
    /// from node `proposer_id`.
    pub fn new(netinfo: Arc<NetworkInfo<N>>, proposer_id: N) -> Result<Self> {
        let parity_shard_num = 2 * netinfo.num_faulty();
        let data_shard_num = netinfo.num_nodes() - parity_shard_num;
        let coding =
            Coding::new(data_shard_num, parity_shard_num).map_err(|_| Error::InvalidNodeCount)?;

        Ok(Broadcast {
            netinfo,
            proposer_id,
            coding,
            value_sent: false,
            echo_sent: false,
            ready_sent: false,
            decided: false,
            echos: BTreeMap::new(),
            readys: BTreeMap::new(),
            threshold_sign: ThresholdSign::new(netinfo),
        })
    }

    /// Initiates the broadcast. This must only be called in the proposer node.
    pub fn broadcast(&mut self, input: Vec<u8>) -> Result<Step<N>> {
        if *self.our_id() != self.proposer_id {
            return Err(Error::InstanceCannotPropose);
        }
        if self.value_sent {
            return Err(Error::MultipleInputs);
        }
        self.value_sent = true;
        // Split the value into chunks/shards, encode them with erasure codes.
        // Assemble a Merkle tree from data and parity shards. Take all proofs
        // from this tree and send them, each to its own node.
        let (proof, step) = self.send_shards(input)?;
        let our_id = &self.our_id().clone();

        Ok(step.join(self.handle_value(our_id, proof)?))
    }

    /// Handles a message received from `sender_id`.
    ///
    /// This must be called with every message we receive from another node.
    pub fn handle_message(&mut self, sender_id: &N, message: Message) -> Result<Step<N>> {
        if !self.netinfo.is_node_validator(sender_id) {
            return Err(Error::UnknownSender);
        }
        match message {
            Message::Value(p, ts) => self.handle_value(sender_id, p),
            Message::Echo(ts) => self.handle_echo(sender_id, ts),
            Message::Ready(ref ts) => self.handle_ready(sender_id, ts),
        }
    }

    /// Returns the proposer's node ID.
    pub fn proposer_id(&self) -> &N {
        &self.proposer_id
    }

    /// Breaks the input value into shards of equal length and encodes them --
    /// and some extra parity shards -- with a Reed-Solomon erasure coding
    /// scheme. The returned value contains the shard assigned to this
    /// node. That shard doesn't need to be sent anywhere. It gets recorded in
    /// the broadcast instance.
    fn send_shards(&mut self, mut value: Vec<u8>) -> Result<(Proof<Vec<u8>>, Step<N>)> {
        let data_shard_num = self.coding.data_shard_count();
        let parity_shard_num = self.coding.parity_shard_count();

        // Insert the length of `v` so it can be decoded without the padding.
        let payload_len = value.len() as u32;
        value.splice(0..0, 0..4); // Insert four bytes at the beginning.
        BigEndian::write_u32(&mut value[..4], payload_len); // Write the size.
        let value_len = value.len(); // This is at least 4 now, due to the payload length.

        // Size of a Merkle tree leaf value: the value size divided by the number of data shards,
        // and rounded up, so that the full value always fits in the data shards. Always at least 1.
        let shard_len = (value_len + data_shard_num - 1) / data_shard_num;
        // Pad the last data shard with zeros. Fill the parity shards with zeros.
        value.resize(shard_len * (data_shard_num + parity_shard_num), 0);

        // Divide the vector into chunks/shards.
        let shards_iter = value.chunks_mut(shard_len);
        // Convert the iterator over slices into a vector of slices.
        let mut shards: Vec<&mut [u8]> = shards_iter.collect();

        // Construct the parity chunks/shards. This only fails if a shard is empty or the shards
        // have different sizes. Our shards all have size `shard_len`, which is at least 1.
        self.coding.encode(&mut shards).expect("wrong shard size");

        debug!(
            "{}: Value: {} bytes, {} per shard. Shards: {:0.10}",
            self,
            value_len,
            shard_len,
            HexList(&shards)
        );

        // Create a Merkle tree from the shards.
        let mtree = MerkleTree::from_vec(shards.into_iter().map(|shard| shard.to_vec()).collect());

        // Default result in case of `proof` error.
        let mut result = Err(Error::ProofConstructionFailed);
        assert_eq!(self.netinfo.num_nodes(), mtree.values().len());

        let mut step = Step::default();
        // Send each proof to a node.
        for (index, id) in self.netinfo.all_ids().enumerate() {
            let proof = mtree.proof(index).ok_or(Error::ProofConstructionFailed)?;
            if *id == *self.our_id() {
                // The proof is addressed to this node.
                result = Ok(proof);
            } else {
                // Rest of the proofs are sent to remote nodes.
                let msg = Target::Node(id.clone()).message(Message::Value(proof));
                step.messages.push(msg);
            }
        }

        result.map(|proof| (proof, step))
    }

    /// Handles a received echo and verifies the proof it contains.
    /// 处理直接发送过来的echo消息，这个消息是来自子块的分割者
    fn handle_value(&mut self, sender_id: &N, p: Proof<Vec<u8>>) -> Result<Step<N>> {
        // If the sender is not the proposer or if this is not the first `Value`, ignore.
        if *sender_id != self.proposer_id {
            let fault_kind = FaultKind::ReceivedValueFromNonProposer;
            return Ok(Fault::new(sender_id.clone(), fault_kind).into());
        }
        if self.echo_sent {
            if self.echos.get(self.our_id()) == Some(&p) {
                warn!(
                    "Node {:?} received Value({:?}) multiple times from {:?}.",
                    self.our_id(),
                    HexProof(&p),
                    sender_id
                );
                return Ok(Step::default());
            } else {
                return Ok(Fault::new(sender_id.clone(), FaultKind::MultipleValues).into());
            }
        }

        // If the proof is invalid, log the faulty node behavior and ignore.
        if !self.validate_proof(&p, &self.our_id()) {
            return Ok(Fault::new(sender_id.clone(), FaultKind::InvalidProof).into());
        }

        // 节点j,在收到节点i发送过来的分割碎片时，先验证，验证完之后，需要对节点i的id进行阈值签名
        self.threshold_sign.set_document(sender_id.clone());
        let threshold_sign_step = self.threshold_sign.sign(sender_id).map_err(Error::PrbcThresholdSignErr)?;

        // Node j Send threshold signture share to share's sender(Node i)
        self.send_echo(sender_id, ts).join(threshold_sign_step)
    }

    /// Handles a received `Echo` message.
    /// 这个是Node i用来处理Node j发送回的echo消息的
    fn handle_echo(&mut self, sender_id: &N, ts_msg: TsMessage) -> Result<Step<N>> {
        // If the sender has already sent `Echo`, ignore.
        if let Some(old_ts_msg) = self.echos.get(sender_id) {
            if *old_ts_msg == ts_msg {
                warn!(
                    "Node {:?} received Echo({:?}) multiple times from {:?}.",
                    self.our_id(),
                    ts_msg,
                    sender_id,
                );
                return Ok(Step::default());
            } else {
                return Ok(Fault::new(sender_id.clone(), FaultKind::MultipleEchos).into());
            }
        }

        // Save the threshold signature shares
        self.echos.insert(sender_id.clone(), ts_msg);

        // 如果收到的echo消息数量不够，继续收集，不做操作
        if self.count_echos(&ts_msg) < self.netinfo.num_correct() {
            Ok(Step::default());
        }

        // Upon receiving `N - f` `Echo`s with threshold signature shares
        // Aggregate threshold shares to a threshold signature as a Ready msg
        // multicast `Ready`.

        // Aggregate
        let aggregate_echo_signature = self.threshold_sign.handle_message(sender_id, ts_msg);

        // send Ready
        self.send_ready(&aggregate_echo_signature)
    }


    /// Handles a received `Ready` message.
    /// Ready消息需要组装为一个列表！！！
    fn handle_ready(&mut self, sender_id: &N, hash: &TsMessage) -> Result<Step<N>> {
        // If the sender has already sent a `Ready` before, ignore.
        if let Some(old_hash) = self.readys.get(sender_id) {
            if old_hash == hash {
                warn!(
                    "Node {:?} received Ready({:?}) multiple times from {:?}.",
                    self.our_id(),
                    hash,
                    sender_id
                );
                return Ok(Step::default());
            } else {
                return Ok(Fault::new(sender_id.clone(), FaultKind::MultipleReadys).into());
            }
        }

        self.readys.insert(sender_id.clone(), hash.to_vec());

        let mut step = Step::default();
        // Upon receiving f + 1 matching Ready(h) messages, if Ready
        // has not yet been sent, multicast Ready(h).
        if self.count_readys(hash) == self.netinfo.num_faulty() + 1 && !self.ready_sent {
            // Enqueue a broadcast of a Ready message.
            step.extend(self.send_ready(hash)?);
        }

        // 输出一个列表W_i
        Ok(step.join(self.compute_output(hash)?))
    }

    /// Sends an `Echo` message and handles it. Does nothing if we are only an observer.
    fn send_echo(&mut self, value_sender: &N, ts_msg: TsMessage) -> Result<Step<N>> {
        self.echo_sent = true;
        if !self.netinfo.is_validator() {
            return Ok(Step::default());
        }
        // echo消息不会是发送给所有的节点，而是返回给Node i
        let echo_msg = Message::Echo(ts_msg.clone());
        // 
        let step: Step<_> = Target::Node(value_sender).message(echo_msg).into();
        let our_id = &self.our_id().clone();
        Ok(step.join(self.handle_echo(our_id, ts_msg)?))
    }

    /// Sends a `Ready` message and handles it. Does nothing if we are only an observer.
    /// Ready message is the threshold signature(AGGREGATION SIGNATURE)
    fn send_ready(&mut self, ts_msg: &TsMessage) -> Result<Step<N>> {
        self.ready_sent = true;
        if !self.netinfo.is_validator() {
            return Ok(Step::default());
        }
        let ready_msg = Message::Ready(*ts_msg);
        let step: Step<_> = Target::All.message(ready_msg).into();
        let our_id = &self.our_id().clone();
        Ok(step.join(self.handle_ready(our_id, ts_msg)?))
    }

    /// Checks whether the conditions for output are met for this hash, and if so, sets the output
    /// value.
    /// 主要看这个节点是否收到了2f+1个节点的聚合签名
    /// 这个函数需是计算PD子协议的输出，即一个节点及其聚合签名的敲定列表（这个列表会被用于后面的Node election）
    fn compute_output(&mut self, hash: &TsMessage) -> Result<Step<N>> {
        if self.decided
            || self.count_readys(hash) <= 2 * self.netinfo.num_faulty()
        {
            return Ok(Step::default());
        }

        // currently, reveive 2f+1 ready(Aggregation threshold signature)，Complete PD
        let now = SystemTime::now();
        let timestamp = now.duration_since(UNIX_EPOCH).expect("time error").as_secs();
        println!("currently, we have finished the RBC {}", timestamp);

        let step = Step::default();
        // construct a Node Election list W_i
        let election_list = self.echos.values().collect();
        step.message.push(election_list)
    }

    /// Returns `true` if the proof is valid and has the same index as the node ID.
    fn validate_proof(&self, p: &Proof<Vec<u8>>, id: &N) -> bool {
        self.netinfo.node_index(id) == Some(p.index()) && p.validate(self.netinfo.num_nodes())
    }

    /// Returns the number of nodes that have sent us an `Echo` message with this hash.
    fn count_echos(&self, ts: &TsMessage) -> usize {
        self.echos
            .values()
            .filter(|p| p == ts)
            .count()
    }

    /// Returns the number of nodes that have sent us a `Ready` message with this hash.
    fn count_readys(&self, ts: &TsMessage) -> usize {
        self.readys
            .values()
            .filter(|h| h == ts)
            .count()
    }
}

impl<N: NodeIdT> fmt::Display for Broadcast<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> result::Result<(), fmt::Error> {
        write!(f, "{:?} Broadcast({:?})", self.our_id(), self.proposer_id)
    }
}

/// A wrapper for `ReedSolomon` that doesn't panic if there are no parity shards.
#[derive(Debug)]
enum Coding {
    /// A `ReedSolomon` instance with at least one parity shard.
    ReedSolomon(Box<ReedSolomon<Field8>>),
    /// A no-op replacement that doesn't encode or decode anything.
    Trivial(usize),
}

impl Coding {
    /// Creates a new `Coding` instance with the given number of shards.
    fn new(data_shard_num: usize, parity_shard_num: usize) -> RseResult<Self> {
        Ok(if parity_shard_num > 0 {
            let rs = ReedSolomon::new(data_shard_num, parity_shard_num)?;
            Coding::ReedSolomon(Box::new(rs))
        } else {
            Coding::Trivial(data_shard_num)
        })
    }

    /// Returns the number of data shards.
    fn data_shard_count(&self) -> usize {
        match *self {
            Coding::ReedSolomon(ref rs) => rs.data_shard_count(),
            Coding::Trivial(dsc) => dsc,
        }
    }

    /// Returns the number of parity shards.
    fn parity_shard_count(&self) -> usize {
        match *self {
            Coding::ReedSolomon(ref rs) => rs.parity_shard_count(),
            Coding::Trivial(_) => 0,
        }
    }

    /// Constructs (and overwrites) the parity shards.
    fn encode(&self, slices: &mut [&mut [u8]]) -> RseResult<()> {
        match *self {
            Coding::ReedSolomon(ref rs) => rs.encode(slices),
            Coding::Trivial(_) => Ok(()),
        }
    }

    /// If enough shards are present, reconstructs the missing ones.
    fn reconstruct_shards(&self, shards: &mut [Option<Box<[u8]>>]) -> RseResult<()> {
        match *self {
            Coding::ReedSolomon(ref rs) => rs.reconstruct(shards),
            Coding::Trivial(_) => {
                if shards.iter().all(Option::is_some) {
                    Ok(())
                } else {
                    Err(rse::Error::TooFewShardsPresent)
                }
            }
        }
    }
}
