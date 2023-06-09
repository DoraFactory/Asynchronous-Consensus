use std::default::Default;
use std::iter::once;
use std::marker::PhantomData;
use std::sync::Arc;

use crate::crypto::{SecretKey, SecretKeySet};
use serde::{de::DeserializeOwned, Serialize};

use super::{DynamicDumbo, EncryptionSchedule, JoinPlan, Result, Step, VoteCounter};
use crate::dumbo::{Dumbo, Params, SubsetHandlingStrategy};
use crate::{Contribution, NetworkInfo, NodeIdT};

/// A Dynamic Dumbo builder, to configure the parameters and create new instances of
/// `DynamicDumbo`.
pub struct DynamicDumboBuilder<C, N> {
    /// Start in this era.
    era: u64,
    /// Start in this epoch.
    epoch: u64,
    /// Parameters controlling Dumbo's behavior and performance.
    params: Params,
    _phantom: PhantomData<(C, N)>,
}

impl<C, N: Ord> Default for DynamicDumboBuilder<C, N> {
    fn default() -> Self {
        DynamicDumboBuilder {
            era: 0,
            epoch: 0,
            params: Params::default(),
            _phantom: PhantomData,
        }
    }
}

impl<C, N> DynamicDumboBuilder<C, N>
where
    C: Contribution + Serialize + DeserializeOwned,
    N: NodeIdT + Serialize + DeserializeOwned,
{
    /// Returns a new `DynamicDumboBuilder` configured to use the node IDs and cryptographic
    /// keys specified by `netinfo`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the starting era to the given value.
    pub fn era(&mut self, era: u64) -> &mut Self {
        self.era = era;
        self
    }

    /// Sets the starting era to the given value.
    pub fn epoch(&mut self, epoch: u64) -> &mut Self {
        self.epoch = epoch;
        self
    }

    /// Sets the maximum number of future epochs for which we handle messages simultaneously.
    pub fn max_future_epochs(&mut self, max_future_epochs: u64) -> &mut Self {
        self.params.max_future_epochs = max_future_epochs;
        self
    }

    /// Sets the strategy to use when handling `Subset` output.
    pub fn subset_handling_strategy(
        &mut self,
        subset_handling_strategy: SubsetHandlingStrategy,
    ) -> &mut Self {
        self.params.subset_handling_strategy = subset_handling_strategy;
        self
    }

    /// Sets the schedule to use for threshold encryption.
    pub fn encryption_schedule(&mut self, encryption_schedule: EncryptionSchedule) -> &mut Self {
        self.params.encryption_schedule = encryption_schedule;
        self
    }

    /// Sets the parameters controlling Dumbo's behavior and performance.
    pub fn params(&mut self, params: Params) -> &mut Self {
        self.params = params;
        self
    }

    /// Creates a new Dynamic Dumbo instance with an empty buffer.
    pub fn build(&mut self, netinfo: NetworkInfo<N>) -> DynamicDumbo<C, N> {
        let DynamicDumboBuilder {
            era,
            epoch,
            params,
            _phantom,
        } = self;
        let arc_netinfo = Arc::new(netinfo.clone());

        let honey_badger = Dumbo::builder(arc_netinfo.clone())
            .session_id(*era)
            .epoch(*epoch)
            .params(params.clone())
            .build();

        DynamicDumbo {
            netinfo,
            max_future_epochs: params.max_future_epochs,
            era: *era,
            vote_counter: VoteCounter::new(arc_netinfo, 0),
            key_gen_msg_buffer: Vec::new(),
            honey_badger,
            key_gen_state: None,
        }
    }

    /// Creates a new `DynamicDumbo` configured to start a new network as a single validator.
    pub fn build_first_node<R: rand::Rng>(
        &mut self,
        our_id: N,
        rng: &mut R,
    ) -> Result<DynamicDumbo<C, N>> {
        let sk_set = SecretKeySet::random(0, rng);
        let pk_set = sk_set.public_keys();
        let sks = sk_set.secret_key_share(0);
        let sk = rng.gen::<SecretKey>();
        let pub_keys = once((our_id.clone(), sk.public_key())).collect();
        let netinfo = NetworkInfo::new(our_id, sks, pk_set, sk, pub_keys);
        Ok(self.build(netinfo))
    }

    /// Creates a new `DynamicDumbo` configured to join the network at the epoch specified in
    /// the `JoinPlan`. This ignores the builder's configuration settings.
    ///
    /// **Deprecated**: Please use `DynamicDumbo::new_joining` instead.
    #[deprecated]
    pub fn build_joining<R: rand::Rng>(
        &mut self,
        our_id: N,
        secret_key: SecretKey,
        join_plan: JoinPlan<N>,
        rng: &mut R,
    ) -> Result<(DynamicDumbo<C, N>, Step<C, N>)> {
        DynamicDumbo::new_joining(our_id, secret_key, join_plan, rng)
    }
}
