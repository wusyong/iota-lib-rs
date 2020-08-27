/// TODO: add more documentation
use bee_crypto::ternary::{
    bigint::{binary_representation::U32Repr, endianness::BigEndian, I384, T242, T243},
    sponge::{Kerl, Sponge},
    Hash,
};
use bee_signing::ternary::wots::normalize;
use bee_ternary::{t3b1::T3B1Buf, Btrit, T1B1Buf, TritBuf};
use bee_transaction::bundled::{
    Address, BundledTransactionBuilder, BundledTransactionError, BundledTransactionField, Index,
    Nonce, OutgoingBundleBuilder, Payload, Tag, Timestamp, Value, ADDRESS_TRIT_LEN, HASH_TRIT_LEN,
    NONCE_TRIT_LEN, PAYLOAD_TRIT_LEN, TAG_TRIT_LEN,
};
use std::convert::TryFrom;
use tokio::{runtime::Builder, sync::mpsc, task, time};
// uses
use futures::future::abortable;

pub const VALUE_TRIT_LEN: usize = 81;
pub const TIMESTAMP_TRIT_LEN: usize = 27;
pub const INDEX_TRIT_LEN: usize = 27;

/// I384 big-endian `u32` 3^81
pub const TRITS82_BE_U32: I384<BigEndian, U32Repr> = I384::<BigEndian, U32Repr>::from_array([
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    1,
    1_301_861_838,
    2_705_975_348,
    3_065_973_865,
    3_580_722_371,
]);

/// TODO: Remove this when they are explosed to public in bee_transaction
#[derive(Copy, Clone)]
pub struct Offset {
    pub start: usize,
    pub length: usize,
}

/// TODO: Remove this when they are explosed to public in bee_transaction
#[derive(Copy, Clone)]
pub struct Field {
    pub trit_offset: Offset,
    pub tryte_offset: Offset,
}

/// TODO: Remove this when they are explosed to public in bee_transaction
impl Field {
    pub fn byte_start(&self) -> usize {
        self.trit_offset.start / 5
    }

    pub fn byte_length(&self) -> usize {
        if self.trit_offset.length % 5 == 0 {
            self.trit_offset.length / 5
        } else {
            self.trit_offset.length / 5 + 1
        }
    }
}

#[derive(Debug)]
pub enum BundleMinerEvent {
    MinedEssence(TritBuf<T1B1Buf>),
    Timeout,
}

/// TODO: Remove this when they are explosed to public in bee_transaction
macro_rules! offsets_from_trits {
    ($start:expr, $length:expr) => {
        Field {
            trit_offset: Offset {
                start: $start,
                length: $length,
            },
            tryte_offset: Offset {
                start: $start / 3,
                length: $length / 3,
            },
        }
    };
}

/// TODO: Remove this when they are explosed to public in bee_transaction
macro_rules! offsets_from_previous_field {
    ($prev:expr, $length:expr) => {
        Field {
            trit_offset: Offset {
                start: ($prev).trit_offset.start + ($prev).trit_offset.length,
                length: $length,
            },
            tryte_offset: Offset {
                start: (($prev).trit_offset.start + ($prev).trit_offset.length) / 3,
                length: $length / 3,
            },
        }
    };
}

/// TODO: Remove this when they are explosed to public in bee_transaction
const PAYLOAD: Field = offsets_from_trits!(0, PAYLOAD_TRIT_LEN);
const ADDRESS: Field = offsets_from_previous_field!(PAYLOAD, ADDRESS_TRIT_LEN);
const VALUE: Field = offsets_from_previous_field!(ADDRESS, VALUE_TRIT_LEN);
const OBSOLETE_TAG: Field = offsets_from_previous_field!(VALUE, TAG_TRIT_LEN);
const TIMESTAMP: Field = offsets_from_previous_field!(OBSOLETE_TAG, TIMESTAMP_TRIT_LEN);
const INDEX: Field = offsets_from_previous_field!(TIMESTAMP, INDEX_TRIT_LEN);
const LAST_INDEX: Field = offsets_from_previous_field!(INDEX, INDEX_TRIT_LEN);
const BUNDLE: Field = offsets_from_previous_field!(LAST_INDEX, HASH_TRIT_LEN);
const TRUNK: Field = offsets_from_previous_field!(BUNDLE, HASH_TRIT_LEN);
const BRANCH: Field = offsets_from_previous_field!(TRUNK, HASH_TRIT_LEN);
const TAG: Field = offsets_from_previous_field!(BRANCH, TAG_TRIT_LEN);
const ATTACHMENT_TS: Field = offsets_from_previous_field!(TAG, TIMESTAMP_TRIT_LEN);
const ATTACHMENT_LBTS: Field = offsets_from_previous_field!(ATTACHMENT_TS, TIMESTAMP_TRIT_LEN);
const ATTACHMENT_UBTS: Field = offsets_from_previous_field!(ATTACHMENT_LBTS, TIMESTAMP_TRIT_LEN);
const NONCE: Field = offsets_from_previous_field!(ATTACHMENT_UBTS, NONCE_TRIT_LEN);
const HASH_TRYTES_COUNT: usize = 81;
const RESERVED_NONCE_TRYTES_COUNT: usize = 42;

/// Builder for a logger output configuration.
#[derive(Default)]
pub struct BundleMinerBuilder {
    /// Number of used core threads.
    core_threads: Option<usize>,
    /// Number of concurrent mining workers.
    mining_workers: Option<usize>,
    /// The essences from transactions for hash mining.
    essences: Option<Vec<TritBuf<T1B1Buf>>>,
    /// Timeout in seconds.
    timeout_seconds: Option<u64>,
}

pub struct BundleMiner {
    /// Number of used core threads.
    core_threads: usize,
    /// Number of concurrent mining workers.
    mining_workers: usize,
    /// The essences from transactions for hash mining.
    essences: Vec<TritBuf<T1B1Buf>>,
    /// Timeout in seconds.
    timeout_seconds: u64,
}

impl BundleMinerBuilder {
    /// Creates a new builder for a bundle miner.
    pub fn new() -> Self {
        Self::default()
    }
    /// Sets the core_threads of the bundle miner.
    pub fn core_threads(mut self, core_threads: usize) -> Self {
        self.core_threads.replace(core_threads);
        self
    }
    /// Sets the mining workers of the bundle miner.
    pub fn mining_workers(mut self, mining_workers: usize) -> Self {
        self.mining_workers.replace(mining_workers);
        self
    }
    /// Sets the essences of the bundle miner.
    pub fn essences(mut self, essences: Vec<TritBuf<T1B1Buf>>) -> Self {
        self.essences.replace(essences);
        self
    }
    /// Sets the timeout of the bundle miner in seconds.
    pub fn timeout_seconds(mut self, timeout_seconds: u64) -> Self {
        self.timeout_seconds.replace(timeout_seconds);
        self
    }
    // TODO: error handling
    /// Builds a bundler miner.
    pub fn finish(self) -> BundleMiner {
        BundleMiner {
            core_threads: self.core_threads.unwrap(),
            mining_workers: self.mining_workers.unwrap(),
            essences: self.essences.unwrap(),
            timeout_seconds: self.timeout_seconds.unwrap(),
        }
    }
}

/// Trait for defining the mining criteria.
pub trait StopMiningCriteria {
    /// Judgement function for the stop criterion.
    fn judge(&self, mined_hash: &TritBuf<T1B1Buf>, target_hash: &TritBuf<T1B1Buf>) -> bool;
}

/// Criteria of each tryte is less then the corresponding tryte in the max hash.
#[derive(Copy, Clone)]
pub struct LessThanMaxHash;

/// Criteria of each tryte equals to then the corresponding tryte in the target hash.
#[derive(Copy, Clone)]
pub struct EqualTargetHash;

/// The constant of `LessThanMaxHash` criterion.
pub const LESS_THAN_MAX_HASH: LessThanMaxHash = LessThanMaxHash;

/// The constant of `EqualTargetHash` criterion.
pub const EQUAL_TRAGET_HASH: EqualTargetHash = EqualTargetHash;

/// For `LessThanMaxHash` criterion, each tryte in mined hash should be smaller than that in the max hash.
impl StopMiningCriteria for LessThanMaxHash {
    fn judge(&self, mined_hash: &TritBuf<T1B1Buf>, target_hash: &TritBuf<T1B1Buf>) -> bool {
        // Get the i8 slices from the mined bundle hash
        let mined_bundle_hash_i8 = TritBuf::<T3B1Buf>::from_i8s(mined_hash.as_i8_slice())
            .unwrap()
            .as_i8_slice()
            .to_vec();

        // Get the i8 slices from the max bundle hash
        let max_bundle_hash_i8 = TritBuf::<T3B1Buf>::from_i8s(target_hash.as_i8_slice())
            .unwrap()
            .as_i8_slice()
            .to_vec();

        // Check whether each tryte of mined hash is smaller than the corresponding tryte in the max hash
        let larger_than_max_count: i8 = max_bundle_hash_i8
            .iter()
            .zip(&mined_bundle_hash_i8[..max_bundle_hash_i8.len()])
            .map(|(&x, &y)| if x < y { 1 } else { 0 })
            .collect::<Vec<i8>>()
            .into_iter()
            .sum();

        // Return true if all of the trytes in the mined hash are smaller than those in the max hash
        larger_than_max_count == 0
    }
}

/// For `EqualTargetHash` criterion, each tryte in mined hash should equal to that in the max hash.
impl StopMiningCriteria for EqualTargetHash {
    fn judge(&self, mined_hash: &TritBuf<T1B1Buf>, target_hash: &TritBuf<T1B1Buf>) -> bool {
        mined_hash == target_hash
    }
}

impl BundleMiner {
    /// Start running mining workers
    pub fn run(
        &mut self,
        target_hash: TritBuf<T1B1Buf>,
        criterion: impl StopMiningCriteria + std::marker::Send + 'static + Copy,
    ) -> BundleMinerEvent {
        let (tx, mut rx) = mpsc::channel(self.mining_workers);
        let mut runtime = Builder::new()
            .threaded_scheduler()
            .core_threads(self.core_threads)
            .thread_name("bundle-miner") // TODO: configurable by user
            .thread_stack_size(3 * 1024 * 1024) // TODO: configurable by user
            .enable_time()
            .build()
            .unwrap();
        let mut abort_handles = Vec::new();
        runtime.block_on(async {
            for i in 0..self.mining_workers as i32 {
                let mut tx_cloned = tx.clone();
                let (abortable_worker, abort_handle) = abortable(mining_worker(
                    0,
                    i,
                    self.essences[..].to_vec(),
                    target_hash.clone(),
                    criterion,
                ));
                tokio::spawn(async move {
                    if let Ok(mined_essence) = abortable_worker.await {
                        tx_cloned
                            .send(BundleMinerEvent::MinedEssence(mined_essence))
                            .await
                            .unwrap();
                    }
                });
                abort_handles.push(abort_handle);
            }
            let (abortable_worker, abort_handle) = abortable(timeout_worker(self.timeout_seconds));
            let mut tx_cloned = tx.clone();
            tokio::spawn(async move {
                if abortable_worker.await.is_ok() {
                    tx_cloned.send(BundleMinerEvent::Timeout).await.unwrap();
                }
            });
            abort_handles.push(abort_handle);
            if let Some(event) = rx.recv().await {
                match event {
                    BundleMinerEvent::MinedEssence(essence) => {
                        for i in abort_handles {
                            i.abort();
                        }
                        return BundleMinerEvent::MinedEssence(essence);
                    }
                    BundleMinerEvent::Timeout => {
                        for i in abort_handles {
                            i.abort();
                        }
                        return BundleMinerEvent::Timeout;
                    }
                }
            } else {
                unreachable!();
            }
        })
    }
}

/// The timeout worker to terminate the runtime in seconds
pub async fn timeout_worker(seconds: u64) {
    time::delay_for(time::Duration::from_secs(seconds)).await;
}

/// The mining worker, stop when timeout or the criterion is met
/// Return the mined essence for the last transaction
pub async fn mining_worker(
    increment: i64,
    worker_id: i32,
    mut essences: Vec<TritBuf<T1B1Buf>>,
    target_hash: TritBuf<T1B1Buf>,
    criterion: impl StopMiningCriteria,
) -> TritBuf<T1B1Buf> {
    let mut last_essence: TritBuf<T1B1Buf> = essences.pop().unwrap();
    let kerl = prepare_keccak_384(&essences).await;
    let obselete_tag = create_obsolete_tag(increment, worker_id).await;
    last_essence = update_essense_with_new_obsolete_tag(last_essence, &obselete_tag).await;

    // Note that we check the last essence with `zero` incresement first
    // While in the go-lang version the first checked essence hash `one` incresement
    let mut mined_hash = last_essence.clone();
    while !criterion.judge(&mined_hash, &target_hash) {
        last_essence = increase_essense(last_essence).await;
        task::yield_now().await;
        mined_hash = absorb_and_get_normalized_bundle_hash(kerl.clone(), &last_essence).await;
        task::yield_now().await;
    }
    last_essence
}

/// Get the OutgoingBundleBuilder for further bundle finalization
pub async fn get_outgoing_bundle_builder(
    transactions: &[TritBuf<T1B1Buf>],
) -> Result<OutgoingBundleBuilder, BundledTransactionError> {
    let mut bundle = OutgoingBundleBuilder::new();
    for trits in transactions.iter() {
        let transaction = BundledTransactionBuilder::new()
            .with_payload(
                Payload::try_from_inner(
                    trits[PAYLOAD.trit_offset.start
                        ..PAYLOAD.trit_offset.start + PAYLOAD.trit_offset.length]
                        .to_buf(),
                )
                .unwrap(),
            )
            .with_address(
                Address::try_from_inner(
                    trits[ADDRESS.trit_offset.start
                        ..ADDRESS.trit_offset.start + ADDRESS.trit_offset.length]
                        .to_buf(),
                )
                .unwrap(),
            )
            .with_value(Value::from_inner_unchecked(
                i64::try_from(
                    &trits[VALUE.trit_offset.start
                        ..VALUE.trit_offset.start + VALUE.trit_offset.length],
                )
                .map_err(|e| BundledTransactionError::InvalidNumericField("value", e))?,
            ))
            .with_obsolete_tag(Tag::from_inner_unchecked(
                trits[OBSOLETE_TAG.trit_offset.start
                    ..OBSOLETE_TAG.trit_offset.start + OBSOLETE_TAG.trit_offset.length]
                    .to_buf(),
            ))
            .with_timestamp(Timestamp::from_inner_unchecked(
                i128::try_from(
                    &trits[TIMESTAMP.trit_offset.start
                        ..TIMESTAMP.trit_offset.start + TIMESTAMP.trit_offset.length],
                )
                .map_err(|e| BundledTransactionError::InvalidNumericField("timestamp", e))?
                    as u64,
            ))
            .with_index(Index::from_inner_unchecked(
                i128::try_from(
                    &trits[INDEX.trit_offset.start
                        ..INDEX.trit_offset.start + INDEX.trit_offset.length],
                )
                .map_err(|e| BundledTransactionError::InvalidNumericField("index", e))?
                    as usize,
            ))
            .with_last_index(Index::from_inner_unchecked(
                i128::try_from(
                    &trits[LAST_INDEX.trit_offset.start
                        ..LAST_INDEX.trit_offset.start + LAST_INDEX.trit_offset.length],
                )
                .map_err(|e| BundledTransactionError::InvalidNumericField("last_index", e))?
                    as usize,
            ))
            .with_tag(Tag::from_inner_unchecked(
                trits[TAG.trit_offset.start..TAG.trit_offset.start + TAG.trit_offset.length]
                    .to_buf(),
            ))
            .with_attachment_ts(Timestamp::from_inner_unchecked(
                i128::try_from(
                    &trits[ATTACHMENT_TS.trit_offset.start
                        ..ATTACHMENT_TS.trit_offset.start + ATTACHMENT_TS.trit_offset.length],
                )
                .map_err(|e| BundledTransactionError::InvalidNumericField("attachment_ts", e))?
                    as u64,
            ))
            .with_bundle(Hash::from_inner_unchecked(
                trits[BUNDLE.trit_offset.start
                    ..BUNDLE.trit_offset.start + BUNDLE.trit_offset.length]
                    .to_buf(),
            ))
            .with_trunk(Hash::from_inner_unchecked(
                trits[TRUNK.trit_offset.start..TRUNK.trit_offset.start + TRUNK.trit_offset.length]
                    .to_buf(),
            ))
            .with_branch(Hash::from_inner_unchecked(
                trits[BRANCH.trit_offset.start
                    ..BRANCH.trit_offset.start + BRANCH.trit_offset.length]
                    .to_buf(),
            ))
            .with_attachment_lbts(Timestamp::from_inner_unchecked(
                i128::try_from(
                    &trits[ATTACHMENT_LBTS.trit_offset.start
                        ..ATTACHMENT_LBTS.trit_offset.start + ATTACHMENT_LBTS.trit_offset.length],
                )
                .map_err(|e| BundledTransactionError::InvalidNumericField("attachment_lbts", e))?
                    as u64,
            ))
            .with_attachment_ubts(Timestamp::from_inner_unchecked(
                i128::try_from(
                    &trits[ATTACHMENT_UBTS.trit_offset.start
                        ..ATTACHMENT_UBTS.trit_offset.start + ATTACHMENT_UBTS.trit_offset.length],
                )
                .map_err(|e| BundledTransactionError::InvalidNumericField("attachment_ubts", e))?
                    as u64,
            ))
            .with_nonce(Nonce::from_inner_unchecked(
                trits[NONCE.trit_offset.start..NONCE.trit_offset.start + NONCE.trit_offset.length]
                    .to_buf(),
            ));
        bundle.push(transaction);
    }
    Ok(bundle)
}

/// Absorb the input essences and return the Kerl
pub async fn prepare_keccak_384(essences: &[TritBuf<T1B1Buf>]) -> Kerl {
    let mut kerl = Kerl::new();
    for essence in essences.iter() {
        async { kerl.absorb(essence.as_slice()).unwrap() }.await;
        task::yield_now().await;
    }
    kerl
}

/// Use Kerl to absorbe the last essence, sqeeze, and output the normalized hash
pub async fn absorb_and_get_normalized_bundle_hash(
    mut kerl: Kerl,
    last_essence: &TritBuf<T1B1Buf>,
) -> TritBuf<T1B1Buf> {
    async { kerl.absorb(last_essence.as_slice()).unwrap() }.await;
    task::yield_now().await;
    let hash = async { normalize(&kerl.squeeze().unwrap()).unwrap() }.await;
    hash
}

/// Increase the essence by 3^81, so the obselete is increased by 1
pub async fn increase_essense(essence: TritBuf<T1B1Buf>) -> TritBuf<T1B1Buf> {
    let mut essence_i384 = async {
        I384::<BigEndian, U32Repr>::try_from(T243::<Btrit>::new(essence).into_t242()).unwrap()
    }
    .await;
    async { essence_i384.add_inplace(TRITS82_BE_U32) }.await;
    let essence = async {
        T242::<Btrit>::try_from(essence_i384)
            .unwrap()
            .into_t243()
            .into_inner()
    }
    .await;
    essence
}

/// Cast TritBuf to String for verification usage and ease of observation
pub async fn trit_buf_to_string(trit_buf: &TritBuf<T1B1Buf>) -> String {
    let trit_str = async {
        TritBuf::<T3B1Buf>::from_i8s(trit_buf.as_i8_slice())
            .unwrap()
            .as_trytes()
            .iter()
            .map(|t| char::from(*t))
            .collect::<String>()
    }
    .await;
    trit_str
}

/// Replace the obselete tag in the essence with a new one
pub async fn update_essense_with_new_obsolete_tag(
    mut essence: TritBuf<T1B1Buf>,
    obselete_tag: &TritBuf<T1B1Buf>,
) -> TritBuf<T1B1Buf> {
    let obselete_tag_i8s = obselete_tag.as_i8_slice();
    let essence_i8s = unsafe { essence.as_i8_slice_mut() };
    essence_i8s[TAG_TRIT_LEN..TAG_TRIT_LEN * 2].copy_from_slice(obselete_tag_i8s);
    async { TritBuf::<T1B1Buf>::from_i8s(essence_i8s).unwrap() }.await
}

/// Create the obsolete tag by the increment (the 43th-81th trits) and worker_id (first 42 trits)
pub async fn create_obsolete_tag(increment: i64, worker_id: i32) -> TritBuf<T1B1Buf> {
    let mut zero_tritbuf = TritBuf::<T1B1Buf>::zeros(TAG_TRIT_LEN);
    let reserved_nonce_tritbuf = async { TritBuf::<T1B1Buf>::from(increment) }.await;
    let reserved_nonce_trits = async { reserved_nonce_tritbuf.as_i8_slice() }.await;
    let other_essence_tritbuf = async { TritBuf::<T1B1Buf>::from(worker_id) }.await;
    let other_essence_trits = async { other_essence_tritbuf.as_i8_slice() }.await;
    let output = async { unsafe { zero_tritbuf.as_i8_slice_mut() } }.await;
    let mut reserved_nonce_trits_len = async { reserved_nonce_trits.len() }.await;
    if reserved_nonce_trits_len > RESERVED_NONCE_TRYTES_COUNT {
        reserved_nonce_trits_len = RESERVED_NONCE_TRYTES_COUNT;
    }
    async { output[..reserved_nonce_trits_len].clone_from_slice(reserved_nonce_trits) }.await;
    let mut other_trits_len = RESERVED_NONCE_TRYTES_COUNT + other_essence_trits.len();
    if other_trits_len > HASH_TRYTES_COUNT {
        other_trits_len = HASH_TRYTES_COUNT;
    }
    async {
        output[RESERVED_NONCE_TRYTES_COUNT..other_trits_len].clone_from_slice(other_essence_trits)
    }
    .await;
    async { TritBuf::<T1B1Buf>::from_i8s(output).unwrap() }.await
}
