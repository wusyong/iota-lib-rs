use crate::bundle_miner::{BundleMiner, BundleMinerEvent, LESS_THAN_MAX_HASH};
use bee_signing::ternary::wots::normalize;
use bee_ternary::{T1B1Buf, T3B1Buf, TritBuf, Trits, T3B1};
const MESSAGE_FRAGMENT_LENGTH: usize = 27;

/// Builder for a logger output configuration.
#[derive(Default)]
pub struct CrackerBuilder {
    /// The security level of the input hashes.
    security_level: Option<usize>,
    /// The input bundle hashes for cracking.
    input_bundle_hashes: Option<Vec<TritBuf<T1B1Buf>>>,
    /// The bundle miner used in cracker.
    bundle_miner: Option<BundleMiner>,
}

pub struct Cracker {
    /// The security level of the input hashes.
    security_level: usize,
    /// The input bundle hashes for cracking.
    input_bundle_hashes: Vec<TritBuf<T1B1Buf>>,
    /// The bundle miner used in cracker.
    bundle_miner: BundleMiner,
}

impl CrackerBuilder {
    /// Creates a new builder for a bundle miner.
    pub fn new() -> Self {
        Self::default()
    }
    /// Sets the security level of the cracker.
    pub fn security_level(mut self, security_level: usize) -> Self {
        self.security_level.replace(security_level);
        self
    }
    /// Sets the input bundle hashes of the cracker.
    pub fn input_bundle_hashes(mut self, input_bundle_hashes: Vec<TritBuf<T1B1Buf>>) -> Self {
        self.input_bundle_hashes.replace(input_bundle_hashes);
        self
    }
    /// Sets the bundle miner of the cracker.
    pub fn bundle_miner(mut self, bundle_miner: BundleMiner) -> Self {
        self.bundle_miner.replace(bundle_miner);
        self
    }
    /// Builds a cracker.
    pub fn finish(self) -> Cracker {
        Cracker {
            security_level: self.security_level.unwrap(),
            input_bundle_hashes: self.input_bundle_hashes.unwrap(),
            bundle_miner: self.bundle_miner.unwrap(),
        }
    }
}

impl Cracker {
    /// Start running mining workers
    pub fn crack(&mut self) -> BundleMinerEvent {
        let max_hash =
            get_max_normalized_bundle_hash(&self.input_bundle_hashes, self.security_level);
        self.bundle_miner.run(max_hash, LESS_THAN_MAX_HASH)
    }
}

/// Get the maximum bundle hash by selecting the max trytes from all input bundle hashes
pub fn get_max_normalized_bundle_hash(
    bundle_hashes: &Vec<TritBuf<T1B1Buf>>,
    security_level: usize,
) -> TritBuf<T1B1Buf> {
    // Normalize the bundle hashes
    let mut normalized_hashes_i8_vecs = bundle_hashes
        .iter()
        .map(|t| {
            TritBuf::<T3B1Buf>::from_i8s(normalize(&t).unwrap().as_i8_slice())
                .unwrap()
                .as_i8_slice()
                .to_vec()
        })
        .collect::<Vec<Vec<i8>>>();

    // Get the max normalized bundle hash
    let mut max_vec_i8 = normalized_hashes_i8_vecs.pop().unwrap();
    while let Some(current_vec_i8) = normalized_hashes_i8_vecs.pop() {
        max_vec_i8 = get_the_max_tryte_values(max_vec_i8, current_vec_i8);
    }

    // Return the max normalized bundle hash in TritBuf::<T1B1Buf>
    let trits_t1b1 = unsafe {
        Trits::<T3B1>::from_raw_unchecked(
            &max_vec_i8[..MESSAGE_FRAGMENT_LENGTH * security_level],
            MESSAGE_FRAGMENT_LENGTH * security_level * 3,
        )
        .to_buf::<T3B1Buf>()
        .encode::<T1B1Buf>()
    };
    trits_t1b1
}

/// Get max trytes values from two i8 vectors
pub fn get_the_max_tryte_values(vec_i8_first: Vec<i8>, vec_i8_second: Vec<i8>) -> Vec<i8> {
    vec_i8_first
        .iter()
        .zip(&vec_i8_second)
        .map(|(&x, &y)| x.max(y))
        .collect()
}
