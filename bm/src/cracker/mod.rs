use bee_signing::ternary::wots::normalize;
use bee_ternary::{T1B1Buf, T3B1Buf, TritBuf, Trits, T3B1};
const MESSAGE_FRAGMENT_LENGTH: usize = 27;

/// Get the maximum bundle hash by selecting the max trytes from all input bundle hashes
pub fn get_max_normalized_bundle_hash(
    bundle_hashes: Vec<TritBuf<T1B1Buf>>,
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

/// Check whether each tryte in mined bundle hash are all smaller smaller than those in the max one
pub fn mined_bundle_hash_is_good(
    mined_bundle_hash: &TritBuf<T1B1Buf>,
    max_bundle_hash: &TritBuf<T1B1Buf>,
) -> bool {
    // Get the i8 slices from the mined bundle hash
    let mined_bundle_hash_i8 = TritBuf::<T3B1Buf>::from_i8s(mined_bundle_hash.as_i8_slice())
        .unwrap()
        .as_i8_slice()
        .to_vec();

    // Get the i8 slices from the max bundle hash
    let max_bundle_hash_i8 = TritBuf::<T3B1Buf>::from_i8s(max_bundle_hash.as_i8_slice())
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
