use bee_crypto::ternary::{
    bigint::{binary_representation::U32Repr, endianness::BigEndian, I384, T242, T243},
    sponge::{Kerl, Sponge},
    Hash,
};
use bee_signing::ternary::wots::normalize;
use bee_ternary::{t3b1::T3B1Buf, Btrit, T1B1Buf, TritBuf, TryteBuf};
use bee_transaction::bundled::{
    Address, BundledTransactionBuilder, BundledTransactionError, BundledTransactionField, Index,
    Nonce, OutgoingBundleBuilder, Payload, Tag, Timestamp, Value, ADDRESS_TRIT_LEN, HASH_TRIT_LEN,
    NONCE_TRIT_LEN, PAYLOAD_TRIT_LEN, TAG_TRIT_LEN,
};
use std::time::SystemTime;
use std::{convert::TryFrom, time::Duration};
use tokio::{runtime::Builder, sync::mpsc, task};

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

fn main() {
    let worker_count = 100;
    let (tx, mut rx) = mpsc::channel(10);
    let time_out_milliseconds = 1000;
    let essences = vec![
        "EDIKZYSKVIWNNTMKWUSXKFMYQVIMBNECNYKBG9YVRKUMXNIXSVAKTIDCAHULLLXR9FSQSDDOFOJWKFACD",
        "A99999999999999999999999999999999999999999999999999999999999999999999999C99999999",
        "BMLAF9QKVBYJTGHTGFFNOVDTGEMA9MSXGTJYSRRHEYTMMKRMQYETPJVAADGYLPYMGBJERKLJVUZUZYRQD",
        "Z99999999999999999999999999999999999999999999999999999999999999A99999999C99999999",
        "BMLAF9QKVBYJTGHTGFFNOVDTGEMA9MSXGTJYSRRHEYTMMKRMQYETPJVAADGYLPYMGBJERKLJVUZUZYRQD",
        "999999999999999999999999999999999999999999999999999999999999999B99999999C99999999",
        "BMLAF9QKVBYJTGHTGFFNOVDTGEMA9MSXGTJYSRRHEYTMMKRMQYETPJVAADGYLPYMGBJERKLJVUZUZYRQD",
        "999999999999999999999999999999999999999999999999999999999999999C99999999C99999999",
    ];
    let final_hash =
        "NNNNNNFAHTZDAMSFMGDCKRWIMMVPVISUYXKTFADURMAEMTNFGBUMODCKQZPMWHUGISUOCWQQL99ZTGCJD";
    let mut runtime = Builder::new()
        .threaded_scheduler()
        .core_threads(1)
        .thread_name("bundle-miner")
        .thread_stack_size(3 * 1024 * 1024)
        .build()
        .unwrap();
    runtime.block_on(async {
        for i in 0..worker_count {
            let mut tx_cloned = tx.clone();
            let essences = essences
                .clone()
                .iter()
                .map(|t| {
                    TryteBuf::try_from_str(&(*t).to_string())
                        .unwrap()
                        .as_trits()
                        .encode()
                })
                .collect::<Vec<TritBuf<T1B1Buf>>>();
            task::spawn(async move {
                let last_essence = async_mining_worker(
                    0,
                    i,
                    essences[..]
                        .iter()
                        .cloned()
                        .collect::<Vec<TritBuf<T1B1Buf>>>(),
                    TryteBuf::try_from_str(&final_hash.to_string())
                        .unwrap()
                        .as_trits()
                        .encode(),
                )
                .await;
                tx_cloned.send(last_essence).await.unwrap();
            });
            task::yield_now().await;
        }
        match rx.recv().await {
            Some(last_essence) => {
                println!("Mined essence {:?} received", last_essence);
                // TODO: gracefully shutdown here
            }
            None => {}
        }
    });
    println!("All tasks are spawned");
    runtime.shutdown_timeout(Duration::from_millis(time_out_milliseconds));
}

/// The mining worker, stop when timeout or the created_hash == target_hash
/// Return the mined essence for the last transaction
pub async fn async_mining_worker(
    increment: i64,
    worker_id: i32,
    mut essences: Vec<TritBuf<T1B1Buf>>,
    target_hash: TritBuf<T1B1Buf>,
) -> TritBuf<T1B1Buf> {
    println!("worker {:?} starts", worker_id);
    let mut last_essence: TritBuf<T1B1Buf> = essences.pop().unwrap();
    let kerl = prepare_keccak_384(&essences).await;
    tokio::task::yield_now().await;
    let obselete_tag = create_obsolete_tag(increment, worker_id).await;
    tokio::task::yield_now().await;
    last_essence = update_essense_with_new_obsolete_tag(last_essence, &obselete_tag).await;
    tokio::task::yield_now().await;
    let mut mined_hash = TritBuf::<T1B1Buf>::new();
    while target_hash != mined_hash {
        last_essence = increase_essense(last_essence).await;
        tokio::task::yield_now().await;
        mined_hash = absorb_and_get_normalized_bundle_hash(kerl.clone(), &last_essence).await;
        tokio::task::yield_now().await;
    }
    println!("hash is found at worker {:?}!", worker_id);
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
        tokio::task::yield_now().await;
    }
    kerl
}

/// Use Kerl to absorbe the last essence, sqeeze, and output the normalized hash
pub async fn absorb_and_get_normalized_bundle_hash(
    mut kerl: Kerl,
    last_essence: &TritBuf<T1B1Buf>,
) -> TritBuf<T1B1Buf> {
    async { kerl.absorb(last_essence.as_slice()).unwrap() }.await;
    tokio::task::yield_now().await;
    let hash = async { normalize(&kerl.squeeze().unwrap()).unwrap() }.await;
    tokio::task::yield_now().await;
    hash
}

/// Increase the essence by 3^81, so the obselete is increased by 1
pub async fn increase_essense(essence: TritBuf<T1B1Buf>) -> TritBuf<T1B1Buf> {
    let mut essence_i384 = async {
        I384::<BigEndian, U32Repr>::try_from(T243::<Btrit>::new(essence).into_t242()).unwrap()
    }
    .await;
    tokio::task::yield_now().await;
    async { essence_i384.add_inplace(TRITS82_BE_U32) }.await;
    let essence = async {
        T242::<Btrit>::try_from(essence_i384)
            .unwrap()
            .into_t243()
            .into_inner()
    }
    .await;
    tokio::task::yield_now().await;
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
    tokio::task::yield_now().await;
    trit_str
}

/// Replace the obselete tag in the essence with a new one
pub async fn update_essense_with_new_obsolete_tag(
    mut essence: TritBuf<T1B1Buf>,
    obselete_tag: &TritBuf<T1B1Buf>,
) -> TritBuf<T1B1Buf> {
    let obselete_tag_i8s = async { obselete_tag.as_i8_slice() }.await;
    tokio::task::yield_now().await;
    let essence_i8s = async { unsafe { essence.as_i8_slice_mut() } }.await;
    tokio::task::yield_now().await;
    async { essence_i8s[TAG_TRIT_LEN..TAG_TRIT_LEN * 2].copy_from_slice(obselete_tag_i8s) }.await;
    tokio::task::yield_now().await;
    let updated_obselete_tag = async { TritBuf::<T1B1Buf>::from_i8s(essence_i8s).unwrap() }.await;
    tokio::task::yield_now().await;
    updated_obselete_tag
}

/// Create the obsolete tag by the increment (the 43th-81th trits) and worker_id (first 42 trits)
pub async fn create_obsolete_tag(increment: i64, worker_id: i32) -> TritBuf<T1B1Buf> {
    let mut zero_tritbuf = async { TritBuf::<T1B1Buf>::zeros(TAG_TRIT_LEN) }.await;
    tokio::task::yield_now().await;
    let reserved_nonce_tritbuf = async { TritBuf::<T1B1Buf>::from(increment) }.await;
    tokio::task::yield_now().await;
    let reserved_nonce_trits = async { reserved_nonce_tritbuf.as_i8_slice() }.await;
    tokio::task::yield_now().await;
    let other_essence_tritbuf = async { TritBuf::<T1B1Buf>::from(worker_id) }.await;
    tokio::task::yield_now().await;
    let other_essence_trits = async { other_essence_tritbuf.as_i8_slice() }.await;
    tokio::task::yield_now().await;
    let output = async { unsafe { zero_tritbuf.as_i8_slice_mut() } }.await;
    tokio::task::yield_now().await;
    let mut reserved_nonce_trits_len = async { reserved_nonce_trits.len() }.await;
    tokio::task::yield_now().await;
    if reserved_nonce_trits_len > RESERVED_NONCE_TRYTES_COUNT {
        reserved_nonce_trits_len = RESERVED_NONCE_TRYTES_COUNT;
    }
    async { output[..reserved_nonce_trits_len].clone_from_slice(reserved_nonce_trits) }.await;
    tokio::task::yield_now().await;
    let mut other_trits_len = RESERVED_NONCE_TRYTES_COUNT + other_essence_trits.len();
    if other_trits_len > HASH_TRYTES_COUNT {
        other_trits_len = HASH_TRYTES_COUNT;
    }
    async {
        output[RESERVED_NONCE_TRYTES_COUNT..other_trits_len].clone_from_slice(other_essence_trits)
    }
    .await;
    tokio::task::yield_now().await;
    let obsolete_tag = async { TritBuf::<T1B1Buf>::from_i8s(output).unwrap() }.await;
    tokio::task::yield_now().await;
    obsolete_tag
}
#[tokio::test]
pub async fn test_get_outgoing_bundle_builder() {
    let transactions = vec![
        "999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999PEQMOYMQWULOGOTWLTJ9TADSOIVBWHDDJVDEVPHJITTZWSGPLEXJNGL99IQX9FHQAZZJOWYSYNNGXTX9ZCTAYNJRBA999999999999999999GPJNITY99999999999999999999D9DWACD99999999999C99999999RV9BHSYRJLJHR9RGEHWHQUOKYQRQ9Q9SKPIAYO9PAVKJLZYUHHOBDLWUJMEAZZIQN9DVJGDIATKLAGCYYQKHTXBACSUXBXHWEGNMZRGVDNRBEFHBZ9K9PAJN9BFVOGWKPUCFRSLPYYKJZOSOYGIFXHJPKPRML99999PWRRZN9UNKJJDDCLSFPKT9YHCWGETPD9ELURTFPDUKBJSQDTPQXLEWYYQKETKUUQL9HHBTDMQNRQA9999TB9CONFIRMER999999999999999RTSAVHHQF999999999MMMMMMMMMKBRKRSIQLGARC9ZIWUQ9DXU9WQZ",
        "VNJ9AEJMYTLGPKHYRJKHAVGBMZJAEFDVKBCWVGSBYYS9TLJZWKRIOMAJZQPPEUOQBMDIKRZTZCKERXXQWZGM9VJKRWEBGHUUBGLSWYGCIOBVXJJ9TSQOEQNIELMGOXSIKNQOZXS9IUMGBMQEBDKS9LNMMJBCLNTJNBUEXAEGLLQLMTS9IMGFYRSUKZ9GQYLDCQUBKISDRXAQWOQARPIWBJIEYEWJXQYIXLMP9XU9CMDYBMZPVUDSLVZTXDYLX9TNCHTGQFJLSKLDBUGXARC9KQANDMJYPOTXSCSZYYETRUEJZFQMYQYTDLELZXIDKJDMVZLYJDZKDSYFRIRMJKRKKFCYTIEFGKARPDPAQDDHIZHGPFQQKBTJB9MCJUSPBYMYTMNIYHJXLADJYINDQNMPDQRHJLDPUEOHP9ZXCSYQFRSLWHKORFFVLEPABDUWE9HHDEZGTYELARFUA9XRHMWQXSJYJEQ9NYWSPWAU9CKEMYZT9QDOJMJJDLMWPJBQGOKZBVMTKMUTNKJXSXOQSUU9UPCDBULMDBOZJWPVSQCGY9XVERGIPWQZRMAMDYKLIQSBPHYXTTUDVAZ9BGEHZG9KGQWTORBRKVQBXXUJVBSTIHHCUIYYQGQJDCLNKNQ9ALCFVMOIOSDCEUALNNIXWNAFBNWKXAAJKBNVWUQVHESOBK9GQMWXEQMHQFZ9CZMXYZRPQDKBCORMJEF9CEF9QSIOLTDZXI9JTEMBBVXODIGMADRMPVZPWLAKXSOVFDRLFMXJRAMUFPLFHVYVHVNCXMDPAGMLVMODJLGONZQ9LMRY9BRLLBXYTHFCZAEH9ZCVXFJELPP9UTLEVONGYVENKDSRBMEJUZHTANZMFNBHNKFMXRVQRTTDDUMFTKHB9HBQAL9KQBRQASJJSARGCZOJQQEDMZYJJQYQRVELKPHBGDADRDMKMYUMR9GZTNVVTZT9FDSDKYODLRTMHSYDRGLBJIASUAOKXJVOSOSDCMEAK9BWOUZUXXRXCWUOSRXWRS99OCITHIMU9RKDHJJJWWEGYJHRQUACGMFXCEVRERGJSEKLDUDXAL9PVU9GQQUBWTMIFYGORWGLCVGRHXMCPJKRKVHPEYWDLNEMHQYNXLHBYRJAF9CYHBTPLICYPLSNXWRDOYMNGTQWUULVBHAGRSRAWZNILTTZOODCFPOEAHSFTJYKHVV9NOVJJVHKYDEZVLCQTFDZBXJ9YMFFIU9LTIKGOGWZAQ9QYIHCZ9MCSRHMBIWKQHDXLJOTAPWYITAJADUAKAPJQCJJ9RONBMCVJQXDV9QPKYXZZOURPGEGAJEKLCUSI9WWHOFFR9JQBW9PZKQTUBID9QHOPYX9WOQJQEUZTPDMASDKQCH9GHQSCMZUDMVAUZTWQHRYNAUVHPNRGLOCXTCUTETPILSNIZDIPBV9JWUJRSRXYLPBEQTJEYOGRVUBLNWWRAFPADN9NALCEYFUEOEYKS9YHMSKCUWFAZW9GPHXPKQMTMY9WXIDNXFYIXYXKAYOPALYTBGNHZOLXVKMIGUHARABDRWH9VXJWZNWBVLJUAPJXEYJY9LHMNZGQQLUSSMTPKVLIJENAGVICZJ9TEMJVJQX9MRDHQQJUNQPTRUWM9FDJ9EUNEGZV9VOFNFLEKSIYYFTHHVMVQCKBAEUTSIXXNPUEPKWMRCLTGHOLNQKPIMMNJYBDQKY9PAVXMFWHZFBJXNFVTHNXABNFLKLHNOHFEYXOUHIH9WZWBCRHMVVFLJTWPQRWPFQGPYYW9WUJXADWWZGWSOPPCGGLNAU9IHWHDAOWSMACHVQUYZYKHQEHUVXRE9MHTUETTLRCWKFADNOZTGFEAIFMIUCLUYSHPKKXMROXMCUPNLZAMWIPXGAZI9QFZ9EMQXMM9UQCWCOJKRCAIMQ9DWRCXKLILTITAU9RFNRIB9TIPJJ9JJRFJFFMOZCOMDENCD9UTUGPRGROFMBGWMKQNZWZMGHYZFTDA9TKIO9OXIXRICNWZHSRGKYXFGYEXHSSTZZFHFBSXODXIDSQIJZG9FJIUTRTIUPZLODGEGPLNB9IDNBXNSZDWUKJOWRTMBGDWQSDLVJVXFLINHAAKLBXSKIDADRUXQTP9BYLEASUBWLPMVJUAZQNMZJYDHLSGRFUWPARUSLXDHILLIEDNEWDMLSESVVFSGQPCBKHEOCYRUWUDDMMBS999NZNHWAMXKFIJWVGRYH9STNSYUWSSZRAEAULFJKUHXTLANQDFAUBKSK9OGMQGXHYUTRNIGIPFXBMUXYWPRQHY99999999999999999999999999999999999999999999D9DWACD99A99999999C99999999RV9BHSYRJLJHR9RGEHWHQUOKYQRQ9Q9SKPIAYO9PAVKJLZYUHHOBDLWUJMEAZZIQN9DVJGDIATKLAGCYYANUD99KXNEMCXJQXNPBWIXCUFZMYFYLLDRTOR9VNZD9KULOLDOVEZGSOLJOMUDSVSPYHVQZZQX9ZA9999PWRRZN9UNKJJDDCLSFPKT9YHCWGETPD9ELURTFPDUKBJSQDTPQXLEWYYQKETKUUQL9HHBTDMQNRQA9999TB9CONFIRMER999999999999999YCRAVHHQF999999999MMMMMMMMMYF9QTDLHAXTIUUYW99RYRBAMH9R",
        "VXNWKEJDTZIWMADEGVNKZNDQFMACCM9DMGQKNCZGSEQAFTRYRTVJBJYEMVLHHFEUKWOAWSHXIARXKNYG9JYUOL9PQCIMZTFVUI9GJOCCARVVWVXNUASUPCXITDFLPLZMIYRUQYYGTJCFVCQQHCUBYBGDOLVKBYARXWMIJWLBFHECCTQAUQOAWXKKKLNHGHSOWMGJPQRENOAJRROKRITCNGVD99JEVZBPBFBQL9OVEG9MYOYEHIAKLTDUEU9HGO9II9F9LT9KXUOGWDPROCEZDJLKOUWEZYQMVUYCXOVCRCIHLFHGVXSKZVFBEHECTHRWZKSWPKEKIQNLJXAANHPBPOQUNFTCJS9RGLCVMSNWESLMNANNHWFLDCBOYZVZSIRGQXEWTHJ9VDQZ9P9ZFRPV9PPXGUENUGQXHTWJECJRRLUNEDZTOCUJRIQAIHAMOVCFKNAHGJXHUAMHJRBTEQMFAOGMRMFGLTBXDEQZKDMUHZDFPPTZPVSCJJYETNR9TFQIXKXMMIJXEIBGXPLGAALHHCKHMQD9LZUAAJVAAZXS99NNQDGBKLJZFA9RXCAISGPHTLUSIBDXKXFVNHVMMPINXQTOIXBAVMDSMRSDLOUFGTHKCEWVF9KPDXNHQWNJCYISHUWGHAGCZXXWLBMYRMOVXWSOZRNMCQBRUWNWCDOTHTOF9QDQZPRMMUXZXBGQEUNDMAZIN9JVNSPOKWZLV9QDYEAPDAQKWNSRJTPIIMGJMEIPPW9PINRTAWXQVUCIEQPYYFEBNBXNGCGFIKDINSD9VQLQOTMVZDUUHDTECYMAYXWQOO9VPSIRV9ABIYYHGTOEGDWLVFGI9SVIQKVJDMATCPK9VAWQEWVVZXFJPBYFZ9RAJXMNHAAOSJAIIDXBORNCHGNZQOZIFMDHQTEPQAVZVQGJOAH9LLZAPEGPSMFVWRHC9N9MZDCYZJMPVVLQVBLAFKUPWEUPVCHXUKUNBJGERNKNQ9EOGJ9P9VKTDEULWHPJSPESJJHZPV9YLVCVYPVTJLC9CMBWBWBLVKNBFUBURRVI9QUFCVOHPU9OVHBFPLMNDLIGOLZFJQNBXDBCOIOYZPDCOZJQVVVHCRVWYUDXCKKIVDPPCGTYUYWKIEUASYU99COMHKKMCQ9S9GKWZYKSKVFFSVDLZFSJHAP9DYHK9HRZKIIFGXUHUXNQESJUUKTGZUNGHOSYSPIRTUJIGFXASBADTUUAXRXYWL9DBGPLXLBXOLPMNZDFAQBJCBUMXEJENNAD9YVTMLPZUQZGWQPPK9OKBNDAHMWPQRA9WH9QOXWCVEYYXNNGRDHPLG9FOWAUUYJVBHPKPNIETEZMBHQZNFBHEBKBYCDKUPNDZOZKGG9SJFXYPILVDEFSCQZOILKCWJ9PUBG9UQOSXXIMJBQMBKSVTCLHQA9OQSKAFMMPGCNJNVPOGPWLUP9HHRRWNBGXTDDAUCCAZXNKOTQTHHMBNGVKKTNMGBIQYE9NKAUYOCQVESJDLLYGRVTPU99GXQEXZQJOPINWXLBMGSKSKZLAMLCPATKEAYLOTG9YYHMQXWVCDJYT9LNGDCKOVGUPTHWYQCKPKTYEESZOLHZXCICKGCY9GTOF9OLUZYSJFSBDDDPGSMQKGGWHDTWAAJJYKZUIGXMYHZJ9RHK9DCHNIXOAFQPYAWYXQUKGOF9P9EJPPWYSHLZMGQGQ9JCEBNEJMFFKVOWNWZUKDATNABDDNVFZXXYZYYUGZFBSNQMCH9YBCRYSAFSEHUIDEYFCLEPZVNBFKPXNYJFMVAKWTKDUKMUNXUWMXHJSLTLYUZNBCPBYCYXZHWQWVYGQKMJ9W9YRVREXCBCANHQVYZQYLNAORXNOBKG9NGBAZAAWFVGQMGVQWUWRUSMMFNFEXWJEVYARMRNNIFDFXZNBHYTWMOGP9EXEER9WAHPPRUYEHVBAGUBUCVDAHVBPFTIB9OBOGIBWKRHNVTIOMTVOKSJQLGYMVSOZU99IYGNIMKVWYIRXLEFVZCUIZRONZLVY9VVBNAMYAJNMCUMUSAPHIFPZXKWBNNUZNESNZQIKIZUTZXCJPAPDD99D9AOSXUDPIQTES9OZXMMYUMPM9IPJYOUFVXCI9VVJB9SQJGTBDYFVKSDMQXHNULAFTWLH9ZWWDIADZCJEOOZDWXLMDZXLQASZWYYJYHNJ9EVTDUSKYGWMMBS999NZNHWAMXKFIJWVGRYH9STNSYUWSSZRAEAULFJKUHXTLANQDFAUBKSK9OGMQGXHYUTRNIGIPFXB999999999999999999999999999999999999999999999999999999D9DWACD99B99999999C99999999RV9BHSYRJLJHR9RGEHWHQUOKYQRQ9Q9SKPIAYO9PAVKJLZYUHHOBDLWUJMEAZZIQN9DVJGDIATKLAGCYYOWEUPIHBAQIPHAVQQKAGGOZEGBECSDHFXTOMJZITBGDZNCIQAHEWOIZ9QYQAPMUGYBVINPPTPKTM99999PWRRZN9UNKJJDDCLSFPKT9YHCWGETPD9ELURTFPDUKBJSQDTPQXLEWYYQKETKUUQL9HHBTDMQNRQA9999TB9CONFIRMER999999999999999UHQAVHHQF999999999MMMMMMMMM9I9YROZDZQKJUSQIUMFAFE9YIL9",
        "999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999LMR9WUQTKFOGKGCIZQUURDDUYIPJWKVHDLLKTXGMJCIHJJCRJPPDDNKLHDABNHZPIPPAIOCM9ZHVMQMODKLBDQBRIRB99999999999999999999999999999999999999999999D9DWACD99C99999999C99999999RV9BHSYRJLJHR9RGEHWHQUOKYQRQ9Q9SKPIAYO9PAVKJLZYUHHOBDLWUJMEAZZIQN9DVJGDIATKLAGCYYPWRRZN9UNKJJDDCLSFPKT9YHCWGETPD9ELURTFPDUKBJSQDTPQXLEWYYQKETKUUQL9HHBTDMQNRQA9999PWRRZN9UNKJJDDCLSFPKT9YHCWGETPD9ELURTFPDUKBJSQDTPQXLEWYYQKETKUUQL9HHBTDMQNRQA9999TB9CONFIRMER999999999999999QOQAVHHQF999999999MMMMMMMMMIGZZ99H9INKISZ9KRIXIJZIZ9CW",
    ];
    let _ = get_outgoing_bundle_builder(
        &transactions
            .iter()
            .map(|t| {
                TryteBuf::try_from_str(&t.to_string())
                    .unwrap()
                    .as_trits()
                    .encode()
            })
            .collect::<Vec<TritBuf<T1B1Buf>>>(),
    )
    .await
    .unwrap();
}

#[tokio::test]
pub async fn test_obsolete_tag_creation() {
    let essences = vec![
        "EDIKZYSKVIWNNTMKWUSXKFMYQVIMBNECNYKBG9YVRKUMXNIXSVAKTIDCAHULLLXR9FSQSDDOFOJWKFACD",
        "A99999999999999999999999999999999999999999999999999999999999999999999999C99999999",
        "BMLAF9QKVBYJTGHTGFFNOVDTGEMA9MSXGTJYSRRHEYTMMKRMQYETPJVAADGYLPYMGBJERKLJVUZUZYRQD",
        "Z99999999999999999999999999999999999999999999999999999999999999A99999999C99999999",
        "BMLAF9QKVBYJTGHTGFFNOVDTGEMA9MSXGTJYSRRHEYTMMKRMQYETPJVAADGYLPYMGBJERKLJVUZUZYRQD",
        "999999999999999999999999999999999999999999999999999999999999999B99999999C99999999",
        "BMLAF9QKVBYJTGHTGFFNOVDTGEMA9MSXGTJYSRRHEYTMMKRMQYETPJVAADGYLPYMGBJERKLJVUZUZYRQD",
        "999999999999999999999999999999999999999999999999999999999999999C99999999C99999999",
    ];
    let final_hash =
        "NNNNNNFAHTZDAMSFMGDCKRWIMMVPVISUYXKTFADURMAEMTNFGBUMODCKQZPMWHUGISUOCWQQL99ZTGCJD";
    let kerl = prepare_keccak_384(
        &essences[..essences.len() - 1]
            .iter()
            .map(|t| {
                TryteBuf::try_from_str(&t.to_string())
                    .unwrap()
                    .as_trits()
                    .encode()
            })
            .collect::<Vec<TritBuf<T1B1Buf>>>(),
    )
    .await;
    let mut last_essence: TritBuf<T1B1Buf> = TryteBuf::try_from_str(essences[essences.len() - 1])
        .unwrap()
        .as_trits()
        .encode();

    let obselete_tag = create_obsolete_tag(3, 0).await;
    last_essence = update_essense_with_new_obsolete_tag(last_essence, &obselete_tag).await;
    let hash = absorb_and_get_normalized_bundle_hash(kerl, &last_essence).await;

    let hash_str = trit_buf_to_string(&hash).await;
    assert_eq!(String::from(final_hash), hash_str);
}

#[tokio::test]
pub async fn test_obsolete_tag_increment() {
    let essences = vec![
        "EDIKZYSKVIWNNTMKWUSXKFMYQVIMBNECNYKBG9YVRKUMXNIXSVAKTIDCAHULLLXR9FSQSDDOFOJWKFACD",
        "A99999999999999999999999999999999999999999999999999999999999999999999999C99999999",
        "BMLAF9QKVBYJTGHTGFFNOVDTGEMA9MSXGTJYSRRHEYTMMKRMQYETPJVAADGYLPYMGBJERKLJVUZUZYRQD",
        "Z99999999999999999999999999999999999999999999999999999999999999A99999999C99999999",
        "BMLAF9QKVBYJTGHTGFFNOVDTGEMA9MSXGTJYSRRHEYTMMKRMQYETPJVAADGYLPYMGBJERKLJVUZUZYRQD",
        "999999999999999999999999999999999999999999999999999999999999999B99999999C99999999",
        "BMLAF9QKVBYJTGHTGFFNOVDTGEMA9MSXGTJYSRRHEYTMMKRMQYETPJVAADGYLPYMGBJERKLJVUZUZYRQD",
        "999999999999999999999999999999999999999999999999999999999999999C99999999C99999999",
    ];
    let final_hash =
        "NNNNNNFAHTZDAMSFMGDCKRWIMMVPVISUYXKTFADURMAEMTNFGBUMODCKQZPMWHUGISUOCWQQL99ZTGCJD";
    let kerl = prepare_keccak_384(
        &essences[..essences.len() - 1]
            .iter()
            .map(|t| {
                TryteBuf::try_from_str(&t.to_string())
                    .unwrap()
                    .as_trits()
                    .encode()
            })
            .collect::<Vec<TritBuf<T1B1Buf>>>(),
    )
    .await;
    let mut last_essence: TritBuf<T1B1Buf> = TryteBuf::try_from_str(essences[essences.len() - 1])
        .unwrap()
        .as_trits()
        .encode();

    let obselete_tag = create_obsolete_tag(0, 0).await;
    last_essence = update_essense_with_new_obsolete_tag(last_essence, &obselete_tag).await;
    let last_essence = increase_essense(last_essence).await;
    let last_essence = increase_essense(last_essence).await;
    let last_essence = increase_essense(last_essence).await;
    let hash = absorb_and_get_normalized_bundle_hash(kerl, &last_essence).await;

    let hash_str = trit_buf_to_string(&hash).await;
    assert_eq!(String::from(final_hash), hash_str);
}

#[tokio::test]
pub async fn test_worker() {
    let essences = vec![
        "EDIKZYSKVIWNNTMKWUSXKFMYQVIMBNECNYKBG9YVRKUMXNIXSVAKTIDCAHULLLXR9FSQSDDOFOJWKFACD",
        "A99999999999999999999999999999999999999999999999999999999999999999999999C99999999",
        "BMLAF9QKVBYJTGHTGFFNOVDTGEMA9MSXGTJYSRRHEYTMMKRMQYETPJVAADGYLPYMGBJERKLJVUZUZYRQD",
        "Z99999999999999999999999999999999999999999999999999999999999999A99999999C99999999",
        "BMLAF9QKVBYJTGHTGFFNOVDTGEMA9MSXGTJYSRRHEYTMMKRMQYETPJVAADGYLPYMGBJERKLJVUZUZYRQD",
        "999999999999999999999999999999999999999999999999999999999999999B99999999C99999999",
        "BMLAF9QKVBYJTGHTGFFNOVDTGEMA9MSXGTJYSRRHEYTMMKRMQYETPJVAADGYLPYMGBJERKLJVUZUZYRQD",
        "999999999999999999999999999999999999999999999999999999999999999C99999999C99999999",
    ];
    let final_hash =
        "NNNNNNFAHTZDAMSFMGDCKRWIMMVPVISUYXKTFADURMAEMTNFGBUMODCKQZPMWHUGISUOCWQQL99ZTGCJD";
    async_mining_worker(
        0,
        0,
        essences
            .iter()
            .map(|t| {
                TryteBuf::try_from_str(&t.to_string())
                    .unwrap()
                    .as_trits()
                    .encode()
            })
            .collect::<Vec<TritBuf<T1B1Buf>>>(),
        TryteBuf::try_from_str(&final_hash.to_string())
            .unwrap()
            .as_trits()
            .encode(),
    )
    .await;
}
