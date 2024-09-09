use std::str::FromStr;

use fake::Dummy;
use num_bigint::BigUint;
use starknet_types_core::felt::Felt;
use serde_with::serde_conv;
// use tagged::Tagged;
// use tagged_debug_derive::TaggedDebug;


#[serde_with::serde_as]
#[derive(Clone, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Event {
    #[serde_as(as = "Vec<EventDataAsDecimalStr>")]
    pub data: Vec<Felt>,
    pub from_address: Felt,
    #[serde_as(as = "Vec<EventKeyAsDecimalStr>")]
    pub keys: Vec<Felt>,
}

serde_conv!(
    EventDataAsDecimalStr,
    Felt,
    |serialize_me: &Felt| starkhash_to_dec_str(&serialize_me),
    |s: &str| starkhash_from_dec_str(s)
);
serde_conv!(
    EventKeyAsDecimalStr,
    Felt,
    |serialize_me: &Felt| starkhash_to_dec_str(&serialize_me),
    |s: &str| starkhash_from_dec_str(s));

/// A helper conversion function. Only use with __sequencer API related types__.
fn starkhash_to_dec_str(h: &Felt) -> String {
    let b = h.to_bytes_be();
    let b = BigUint::from_bytes_be(&b);
    b.to_str_radix(10)
}

/// A helper conversion function. Only use with __sequencer API related types__.
fn starkhash_from_dec_str(s: &str) -> Result<Felt, anyhow::Error> {
    match BigUint::from_str(s) {
        Ok(b) => {
            let h = Felt::from_bytes_be_slice(&b.to_bytes_be());
            Ok(h)
        }
        Err(_) => {
            let h = Felt::from_dec_str(s).unwrap();
            Ok(h)
        }
    }
}
