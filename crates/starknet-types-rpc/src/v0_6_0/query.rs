use serde::{Deserialize, Serialize};


use super::{
    BroadcastedDeclareTxnV1, BroadcastedDeclareTxnV2, BroadcastedDeclareTxnV3, DeployAccountTxnV1, DeployAccountTxnV3, InvokeTxnV0, InvokeTxnV1, InvokeTxnV3
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "version")]
pub enum BroadcastedDeclareTxn {
    #[serde(rename = "0x1")]
    V1(BroadcastedDeclareTxnV1),
    #[serde(rename = "0x2")]
    V2(BroadcastedDeclareTxnV2),
    #[serde(rename = "0x3")]
    V3(BroadcastedDeclareTxnV3),
    /// Query-only broadcasted declare transaction.
    #[serde(rename = "0x100000000000000000000000000000001")]
    QueryV1(BroadcastedDeclareTxnV1),
    /// Query-only broadcasted declare transaction.
    #[serde(rename = "0x100000000000000000000000000000002")]
    QueryV2(BroadcastedDeclareTxnV2),
    /// Query-only broadcasted declare transaction.
    #[serde(rename = "0x100000000000000000000000000000003")]
    QueryV3(BroadcastedDeclareTxnV3),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "version")]
pub enum BroadcastedDeployAccountTxn {
    #[serde(rename = "0x1")]
    V1(DeployAccountTxnV1),
    #[serde(rename = "0x3")]
    V3(DeployAccountTxnV3),
    /// Query-only broadcasted deploy account transaction.
    #[serde(rename = "0x100000000000000000000000000000001")]
    QueryV1(DeployAccountTxnV1),
    /// Query-only broadcasted deploy account transaction.
    #[serde(rename = "0x100000000000000000000000000000003")]
    QueryV3(DeployAccountTxnV3),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "version")]
pub enum BroadcastedInvokeTxn {
    #[serde(rename = "0x0")]
    V0(InvokeTxnV0),
    #[serde(rename = "0x1")]
    V1(InvokeTxnV1),
    #[serde(rename = "0x3")]
    V3(InvokeTxnV3),    
    /// Query-only broadcasted invoke transaction.
    #[serde(rename = "0x100000000000000000000000000000000")]
    QueryV0(InvokeTxnV0),
    /// Query-only broadcasted invoke transaction.
    #[serde(rename = "0x100000000000000000000000000000001")]
    QueryV1(InvokeTxnV1),
    /// Query-only broadcasted invoke transaction.
    #[serde(rename = "0x100000000000000000000000000000003")]
    QueryV3(InvokeTxnV3),
}
