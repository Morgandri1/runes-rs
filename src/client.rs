use std::str::FromStr;
use std::time::Duration;

use bitcoin::{Amount, Network, Transaction, Txid, Address};
use log::{debug, info};

use crate::wallet::Utxo;

#[derive(Debug, Clone, Copy)]
pub struct Client {
    pub network: Network
}
impl Client {
    pub fn new(network: Network) -> Self {
        Self { network }
    }
    
    pub async fn broadcast_transaction(
        self: Self,
        transaction: &Transaction,
    ) -> anyhow::Result<Txid> {
        let network_str = match self.network {
            Network::Testnet => "/testnet",
            Network::Regtest => "/regtest",
            Network::Signet => "/signet",
            _ => "",
        };
    
        let url = format!("https://blockstream.info{network_str}/api/tx");
        let tx_hex = hex::encode(bitcoin::consensus::serialize(&transaction));
        debug!("tx_hex ({}): {tx_hex}", tx_hex.len());
    
        let result = reqwest::Client::new()
            .post(&url)
            .body(tx_hex)
            .send()
            .await?;
    
        debug!("result: {:?}", result);
    
        if result.status().is_success() {
            let txid = result.text().await?;
            debug!("txid: {txid}");
            Ok(Txid::from_str(&txid)?)
        } else {
            Err(anyhow::anyhow!(
                "failed to broadcast transaction: {}",
                result.text().await?
            ))
        }
    }
    
    pub async fn sats_amount_from_tx_inputs(
        self: Self,
        inputs: &[(Txid, u32)],
    ) -> anyhow::Result<Vec<Utxo>> {
        let mut output_inputs = Vec::with_capacity(inputs.len());
        for (txid, index) in inputs {
            let tx = self.get_tx_by_hash(txid).await?;
            let output = tx
                .vout
                .get(*index as usize)
                .ok_or_else(|| anyhow::anyhow!("invalid index {} for txid {}", index, txid))?;
    
            output_inputs.push(Utxo {
                id: *txid,
                index: *index,
                amount: Amount::from_sat(output.value),
            });
        }
        Ok(output_inputs)
    }
    
    pub async fn get_tx_by_hash(self: Self, txid: &Txid) -> anyhow::Result<ApiTransaction> {
        let network_str = match self.network {
            Network::Testnet => "/testnet",
            Network::Regtest => "/regtest",
            Network::Signet => "/signet",
            _ => "",
        };
    
        let url = format!("https://blockstream.info{network_str}/api/tx/{}", txid);
        let tx = reqwest::get(&url).await?.json().await?;
        Ok(tx)
    }
    
    #[allow(dead_code)]
    pub async fn wait_for_tx(self: Self, txid: &Txid) -> anyhow::Result<()> {
        loop {
            tokio::time::sleep(Duration::from_secs(10)).await;
            if (&self).get_tx_by_hash(txid).await.is_ok() {
                break;
            }
            debug!("retrying in 10 seconds...");
        }
        Ok(())
    }
}


#[derive(Debug, serde::Deserialize)]
pub struct ApiTransaction {
    vout: Vec<ApiVout>,
}

#[derive(Debug, serde::Deserialize)]
pub struct ApiVout {
    value: u64,
}
#[cfg(test)]
pub mod ClientTests {
    use super::*;
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::{PublicKey, PrivateKey};
    
    #[test]
    fn test_instantiation() {
        let client = Client::new(Network::Testnet);
        assert_eq!(client.network, Network::Testnet);
    }
    
    #[tokio::test]
    async fn test_broadcast_transaction() {
        let network = Network::Testnet;
        let client = Client::new(network);
        let engine = Secp256k1::new();
        let ticker = "TEST";
        let amount = 100;
        let limit = 100;
        let (secret_key, public_key) = engine.generate_keypair(&mut rand::thread_rng());
        let pubkey = PublicKey::new(public_key);
        let private_key = PrivateKey::new(secret_key, network);
        let sender_address = Address::p2wpkh(&pubkey, network).unwrap();
        
        let Fees {
            commit_fee,
            reveal_fee,
            ..
        } = calc_fees(network);
        info!("Commit fee: {commit_fee}, reveal fee: {reveal_fee}",);
    
        let inputs = client.sats_amount_from_tx_inputs(&inputs).await?;
    
        debug!("getting commit transaction...");
        let mut builder = match args.script_type.as_str() {
            "p2tr" | "P2TR" => OrdTransactionBuilder::p2tr(private_key),
            "p2wsh" | "P2WSH" => OrdTransactionBuilder::p2wsh(private_key),
            _ => panic!("invalid script type"),
        };
    
        let commit_tx = builder
            .build_commit_transaction(
                network,
                CreateCommitTransactionArgs {
                    inputs,
                    inscription: Brc20::deploy(ticker, amount, Some(limit), None),
                    txin_script_pubkey: sender_address.script_pubkey(),
                    leftovers_recipient: sender_address.clone(),
                    commit_fee,
                    reveal_fee,
                },
            )
            .await?;
        debug!("commit transaction: {commit_tx:?}");
    }
    
}
