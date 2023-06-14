pub mod hashing;
pub mod wallet;

use base64::{engine::general_purpose, Engine};
use bitcoin::{
    absolute, ecdsa,
    psbt::{PartiallySignedTransaction, SignError},
    secp256k1::{Message, Secp256k1, Signing},
    sighash::{EcdsaSighashType, SighashCache},
    OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use wallet::Wallet;
const UTXO: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const TAG: &str = "BIP0322-signed-message";

fn create_to_spend(message: &str, wallet: &Wallet) -> Txid {
    let tag_hash = hashing::hash_sha256(&TAG.as_bytes().to_vec());
    let mut concat_for_result = Vec::new();
    concat_for_result.extend(tag_hash.clone());
    concat_for_result.extend(tag_hash);
    concat_for_result.extend(message.as_bytes().to_vec());
    let result = hashing::hash_sha256(&concat_for_result);

    //Create script sig
    let mut script_sig = Vec::new();
    script_sig.extend(hex::decode("0020").unwrap());
    script_sig.extend(result);

    //Tx ins
    let ins = vec![TxIn {
        previous_output: OutPoint {
            txid: UTXO.parse().unwrap(),
            vout: 0xFFFFFFFF,
        },
        script_sig: ScriptBuf::from_bytes(script_sig),
        sequence: Sequence(0),
        witness: Witness::new(),
    }];

    //Tx outs
    let outs = vec![TxOut {
        value: 0,
        script_pubkey: wallet.desc.script_pubkey(),
    }];

    let tx = Transaction {
        version: 0,
        lock_time: absolute::LockTime::ZERO,
        input: ins,
        output: outs,
    };
    tx.txid()
}
fn create_to_sign_empty(txid: Txid, wallet: &Wallet) -> PartiallySignedTransaction {
    //Tx ins
    let ins = vec![TxIn {
        previous_output: OutPoint { txid, vout: 0 },
        script_sig: ScriptBuf::new(),
        sequence: Sequence(0),
        witness: Witness::new(),
    }];

    //Tx outs
    let outs = vec![TxOut {
        value: 0,
        script_pubkey: ScriptBuf::from_bytes(hex::decode("6a").unwrap()),
    }];

    let tx = Transaction {
        version: 0,
        lock_time: absolute::LockTime::ZERO,
        input: ins,
        output: outs,
    };
    let mut psbt = PartiallySignedTransaction::from_unsigned_tx(tx).unwrap();
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: 0,
        script_pubkey: wallet.desc.script_pubkey(),
    });
    psbt
}
fn get_base64_signature<C: Signing>(
    to_sign_empty: PartiallySignedTransaction,
    wallet: &Wallet,
    secp: &Secp256k1<C>,
) -> String {
    let redeem_script = ScriptBuf::new_v0_p2wpkh(&wallet.pubkey.wpubkey_hash().unwrap());
    let script_code = ScriptBuf::p2wpkh_script_code(&redeem_script)
        .ok_or(SignError::NotWpkh)
        .unwrap();
    let binding = to_sign_empty.unsigned_tx;
    let mut cache = SighashCache::new(&binding);
    let message = cache
        .segwit_signature_hash(0, &script_code, 0, EcdsaSighashType::All)
        .unwrap();
    let message = Message::from_slice(message.as_ref()).unwrap();
    let signature = secp.sign_ecdsa(&message, &wallet.private_key.inner);
    let sig = ecdsa::Signature {
        sig: signature,
        hash_ty: EcdsaSighashType::All,
    };
    let witness = vec![sig.to_vec(), wallet.pubkey.to_bytes()];

    let result: Vec<u8> = witness_to_vec(witness);
    general_purpose::STANDARD.encode(result)
}
fn witness_to_vec(witness: Vec<Vec<u8>>) -> Vec<u8> {
    let mut ret_val: Vec<u8> = Vec::new();
    ret_val.push(witness.len() as u8);
    for item in witness {
        ret_val.push(item.len() as u8);
        ret_val.extend(item);
    }
    ret_val
}
pub fn simple_signature_with_wif(message: &str, wif: &str) -> String {
    let secp = Secp256k1::new();
    let wallet = Wallet::new(wif, &secp);
    let txid = create_to_spend(message, &wallet);
    let to_sign = create_to_sign_empty(txid, &wallet);
    get_base64_signature(to_sign, &wallet, &secp)
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_to_spend() {
        let secp = Secp256k1::new();
        let wallet = Wallet::new(
            "L3gn3CheHVnEJHApMjb6BuKdc45LzqChEebLMQaMh3V7cMh6qsaM",
            &secp,
        );
        assert_eq!(
            create_to_spend("test", &wallet).to_string(),
            "b5cb848389f3ee72a8984560f6ae19f4a8dec1cd2d7e799d62f3e38ff121271c"
        );
    }

    #[test]
    fn test_base64_encoded_signature() {
        let secp = Secp256k1::new();
        let wallet = Wallet::new(
            "L3gn3CheHVnEJHApMjb6BuKdc45LzqChEebLMQaMh3V7cMh6qsaM",
            &secp,
        );
        let txid = create_to_spend("test", &wallet);
        let to_sign = create_to_sign_empty(txid, &wallet);
        let signature = get_base64_signature(to_sign, &wallet, &secp);
        assert_eq!(signature, "AkcwRAIgcS8lDfTl7UAytHbZI9BT74uTYqIuQHHUxlFOGGmT5Q8CIAclpi1G295lXeeRfDXdUWfdlkWdhv0S8XFP8rNFfvnDASEDviPnXh+H71VQrKuWCm2FYhSGV9TPO4XJTPhu3fwhhPM=")
    }
    #[test]
    fn test_simple_sig() {
        assert_eq!(simple_signature_with_wif("test", "L3gn3CheHVnEJHApMjb6BuKdc45LzqChEebLMQaMh3V7cMh6qsaM"), "AkcwRAIgcS8lDfTl7UAytHbZI9BT74uTYqIuQHHUxlFOGGmT5Q8CIAclpi1G295lXeeRfDXdUWfdlkWdhv0S8XFP8rNFfvnDASEDviPnXh+H71VQrKuWCm2FYhSGV9TPO4XJTPhu3fwhhPM=")
    }
}
