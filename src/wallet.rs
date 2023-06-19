use bitcoin::{
    secp256k1::{Secp256k1, Signing},
    PrivateKey, PublicKey,
};
use miniscript::Descriptor;

pub struct Wallet {
    pub pubkey: PublicKey,
    pub private_key: PrivateKey,
    pub desc: Descriptor<PublicKey>,
}
pub enum WalletType {
    NativeSegwit,
    Taproot,
}
impl Wallet {
    pub fn new<C: Signing>(wif: &str, wallet_type: WalletType, secp: &Secp256k1<C>) -> Self {
        let private_key = PrivateKey::from_wif(wif).unwrap();
        let pubkey = private_key.public_key(secp);
        let desc = match wallet_type {
            WalletType::NativeSegwit => Descriptor::new_wpkh(pubkey).unwrap(),
            WalletType::Taproot => Descriptor::new_tr(pubkey, None).unwrap(),
        };

        Self {
            pubkey,
            private_key,
            desc,
        }
    }
}
