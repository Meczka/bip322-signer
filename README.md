
# Bitcoin Bip322 Signer

This tool is aiming to simplify message signing process on bitcoin. Simply pass private key in WIF format and message:
```
simple_signature_with_wif(message: &str, wif: &str) -> &str
```



Currently only Nested Segwit addresses are supported. Support for other address types will be added if there will be need for them.


## Installation

Add crate to dependencies

```
  [dependencies]
  bip322-simple = "0.1.0"
```
    