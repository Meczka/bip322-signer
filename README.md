
# Bitcoin Bip322 Signer

This tool is aiming to simplify message signing process on bitcoin. This was tested on subber.

 Simply pass private key in WIF format and message:
```
simple_signature_with_wif_segwit(message: &str, wif: &str) -> &str
simple_signature_with_wif_taproot(message: &str, wif: &str) -> &str
```



Currently only Nested Segwit and Taproot addresses are supported. Support for other address types will be added if there will be need for them.


## Installation

Add crate to dependencies

```
  [dependencies]
  bip322-simple = "0.3.1"
```


## FFI

To compile to a static linked library. Clone the source and compile it with following command:

```
cargo build --features ffi --release
```

Exported functions have following signatures:
```
pub extern "C" fn signature_with_wif_segwit(
        message: *const c_char,
        wif: *const c_char,
    ) -> *const c_char

pub extern "C" fn signature_with_wif_taproot(
        message: *const c_char,
        wif: *const c_char,
    ) -> *const c_char
```

