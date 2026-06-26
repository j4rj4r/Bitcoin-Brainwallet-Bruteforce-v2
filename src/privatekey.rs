use ripemd::Ripemd160;
use secp256k1::{PublicKey, Secp256k1, SecretKey, Signing};
use sha2::{Digest, Sha256};

const WIF_VERSION: u8 = 0x80;
const ADDRESS_VERSION: u8 = 0x00;
const COMPRESSED_WIF_SUFFIX: u8 = 0x01;

fn hash160(data: &[u8]) -> [u8; 20] {
    let sha = Sha256::digest(data);
    Ripemd160::digest(sha).into()
}

fn base58check(version: u8, payload: &[u8]) -> String {
    let mut bytes = Vec::with_capacity(1 + payload.len());
    bytes.push(version);
    bytes.extend_from_slice(payload);
    bs58::encode(bytes).with_check().into_string()
}

fn address_from_public_key(public_key: &PublicKey, compressed: bool) -> String {
    let pubkey_bytes: Vec<u8> = if compressed {
        public_key.serialize().to_vec()
    } else {
        public_key.serialize_uncompressed().to_vec()
    };
    base58check(ADDRESS_VERSION, &hash160(&pubkey_bytes))
}

/// Derives the P2PKH address directly from the raw private key bytes, without ever
/// detouring through a WIF string - skips the WIF-decode round trip that previously
/// dominated per-candidate cost.
pub fn address_from_private_key<C: Signing>(
    secp: &Secp256k1<C>,
    privkey: &[u8; 32],
    compressed: bool,
) -> Option<String> {
    let secret_key = SecretKey::from_byte_array(*privkey).ok()?;
    let public_key = PublicKey::from_secret_key(secp, &secret_key);
    Some(address_from_public_key(&public_key, compressed))
}

/// Same as calling `address_from_private_key` once per mode, but the EC scalar
/// multiplication (the expensive step) happens only once per private key - the
/// compressed and uncompressed addresses are just two encodings of the same point.
pub fn addresses_from_private_key<C: Signing>(
    secp: &Secp256k1<C>,
    privkey: &[u8; 32],
    modes: &[bool],
) -> Option<Vec<(bool, String)>> {
    let secret_key = SecretKey::from_byte_array(*privkey).ok()?;
    let public_key = PublicKey::from_secret_key(secp, &secret_key);
    Some(
        modes
            .iter()
            .map(|&compressed| (compressed, address_from_public_key(&public_key, compressed)))
            .collect(),
    )
}

/// Only called when a discovery is confirmed (rare) - never on the per-candidate hot path.
pub fn wif_from_private_key(privkey: &[u8; 32], compressed: bool) -> String {
    let mut payload = privkey.to_vec();
    if compressed {
        payload.push(COMPRESSED_WIF_SUFFIX);
    }
    base58check(WIF_VERSION, &payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn warpwallet_vector_wif_and_address() {
        let privkey = crate::schemes::warpwallet_scheme("ER8FT+HFjk0", "7DpniYifN6c");
        let wif = wif_from_private_key(&privkey, false);
        assert_eq!(wif, "5JfEekYcaAexqcigtFAy4h2ZAY95vjKCvS1khAkSG8ATo1veQAD");

        let secp = Secp256k1::new();
        let address = address_from_private_key(&secp, &privkey, false).unwrap();
        assert_eq!(address, "1J32CmwScqhwnNQ77cKv9q41JGwoZe2JYQ");
    }

    #[test]
    fn address_derived_directly_matches_address_derived_via_wif_decode() {
        let secp = Secp256k1::new();
        let privkey = crate::schemes::sha256_scheme("correct horse battery staple");

        for compressed in [false, true] {
            let direct = address_from_private_key(&secp, &privkey, compressed).unwrap();

            // Decode the WIF back to raw bytes + compression flag, the way `bit.Key(wif)`
            // used to, and re-derive - guards against ever reintroducing a version-byte mixup.
            let wif = wif_from_private_key(&privkey, compressed);
            let decoded = bs58::decode(&wif)
                .with_check(Some(WIF_VERSION))
                .into_vec()
                .unwrap();
            let payload = &decoded[1..]; // strip version byte
            let (decoded_privkey, decoded_compressed) = if payload.len() == 33 {
                (&payload[..32], true)
            } else {
                (payload, false)
            };
            assert_eq!(decoded_compressed, compressed);
            let mut decoded_privkey_arr = [0u8; 32];
            decoded_privkey_arr.copy_from_slice(decoded_privkey);
            assert_eq!(decoded_privkey_arr, privkey);

            let via_wif =
                address_from_private_key(&secp, &decoded_privkey_arr, decoded_compressed).unwrap();
            assert_eq!(direct, via_wif);
        }
    }

    #[test]
    fn addresses_from_private_key_matches_per_mode_derivation() {
        let secp = Secp256k1::new();
        let privkey = crate::schemes::sha256_scheme("correct horse battery staple");
        let modes = [false, true];

        let batched = addresses_from_private_key(&secp, &privkey, &modes).unwrap();
        let expected: Vec<(bool, String)> = modes
            .iter()
            .map(|&compressed| {
                (
                    compressed,
                    address_from_private_key(&secp, &privkey, compressed).unwrap(),
                )
            })
            .collect();
        assert_eq!(batched, expected);
    }
}
