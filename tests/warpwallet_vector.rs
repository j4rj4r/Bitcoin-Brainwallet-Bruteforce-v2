use brainwallet_bruteforce::privatekey::{address_from_private_key, wif_from_private_key};
use brainwallet_bruteforce::schemes::warpwallet_scheme;
use secp256k1::Secp256k1;

/// The official WarpWallet test vector, carried all the way from passphrase to
/// address - the single most valuable correctness check in this crate, since it
/// proves scrypt params, pbkdf2 iterations, the XOR combine, WIF encoding and
/// address derivation are all simultaneously correct (a mistake in any one of
/// them would produce the wrong final address).
#[test]
fn official_vector_end_to_end() {
    let privkey = warpwallet_scheme("ER8FT+HFjk0", "7DpniYifN6c");

    let privkey_hex: String = privkey.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        privkey_hex,
        "6f2552e159f2a1e1e26c2262da459818fd56c81c363fcc70b94c423def42e59f"
    );

    let wif = wif_from_private_key(&privkey, false);
    assert_eq!(wif, "5JfEekYcaAexqcigtFAy4h2ZAY95vjKCvS1khAkSG8ATo1veQAD");

    let secp = Secp256k1::new();
    let address = address_from_private_key(&secp, &privkey, false).unwrap();
    assert_eq!(address, "1J32CmwScqhwnNQ77cKv9q41JGwoZe2JYQ");
}
