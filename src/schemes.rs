use pbkdf2::pbkdf2_hmac;
use scrypt::Params as ScryptParams;
use sha2::{Digest, Sha256};

/// WarpWallet's scrypt cost factor is N=2^18 (log2(N)=18), r=8, p=1 - deliberately
/// expensive so each derivation takes roughly half a second.
const WARPWALLET_SCRYPT_LOG_N: u8 = 18;
const WARPWALLET_SCRYPT_R: u32 = 8;
const WARPWALLET_SCRYPT_P: u32 = 1;
const WARPWALLET_PBKDF2_ITERATIONS: u32 = 65536;

pub const WARPWALLET_APPROX_SECONDS_PER_DERIVATION: f64 = 0.5;

#[derive(Clone)]
pub enum Scheme {
    Sha256,
    Sha256d,
    Warpwallet { salt: String },
}

impl Scheme {
    pub fn from_name(name: &str, salt: &str) -> Option<Scheme> {
        match name {
            "sha256" => Some(Scheme::Sha256),
            "sha256d" => Some(Scheme::Sha256d),
            "warpwallet" => Some(Scheme::Warpwallet {
                salt: salt.to_string(),
            }),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Scheme::Sha256 => "sha256",
            Scheme::Sha256d => "sha256d",
            Scheme::Warpwallet { .. } => "warpwallet",
        }
    }

    pub fn derive(&self, passphrase: &str) -> [u8; 32] {
        match self {
            Scheme::Sha256 => sha256_scheme(passphrase),
            Scheme::Sha256d => sha256d_scheme(passphrase),
            Scheme::Warpwallet { salt } => warpwallet_scheme(passphrase, salt),
        }
    }
}

pub fn sha256_scheme(passphrase: &str) -> [u8; 32] {
    Sha256::digest(passphrase.as_bytes()).into()
}

pub fn sha256d_scheme(passphrase: &str) -> [u8; 32] {
    let once: [u8; 32] = Sha256::digest(passphrase.as_bytes()).into();
    Sha256::digest(once).into()
}

pub fn warpwallet_scheme(passphrase: &str, salt: &str) -> [u8; 32] {
    let mut s1_input = passphrase.as_bytes().to_vec();
    s1_input.push(0x01);
    let mut s1_salt = salt.as_bytes().to_vec();
    s1_salt.push(0x01);

    let params = ScryptParams::new(
        WARPWALLET_SCRYPT_LOG_N,
        WARPWALLET_SCRYPT_R,
        WARPWALLET_SCRYPT_P,
    )
    .expect("static WarpWallet scrypt params are valid");
    let mut s1 = [0u8; 32];
    scrypt::scrypt(&s1_input, &s1_salt, &params, &mut s1)
        .expect("32-byte output is within scrypt's valid range");

    let mut s2_input = passphrase.as_bytes().to_vec();
    s2_input.push(0x02);
    let mut s2_salt = salt.as_bytes().to_vec();
    s2_salt.push(0x02);

    let mut s2 = [0u8; 32];
    pbkdf2_hmac::<Sha256>(&s2_input, &s2_salt, WARPWALLET_PBKDF2_ITERATIONS, &mut s2);

    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = s1[i] ^ s2[i];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn warpwallet_official_test_vector() {
        let privkey = warpwallet_scheme("ER8FT+HFjk0", "7DpniYifN6c");
        assert_eq!(
            to_hex(&privkey),
            "6f2552e159f2a1e1e26c2262da459818fd56c81c363fcc70b94c423def42e59f"
        );
    }

    #[test]
    fn sha256_scheme_is_plain_sha256() {
        let privkey = sha256_scheme("correct horse battery staple");
        assert_eq!(
            privkey,
            Sha256::digest(b"correct horse battery staple").as_slice()
        );
    }

    #[test]
    fn sha256d_scheme_hashes_twice() {
        let once: [u8; 32] = Sha256::digest(b"hello").into();
        let twice: [u8; 32] = Sha256::digest(once).into();
        assert_eq!(sha256d_scheme("hello"), twice);
    }
}
