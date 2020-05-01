//! Encoding and decoding functions for Zcash key and address structs.
//!
//! Human-Readable Prefixes (HRPs) for Bech32 encodings are located in the [`constants`]
//! module.

use bech32::{self, Error, FromBase32, ToBase32};
use bs58::{self, decode::DecodeError};
use pairing::bls12_381::Bls12;
use std::io::{self, Write};
use zcash_primitives::{
    jubjub::edwards,
    primitives::{Diversifier, PaymentAddress},
};
use zcash_primitives::{
    legacy::TransparentAddress,
    zip32::{ExtendedFullViewingKey, ExtendedSpendingKey},
    JUBJUB,
};

fn bech32_encode<F>(hrp: &str, write: F) -> String
where
    F: Fn(&mut dyn Write) -> io::Result<()>,
{
    let mut data: Vec<u8> = vec![];
    write(&mut data).expect("Should be able to write to a Vec");
    bech32::encode(hrp, data.to_base32()).expect("hrp is invalid")
}

fn bech32_decode<T, F>(hrp: &str, s: &str, read: F) -> Result<Option<T>, Error>
where
    F: Fn(Vec<u8>) -> Option<T>,
{
    let (decoded_hrp, data) = bech32::decode(s)?;
    if decoded_hrp == hrp {
        Vec::<u8>::from_base32(&data).map(|data| read(data))
    } else {
        Ok(None)
    }
}

/// Writes an [`ExtendedSpendingKey`] as a Bech32-encoded string.
///
/// # Examples
///
/// ```
/// use zcash_client_backend::{
///     constants::testnet::{COIN_TYPE, HRP_SAPLING_EXTENDED_SPENDING_KEY},
///     encoding::encode_extended_spending_key,
///     keys::spending_key,
/// };
///
/// let extsk = spending_key(&[0; 32][..], COIN_TYPE, 0);
/// let encoded = encode_extended_spending_key(HRP_SAPLING_EXTENDED_SPENDING_KEY, &extsk);
/// ```
pub fn encode_extended_spending_key(hrp: &str, extsk: &ExtendedSpendingKey) -> String {
    bech32_encode(hrp, |w| extsk.write(w))
}

/// Decodes an [`ExtendedSpendingKey`] from a Bech32-encoded string.
pub fn decode_extended_spending_key(
    hrp: &str,
    s: &str,
) -> Result<Option<ExtendedSpendingKey>, Error> {
    bech32_decode(hrp, s, |data| ExtendedSpendingKey::read(&data[..]).ok())
}

/// Writes an [`ExtendedFullViewingKey`] as a Bech32-encoded string.
///
/// # Examples
///
/// ```
/// use zcash_client_backend::{
///     constants::testnet::{COIN_TYPE, HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY},
///     encoding::encode_extended_full_viewing_key,
///     keys::spending_key,
/// };
/// use zcash_primitives::zip32::ExtendedFullViewingKey;
///
/// let extsk = spending_key(&[0; 32][..], COIN_TYPE, 0);
/// let extfvk = ExtendedFullViewingKey::from(&extsk);
/// let encoded = encode_extended_full_viewing_key(HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY, &extfvk);
/// ```
pub fn encode_extended_full_viewing_key(hrp: &str, extfvk: &ExtendedFullViewingKey) -> String {
    bech32_encode(hrp, |w| extfvk.write(w))
}

/// Decodes an [`ExtendedFullViewingKey`] from a Bech32-encoded string.
pub fn decode_extended_full_viewing_key(
    hrp: &str,
    s: &str,
) -> Result<Option<ExtendedFullViewingKey>, Error> {
    bech32_decode(hrp, s, |data| ExtendedFullViewingKey::read(&data[..]).ok())
}

/// Writes a [`PaymentAddress`] as a Bech32-encoded string.
///
/// # Examples
///
/// ```
/// use pairing::bls12_381::Bls12;
/// use rand_core::SeedableRng;
/// use rand_xorshift::XorShiftRng;
/// use zcash_client_backend::{
///     constants::testnet::HRP_SAPLING_PAYMENT_ADDRESS,
///     encoding::encode_payment_address,
/// };
/// use zcash_primitives::{
///     jubjub::edwards,
///     primitives::{Diversifier, PaymentAddress},
///     JUBJUB,
/// };
///
/// let rng = &mut XorShiftRng::from_seed([
///     0x59, 0x62, 0xbe, 0x3d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
///     0xbc, 0xe5,
/// ]);
///
/// let pa = PaymentAddress {
///     diversifier: Diversifier([0u8; 11]),
///     pk_d: edwards::Point::<Bls12, _>::rand(rng, &JUBJUB).mul_by_cofactor(&JUBJUB),
/// };
///
/// assert_eq!(
///     encode_payment_address(HRP_SAPLING_PAYMENT_ADDRESS, &pa),
///     "ytestsapling1qqqqqqqqqqqqqqqqqrjq05nyfku05msvu49mawhg6kr0wwljahypwyk2h88z6975u563j9k7cxg",
/// );
/// ```
pub fn encode_payment_address(hrp: &str, addr: &PaymentAddress<Bls12>) -> String {
    bech32_encode(hrp, |w| {
        w.write_all(&addr.diversifier.0)?;
        addr.pk_d.write(w)
    })
}

/// Decodes a [`PaymentAddress`] from a Bech32-encoded string.
///
/// # Examples
///
/// ```
/// use pairing::bls12_381::Bls12;
/// use rand_core::SeedableRng;
/// use rand_xorshift::XorShiftRng;
/// use zcash_client_backend::{
///     constants::testnet::HRP_SAPLING_PAYMENT_ADDRESS,
///     encoding::decode_payment_address,
/// };
/// use zcash_primitives::{
///     jubjub::edwards,
///     primitives::{Diversifier, PaymentAddress},
///     JUBJUB,
/// };
///
/// let rng = &mut XorShiftRng::from_seed([
///     0x59, 0x62, 0xbe, 0x3d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
///     0xbc, 0xe5,
/// ]);
///
/// let pa = PaymentAddress {
///     diversifier: Diversifier([0u8; 11]),
///     pk_d: edwards::Point::<Bls12, _>::rand(rng, &JUBJUB).mul_by_cofactor(&JUBJUB),
/// };
///
/// assert_eq!(
///     decode_payment_address(
///         HRP_SAPLING_PAYMENT_ADDRESS,
///         "ytestsapling1qqqqqqqqqqqqqqqqqrjq05nyfku05msvu49mawhg6kr0wwljahypwyk2h88z6975u563j9k7cxg",
///     ),
///     Ok(Some(pa)),
/// );
/// ```
pub fn decode_payment_address(hrp: &str, s: &str) -> Result<Option<PaymentAddress<Bls12>>, Error> {
    bech32_decode(hrp, s, |data| {
        let mut diversifier = Diversifier([0; 11]);
        diversifier.0.copy_from_slice(&data[0..11]);
        // Check that the diversifier is valid
        if diversifier.g_d::<Bls12>(&JUBJUB).is_none() {
            return None;
        }

        edwards::Point::<Bls12, _>::read(&data[11..], &JUBJUB)
            .ok()?
            .as_prime_order(&JUBJUB)
            .map(|pk_d| PaymentAddress { pk_d, diversifier })
    })
}

/// Writes a [`TransparentAddress`] as a Base58Check-encoded string.
///
/// # Examples
///
/// ```
/// use zcash_client_backend::{
///     constants::testnet::{B58_PUBKEY_ADDRESS_PREFIX, B58_SCRIPT_ADDRESS_PREFIX},
///     encoding::encode_transparent_address,
/// };
/// use zcash_primitives::legacy::TransparentAddress;
///
/// assert_eq!(
///     encode_transparent_address(
///         &B58_PUBKEY_ADDRESS_PREFIX,
///         &B58_SCRIPT_ADDRESS_PREFIX,
///         &TransparentAddress::PublicKey([0; 20]),
///     ),
///     "smD3VYXz481ZvyUAs5k9yARaPE1B4ySFMDJ",
/// );
///
/// ```
pub fn encode_transparent_address(
    pubkey_version: &[u8],
    script_version: &[u8],
    addr: &TransparentAddress,
) -> String {
    let decoded = match addr {
        TransparentAddress::PublicKey(key_id) => {
            let mut decoded = vec![0; pubkey_version.len() + 20];
            decoded[..pubkey_version.len()].copy_from_slice(pubkey_version);
            decoded[pubkey_version.len()..].copy_from_slice(key_id);
            decoded
        }
        TransparentAddress::Script(script_id) => {
            let mut decoded = vec![0; script_version.len() + 20];
            decoded[..script_version.len()].copy_from_slice(script_version);
            decoded[script_version.len()..].copy_from_slice(script_id);
            decoded
        }
    };
    bs58::encode(decoded).with_check().into_string()
}

/// Decodes a [`TransparentAddress`] from a Base58Check-encoded string.
///
/// # Examples
///
/// ```
/// use zcash_client_backend::{
///     constants::testnet::{B58_PUBKEY_ADDRESS_PREFIX, B58_SCRIPT_ADDRESS_PREFIX},
///     encoding::decode_transparent_address,
/// };
/// use zcash_primitives::legacy::TransparentAddress;
///
/// assert_eq!(
///     decode_transparent_address(
///         &B58_PUBKEY_ADDRESS_PREFIX,
///         &B58_SCRIPT_ADDRESS_PREFIX,
///         "smD3VYXz481ZvyUAs5k9yARaPE1B4ySFMDJ",
///     ),
///     Ok(Some(TransparentAddress::PublicKey([0; 20]))),
/// );
///
/// ```
pub fn decode_transparent_address(
    pubkey_version: &[u8],
    script_version: &[u8],
    s: &str,
) -> Result<Option<TransparentAddress>, DecodeError> {
    let decoded = bs58::decode(s).with_check(None).into_vec()?;
    if &decoded[..pubkey_version.len()] == pubkey_version {
        if decoded.len() == pubkey_version.len() + 20 {
            let mut data = [0; 20];
            data.copy_from_slice(&decoded[pubkey_version.len()..]);
            Ok(Some(TransparentAddress::PublicKey(data)))
        } else {
            Ok(None)
        }
    } else if &decoded[..script_version.len()] == script_version {
        if decoded.len() == script_version.len() + 20 {
            let mut data = [0; 20];
            data.copy_from_slice(&decoded[script_version.len()..]);
            Ok(Some(TransparentAddress::Script(data)))
        } else {
            Ok(None)
        }
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use pairing::bls12_381::Bls12;
    use rand_core::SeedableRng;
    use rand_xorshift::XorShiftRng;
    use zcash_primitives::JUBJUB;
    use zcash_primitives::{
        jubjub::edwards,
        primitives::{Diversifier, PaymentAddress},
    };

    use super::{decode_payment_address, encode_payment_address};
    use crate::constants;

    #[test]
    fn payment_address() {
        let rng = &mut XorShiftRng::from_seed([
            0x59, 0x62, 0xbe, 0x3d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);

        let addr = PaymentAddress {
            diversifier: Diversifier([0u8; 11]),
            pk_d: edwards::Point::<Bls12, _>::rand(rng, &JUBJUB).mul_by_cofactor(&JUBJUB),
        };

        let encoded_main =
            "ys1qqqqqqqqqqqqqqqqqrjq05nyfku05msvu49mawhg6kr0wwljahypwyk2h88z6975u563j87stas";
        let encoded_test =
            "ytestsapling1qqqqqqqqqqqqqqqqqrjq05nyfku05msvu49mawhg6kr0wwljahypwyk2h88z6975u563j9k7cxg";

        assert_eq!(
            encode_payment_address(constants::mainnet::HRP_SAPLING_PAYMENT_ADDRESS, &addr),
            encoded_main
        );
        assert_eq!(
            decode_payment_address(
                constants::mainnet::HRP_SAPLING_PAYMENT_ADDRESS,
                encoded_main
            )
            .unwrap(),
            Some(addr.clone())
        );

        assert_eq!(
            encode_payment_address(constants::testnet::HRP_SAPLING_PAYMENT_ADDRESS, &addr),
            encoded_test
        );
        assert_eq!(
            decode_payment_address(
                constants::testnet::HRP_SAPLING_PAYMENT_ADDRESS,
                encoded_test
            )
            .unwrap(),
            Some(addr)
        );
    }

    #[test]
    fn invalid_diversifier() {
        let rng = &mut XorShiftRng::from_seed([
            0x59, 0x62, 0xbe, 0x3d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);

        let addr = PaymentAddress {
            diversifier: Diversifier([1u8; 11]),
            pk_d: edwards::Point::<Bls12, _>::rand(rng, &JUBJUB).mul_by_cofactor(&JUBJUB),
        };

        let encoded_main =
            encode_payment_address(constants::mainnet::HRP_SAPLING_PAYMENT_ADDRESS, &addr);

        assert_eq!(
            decode_payment_address(
                constants::mainnet::HRP_SAPLING_PAYMENT_ADDRESS,
                &encoded_main
            )
            .unwrap(),
            None
        );
    }
}
