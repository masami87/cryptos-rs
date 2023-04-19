use crate::crypto::{
    ripemd160::ripemd160,
    secp256k1::{secp256k1_generator, Point},
    sha256::sha256,
};
use crate::error::Result;
use crate::network::Net;

use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::{ToPrimitive, Zero};
pub(crate) struct PublicKey<'a>(Point<'a>);

impl<'a> PublicKey<'a> {
    pub fn from_point(point: &Point<'a>) -> Self {
        PublicKey(point.clone())
    }

    pub fn from_sk(sk: &BigInt) -> Self {
        let pk_point = sk.clone() * secp256k1_generator();
        PublicKey::from_point(&pk_point)
    }

    pub fn encode(&self, compressed: bool, hash160: bool) -> Result<Vec<u8>> {
        let publick_key = match compressed {
            true => {
                // (x,y) is very redundant. Because y^2 = x^3 + 7,
                // we can just encode x, and then y = +/- sqrt(x^3 + 7),
                // so we need one more bit to encode whether it was the + or the -
                // but because this is modular arithmetic there is no +/-, instead
                // it can be shown that one y will always be even and the other odd.
                let prefix = if self.0.y.is_even() { b"\x02" } else { b"\x03" };
                let mut tmp = prefix.to_vec();
                tmp.extend(self.0.x.to_bytes_be().1);
                tmp
            }
            false => {
                let prefix = b"\x04";
                prefix
                    .iter()
                    .chain(self.0.x.to_bytes_be().1.iter())
                    .cloned()
                    .collect::<Vec<_>>()
            }
        };
        if hash160 {
            Ok(ripemd160(&sha256(&publick_key)))
        } else {
            Ok(publick_key)
        }
    }

    /// Return the associated bitcoin address for this public key as string
    pub fn address(&self, net: Net, compressed: bool) -> Result<String> {
        let pkb_hash = self.encode(compressed, true)?;

        let version = match net {
            Net::Main => b"\x00",
            Net::Test => b"\x6f",
        };

        let version_pkb_hash = version
            .iter()
            .chain(pkb_hash.iter())
            .cloned()
            .collect::<Vec<_>>();

        let checksum: Vec<u8> = sha256(&sha256(&version_pkb_hash))
            .iter()
            .take(4)
            .cloned()
            .collect();

        let mut byte_address = version_pkb_hash.clone();
        byte_address.extend_from_slice(&checksum);

        let b58check_address = base_58_check(&byte_address);
        b58check_address
    }
}

fn base_58_check(data: &[u8]) -> Result<String> {
    if data.len() != 25 {
        return Err(crate::error::CryptosError::Key(
            "the length of data != 25".to_string(),
        ));
    }
    let mut n = BigInt::from_signed_bytes_be(data);
    let mut i: BigInt;
    let mut chars = String::new();
    while !n.is_zero() {
        (n, i) = n.div_mod_floor(&BigInt::from(58));
        chars.push(BASE58_CHARS.chars().nth(i.to_usize().unwrap()).unwrap());
    }
    let zeros = data
        .iter()
        .take_while(|&b| *b == 0x00 as u8)
        .map(|_| BASE58_CHARS.chars().nth(0).unwrap());
    Ok(zeros.chain(chars.chars().rev()).collect())
}
const BASE58_CHARS: &'static str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::crypto::secp256k1::secp256k1_generator;

    use super::*;
    use hex::{self, ToHex};
    use num_bigint::BigInt;
    use num_traits::{Num, One};

    #[test]
    fn test_btc_addresses() -> Result<()> {
        // https://www.blockchain.com/explorer/addresses/btc-testnet/mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r
        let sk: BigInt = One::one();
        let pk_point = sk * secp256k1_generator();
        let pk = PublicKey::from_point(&pk_point);
        let address = pk.address(Net::Test, true)?;
        assert_eq!(&address, "mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r");

        // https://www.blockchain.com/btc-testnet/address/mnNcaVkC35ezZSgvn8fhXEa9QTHSUtPfzQ
        let sk = BigInt::from_str("22265090479312778178772228083027296664144").unwrap();
        let pk_point = sk * secp256k1_generator();
        let pk = PublicKey::from_point(&pk_point);
        let address = pk.address(Net::Test, true)?;
        assert_eq!(&address, "mnNcaVkC35ezZSgvn8fhXEa9QTHSUtPfzQ");

        // https://github.com/karpathy/cryptos/blob/main/tests/test_keys.py
        // tuples of (net, compressed, secret key in hex, expected compressed bitcoin address string in b58check)
        let sk_hex1 = BigInt::from(2020_i32).pow(5).to_str_radix(16);
        let test_cases = vec![
            (
                "main",
                true,
                "3aba4162c7251c891207b747840551a71939b0de081f85c4e44cf7c13e41daa6",
                "14cxpo3MBCYYWCgF74SWTdcmxipnGUsPw3",
            ),
            (
                "main",
                true,
                "18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725",
                "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs",
            ),
            (
                "main",
                true,
                "12345deadbeef",
                "1F1Pn2y6pDb68E5nYJJeba4TLg2U7B6KF1",
            ),
            ("test", true, &sk_hex1, "mopVkxp8UhXqRYbCYJsbeE1h1fiF64jcoH"),
        ];

        test_cases
            .into_iter()
            .for_each(|(net, compressed, sk_hex, expect)| {
                let sk = BigInt::from_str_radix(sk_hex, 16).unwrap();
                let pk = PublicKey::from_sk(&sk);
                let address = pk.address(Net::from(net), compressed).unwrap();
                assert_eq!(&address, expect,);
            });
        Ok(())
    }

    #[test]
    fn test_public_key_hash() -> Result<()> {
        let sk = BigInt::from_str("22265090479312778178772228083027296664144").unwrap();
        let pk = PublicKey::from_sk(&sk);
        let hash = pk.encode(true, true)?;
        assert_eq!(
            hash.encode_hex::<String>(),
            "4b3518229b0d3554fe7cd3796ade632aff3069d8"
        );
        Ok(())
    }
}
