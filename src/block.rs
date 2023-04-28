use std::io::{BufReader, Read};

use num_bigint::{BigInt, Sign};
use num_traits::{Num, Pow, ToPrimitive};

use crate::crypto::sha256::sha256;
use crate::encoding::{decode_int, encode_int};
use crate::Result;

const MAIN_GENESIS_BLOCK: &str = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c";
const TEST_GENESIS_BLOCK: &str = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff001d1aa4ae18";

fn bits_to_target(bits: &[u8]) -> BigInt {
    let exponent = bits[bits.len() - 1];
    let coeff = BigInt::from_bytes_le(Sign::Plus, &[bits[0], bits[1], bits[2]]);
    let target = coeff * BigInt::from(256u64).pow(exponent - 3);
    target
}

fn target_to_bits(target: BigInt) -> Vec<u8> {
    let b: Vec<u8> = target
        .to_bytes_be()
        .1
        .to_vec()
        .into_iter()
        .skip_while(|&x| x == 0)
        .collect();
    let (exponent, coeff) = (b.len() as u8, b[0..3].to_vec());
    let mut new_bits = coeff;
    new_bits.reverse();
    new_bits.push(exponent);
    new_bits
}

fn calculate_new_bits(prev_bits: &[u8], dt: u64) -> Vec<u8> {
    let two_weeks = 60 * 60 * 24 * 14;
    let dt = dt.max(two_weeks / 4).min(two_weeks * 4);
    let prev_target = bits_to_target(prev_bits);
    let new_target = prev_target * dt as u64 / two_weeks as u64;
    let new_target =
        new_target.min(BigInt::from(0xffff) * BigInt::from(256u64).pow(0x1d as u8 - 3));
    let new_bits = target_to_bits(new_target);
    new_bits
}

#[derive(Debug)]
pub struct Block {
    version: i32,
    prev_block: Vec<u8>,
    merkle_root: Vec<u8>,
    timestamp: u32,
    bits: Vec<u8>,
    nonce: Vec<u8>,
}

impl Block {
    pub fn decode_bytes(bytes: &[u8]) -> Result<Block> {
        let mut r = BufReader::new(bytes);
        Self::decode(&mut r)
    }
    pub fn decode(s: &mut dyn Read) -> Result<Block> {
        let version = decode_int(s, 4)? as i32;
        let mut prev_block = [0u8; 32];
        s.read_exact(&mut prev_block)?;
        prev_block.reverse();
        let mut merkle_root = [0u8; 32];
        s.read_exact(&mut merkle_root)?;
        merkle_root.reverse();
        let timestamp = decode_int(s, 4)? as u32;
        let mut bits = [0u8; 4];
        s.read_exact(&mut bits)?;
        let mut nonce = [0u8; 4];
        s.read_exact(&mut nonce)?;
        Ok(Block {
            version,
            prev_block: prev_block.to_vec(),
            merkle_root: merkle_root.to_vec(),
            timestamp,
            bits: bits.to_vec(),
            nonce: nonce.to_vec(),
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = vec![];
        out.extend_from_slice(&encode_int(self.version as u64, 4)?);
        out.extend_from_slice(&self.prev_block.iter().rev().cloned().collect::<Vec<u8>>());
        out.extend_from_slice(&self.merkle_root.iter().rev().cloned().collect::<Vec<u8>>());
        out.extend_from_slice(&encode_int(self.timestamp as u64, 4)?);
        out.extend_from_slice(&self.bits);
        out.extend_from_slice(&self.nonce);
        Ok(out)
    }

    pub fn id(&self) -> Result<String> {
        let mut hash = sha256(&sha256(&self.encode()?));
        hash.reverse();
        Ok(hex::encode(hash))
    }

    pub fn target(&self) -> BigInt {
        bits_to_target(&self.bits)
    }

    pub fn difficulty(&self) -> f64 {
        let genesis_block_target = BigInt::from(0xffff) * BigInt::from(256u64).pow(0x1d as u8 - 3);
        (genesis_block_target / self.target()).to_f64().unwrap()
    }

    pub fn validate(&self) -> Result<bool> {
        if BigInt::from_str_radix(&self.id()?, 16).unwrap() >= self.target() {
            return Ok(false);
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_block() -> Result<()> {
        let raw = hex::decode("020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d")?;
        let block = Block::decode_bytes(&raw)?;
        assert_eq!(block.version, 0x20000002);
        assert_eq!(block.timestamp, 0x59a7771e);
        assert_eq!(block.bits, hex::decode("e93c0118")?);
        assert_eq!(block.nonce, hex::decode("a4ffd71d")?);
        assert_eq!(
            block.prev_block,
            hex::decode("000000000000000000fd0c220a0a8c3bc5a7b487e8c8de0dfa2373b12894c38e")?
        );
        assert_eq!(
            block.merkle_root,
            hex::decode("be258bfd38db61f957315c3f9e9c5e15216857398d50402d5089a8e0fc50075b")?
        );

        let raw2 = block.encode()?;
        assert_eq!(raw, raw2);
        assert_eq!(
            block.id()?,
            "0000000000000000007e9e4c586439b0cdbe13b1370bdd9435d76a644d047523".to_string()
        );
        assert_eq!(
            block.target().to_str_radix(16),
            "13ce9000000000000000000000000000000000000000000"
        );
        Ok(())
    }

    #[test]
    fn test_validate() -> Result<()> {
        let raw = hex::decode("04000000fbedbbf0cfdaf278c094f187f2eb987c86a199da22bbb20400000000000000007b7697b29129648fa08b4bcd13c9d5e60abb973a1efac9c8d573c71c807c56c3d6213557faa80518c3737ec1")?;
        let block = Block::decode_bytes(&raw)?;
        assert_eq!(block.validate()?, true);

        let raw = hex::decode("04000000fbedbbf0cfdaf278c094f187f2eb987c86a199da22bbb20400000000000000007b7697b29129648fa08b4bcd13c9d5e60abb973a1efac9c8d573c71c807c56c3d6213557faa80518c3737ec0")?;
        let block = Block::decode_bytes(&raw)?;
        assert_eq!(block.validate()?, false);
        Ok(())
    }

    #[test]
    fn test_calculate_bits() -> Result<()> {
        let dt = 302400;
        let prev_bits = hex::decode("54d80118")?;
        let next_bits = calculate_new_bits(&prev_bits, dt);
        assert_eq!(hex::encode(&next_bits), "00157617");

        // make sure encoding/decidng of bits <-> target works
        for bits in vec![prev_bits, next_bits] {
            let target = bits_to_target(&bits);
            let bits2 = target_to_bits(target);
            assert_eq!(bits, bits2);
        }

        Ok(())
    }

    #[test]
    fn test_genesis_block() -> Result<()> {
        // Validate the Bitcoin mainnet genesis block header
        // Reference: https://en.bitcoin.it/wiki/Genesis_block
        // Original code: https://sourceforge.net/p/bitcoin/code/133/tree/trunk/main.cpp#l1613
        let block_bytes = hex::decode(MAIN_GENESIS_BLOCK)?;
        assert_eq!(block_bytes.len(), 80);

        let block = Block::decode_bytes(&block_bytes)?;
        assert_eq!(block.version, 1);
        assert_eq!(block.prev_block, [0u8; 32].to_vec());
        assert_eq!(
            block.merkle_root,
            hex::decode("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b")?
        );
        assert_eq!(block.timestamp, 1231006505);
        assert_eq!(
            block.bits.iter().cloned().rev().collect::<Vec<_>>(),
            hex::decode("1d00ffff")?
        );
        assert_eq!(
            BigInt::from_bytes_le(Sign::Plus, &block.nonce),
            BigInt::from(2083236893)
        );

        // validate proof of work. by two extra zeros, too!
        assert_eq!(
            block.id()?,
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        );
        assert_eq!(block.validate()?, true);
        Ok(())
    }
}
