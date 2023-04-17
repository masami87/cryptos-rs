use std::convert::TryFrom;

use crate::{CryptosError, Result};

pub enum Cmd {
    Num(u8),
    Bytes(Vec<u8>),
}
pub struct Script {
    cmds: Vec<Cmd>,
}

impl Script {
    pub fn new(cmds: Vec<Cmd>) -> Self {
        Script { cmds }
    }

    pub fn encode(self) -> Result<Vec<u8>> {
        let mut out: Vec<u8> = vec![];
        for cmd in self.cmds {
            match cmd {
                Cmd::Num(n) => {
                    // an int is just an opcode, encode as a single byte
                    out.push(n);
                }
                Cmd::Bytes(c) => {
                    let len = c.len();
                    if len >= 75 {
                        return Err(CryptosError::Internal(format!("too long: {}", len)));
                    }
                    out.push(len as u8);
                    out.extend(c.iter());
                }
            }
        }
        let mut result = encode_varint(out.len() as u64)?;
        result.extend(out.iter());
        Ok(result)
    }
}

fn encode_int(i: u64, nbytes: usize) -> Result<Vec<u8>> {
    let bytes = i.to_le_bytes();
    if nbytes > bytes.len() {
        return Err(CryptosError::Internal(format!(
            "nbytes too long: {}",
            nbytes
        )));
    }
    Ok(bytes[..nbytes].to_vec())
}

fn encode_varint(i: u64) -> Result<Vec<u8>> {
    if i < 0xfd {
        Ok(vec![u8::try_from(i).unwrap()])
    } else if i < 0x10000 {
        Ok([0xfd].iter().cloned().chain(encode_int(i, 2)?).collect())
    } else if i < 0x100000000 {
        Ok([0xfe].iter().cloned().chain(encode_int(i, 4)?).collect())
    } else {
        Ok([0xff].iter().cloned().chain(encode_int(i, 8)?).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::secp256k1::secp256k1_generator,
        key::{Net, PublicKey},
    };
    use hex::ToHex;
    use num_bigint::BigInt;
    use std::str::FromStr;

    #[test]
    fn test_script_encode() -> Result<()> {
        // https://karpathy.github.io/2021/06/21/blockchain/
        let sk1 = BigInt::from_str("22265090479312778178772228083027296664144").unwrap();
        let pk1 = PublicKey::from_sk(&sk1);
        let pkh1 = pk1.encode(true, true)?;
        assert_eq!(
            &pkh1.encode_hex::<String>(),
            "4b3518229b0d3554fe7cd3796ade632aff3069d8"
        );

        let sk2 = BigInt::from_str(
            "29595381593786747354608258168471648998894101022644411052850960746671046944116",
        )
        .unwrap();
        let pk2 = PublicKey::from_sk(&sk2);
        let pkh2 = pk2.encode(true, true)?;
        assert_eq!(
            &pkh2.encode_hex::<String>(),
            "75b0c9fc784ba2ea0839e3cdf2669495cac67073"
        );

        // OP_DUP, OP_HASH160, <hash>, OP_EQUALVERIFY, OP_CHECKSIG
        let out1_script = Script::new(vec![
            Cmd::Num(118),
            Cmd::Num(169),
            Cmd::Bytes(pkh2),
            Cmd::Num(136),
            Cmd::Num(172),
        ]);
        assert_eq!(
            out1_script.encode()?.encode_hex::<String>(),
            "1976a91475b0c9fc784ba2ea0839e3cdf2669495cac6707388ac"
        );

        let out2_script = Script::new(vec![
            Cmd::Num(118),
            Cmd::Num(169),
            Cmd::Bytes(pkh1),
            Cmd::Num(136),
            Cmd::Num(172),
        ]);
        assert_eq!(
            out2_script.encode()?.encode_hex::<String>(),
            "1976a9144b3518229b0d3554fe7cd3796ade632aff3069d888ac"
        );
        Ok(())
    }
}
