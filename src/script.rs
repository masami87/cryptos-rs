use std::{
    fmt::Debug,
    io::{BufReader, Read},
    ops::Add,
};

use crate::{
    crypto::{
        ecdsa::{verify, Signature},
        ripemd160::ripemd160,
        sha256::sha256,
    },
    encoding::{decode_int, decode_varint, encode_int, encode_varint},
    key::PublicKey,
    CryptosError, Result,
};

#[derive(Debug, Clone)]
pub enum Cmd {
    Op(u8),
    Bytes(Vec<u8>),
}

impl Cmd {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Cmd::Op(op) => vec![*op],
            Cmd::Bytes(bytes) => bytes.clone(),
        }
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        match bytes.len() {
            1 => Ok(Self::Op(bytes[0])),
            0 => Err(CryptosError::Internal("empty bytes for cmd".to_string())),
            _ => Ok(Self::Bytes(bytes.to_vec())),
        }
    }
}
#[derive(Clone)]
pub struct Script {
    pub cmds: Vec<Cmd>,
}

impl Debug for Script {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Script").field("cmds", &self.cmds).finish()
    }
}

impl PartialEq for Cmd {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Op(l0), Self::Op(r0)) => l0 == r0,
            (Self::Bytes(l0), Self::Bytes(r0)) => l0 == r0,
            _ => false,
        }
    }
}

impl PartialEq for Script {
    fn eq(&self, other: &Self) -> bool {
        if self.cmds.len() != other.cmds.len() {
            return false;
        }
        self.cmds
            .iter()
            .zip(other.cmds.iter())
            .all(|(lhs, rhs)| lhs == rhs)
    }
}

impl Add for Script {
    type Output = Script;

    fn add(self, rhs: Self) -> Self::Output {
        Script {
            cmds: [self.cmds, rhs.cmds].concat(),
        }
    }
}

impl Script {
    pub fn new(cmds: Vec<Cmd>) -> Self {
        Script { cmds }
    }

    pub fn decode_bytes(bytes: &[u8]) -> Result<Self> {
        let mut reader = BufReader::new(bytes);
        Self::decode(&mut reader)
    }

    pub fn decode(reader: &mut dyn Read) -> Result<Self> {
        let mut cmds = vec![];

        let len = decode_varint(reader)? as usize;

        let mut count = 0usize;

        while count < len {
            let mut buf = [0u8; 1];
            reader.read_exact(&mut buf)?;
            let current = buf[0];
            count += 1;
            if current >= 1 && current <= 75 {
                // elements of size [1, 75] bytes
                let mut buf = vec![0u8; current as usize];
                reader.read_exact(&mut buf)?;
                cmds.push(Cmd::Bytes(buf));
                count += current as usize;
            } else if current == 76 {
                let data_len = decode_int(reader, 1)?;
                let mut buf = vec![0u8; data_len as usize];
                reader.read_exact(&mut buf)?;
                cmds.push(Cmd::Bytes(buf));
                count += data_len as usize + 1;
            } else if current == 77 {
                let data_len = decode_int(reader, 2)?;
                let mut buf = vec![0u8; data_len as usize];
                reader.read_exact(&mut buf)?;
                cmds.push(Cmd::Bytes(buf));
                count += data_len as usize + 2;
            } else {
                cmds.push(Cmd::Op(current));
            }
        }

        if count != len {
            return Err(CryptosError::Internal("parsing script failed".to_string()));
        }

        Ok(Self { cmds })
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out: Vec<u8> = vec![];
        for cmd in self.cmds.iter() {
            match cmd {
                Cmd::Op(n) => {
                    // an int is just an opcode, encode as a single byte
                    out.push(*n);
                }
                Cmd::Bytes(c) => {
                    let len = c.len() as u64;
                    if len < 75 {
                        out.extend(encode_int(len, 1)?);
                    } else if len >= 76 && len <= 255 {
                        out.extend(encode_int(76, 1)?);
                        out.extend(encode_int(len, 1)?);
                    } else if len >= 256 && len < 520 {
                        out.extend(encode_int(77, 1)?);
                        out.extend(encode_int(len, 2)?);
                    } else {
                        return Err(CryptosError::Internal(format!("too long: {}", len)));
                    }

                    out.extend(c.iter());
                }
            }
        }
        let mut result = encode_varint(out.len() as u64)?;
        result.extend(out.iter());
        Ok(result)
    }

    pub fn evalueate(&self, mod_tx_enc: &[u8]) -> Result<bool> {
        // for now let's just support a standard p2pkh transaction
        assert_eq!(self.cmds.len(), 7);

        // signature
        assert!(matches!(self.cmds[0], Cmd::Bytes(_)));
        // pubkey
        assert!(matches!(self.cmds[1], Cmd::Bytes(_)));
        // OP_DUP
        assert!(matches!(self.cmds[2], Cmd::Op(118)));
        // OP_HASH160
        assert!(matches!(self.cmds[3], Cmd::Op(169)));
        // hash
        assert!(matches!(self.cmds[4], Cmd::Bytes(_)));
        // OP_EQUALVERIFY
        assert!(matches!(self.cmds[5], Cmd::Op(136)));
        // OP_CHECKSIG
        assert!(matches!(self.cmds[6], Cmd::Op(172)));

        // verify the public key hash, answering the OP_EQUALVERIFY challenge
        let (pubkey, pubkey_hash) = (&self.cmds[1], &self.cmds[4]);
        let hash = ripemd160(&sha256(&pubkey.encode()));
        if hash != pubkey_hash.encode() {
            return Ok(false);
        }

        // verify the digital signature of the transaction, answering the OP_CHECKSIG challenge
        // DER encoded signature, but crop out the last byte
        let mut der = self.cmds[0].encode().clone();
        let sighash_type = der.pop().ok_or(CryptosError::Internal(format!(
            "no sighash type in {:?}",
            self.cmds[0]
        )))?;
        assert_eq!(sighash_type, 1);

        // public key without hash
        let sec = self.cmds[1].encode();
        let pk = PublicKey::decode(&sec)?;

        let sig = Signature::decode(&der);

        let valid = verify(&pk, mod_tx_enc, &sig);

        Ok(valid)
    }
}

#[cfg(test)]
mod tests {
    use crate::key::PublicKey;

    use super::*;
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
            Cmd::Op(118),
            Cmd::Op(169),
            Cmd::Bytes(pkh2),
            Cmd::Op(136),
            Cmd::Op(172),
        ]);
        assert_eq!(
            out1_script.encode()?.encode_hex::<String>(),
            "1976a91475b0c9fc784ba2ea0839e3cdf2669495cac6707388ac"
        );

        let out2_script = Script::new(vec![
            Cmd::Op(118),
            Cmd::Op(169),
            Cmd::Bytes(pkh1),
            Cmd::Op(136),
            Cmd::Op(172),
        ]);
        assert_eq!(
            out2_script.encode()?.encode_hex::<String>(),
            "1976a9144b3518229b0d3554fe7cd3796ade632aff3069d888ac"
        );
        Ok(())
    }

    #[test]
    fn test_script_decode() -> Result<()> {
        let pkh1 = hex::decode("4b3518229b0d3554fe7cd3796ade632aff3069d8")?;
        let pkh2 = hex::decode("75b0c9fc784ba2ea0839e3cdf2669495cac67073")?;

        let out1_script = Script::new(vec![
            Cmd::Op(118),
            Cmd::Op(169),
            Cmd::Bytes(pkh2),
            Cmd::Op(136),
            Cmd::Op(172),
        ]);
        let encode_str1 = "1976a91475b0c9fc784ba2ea0839e3cdf2669495cac6707388ac";
        assert_eq!(
            Script::decode_bytes(&hex::decode(encode_str1)?)?,
            out1_script
        );

        let out2_script = Script::new(vec![
            Cmd::Op(118),
            Cmd::Op(169),
            Cmd::Bytes(pkh1),
            Cmd::Op(136),
            Cmd::Op(172),
        ]);
        let encode_str1 = "1976a9144b3518229b0d3554fe7cd3796ade632aff3069d888ac";
        assert_eq!(
            Script::decode_bytes(&hex::decode(encode_str1)?)?,
            out2_script
        );

        Ok(())
    }
}
