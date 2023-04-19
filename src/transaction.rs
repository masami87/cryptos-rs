use std::{
    fs,
    io::{BufReader, Cursor, Read, Write},
    path::Path,
};

use crate::{
    encoding::{decode_int, encode_int, encode_varint},
    network::Net,
    script::Script,
    CryptosError, Result,
};

pub(crate) struct Tx {
    version: i32,
    tx_ins: Vec<TxIn>,
    tx_outs: Vec<TxOut>,
    locktime: u64,
    net: Net,
}

impl Tx {
    fn new(version: i32, tx_ins: Vec<TxIn>, tx_outs: Vec<TxOut>) -> Self {
        Self {
            version,
            tx_ins,
            tx_outs,
            locktime: 0,
            net: Net::Test,
        }
    }
    fn decode(s: &mut dyn Read) -> Result<Self> {
        // decode version
        let mut version_bytes = [0u8; 4];
        s.read_exact(&mut version_bytes)?;
        let version = i32::from_le_bytes(version_bytes);

        // decode inputs

        todo!()
    }
    // Encode this transaction as bytes.
    // If sig_index is given then return the modified transaction
    // encoding of this tx with respect to the single input index.
    // This result then constitutes the "message" that gets signed
    // by the aspiring transactor of this input.
    fn encode(self, sig_index: Option<usize>) -> Result<Vec<u8>> {
        let mut out = vec![];
        // encode metadata
        out.extend(&self.version.to_le_bytes());
        // encode inputs
        out.extend(encode_varint(self.tx_ins.len() as u64)?);
        match sig_index {
            Some(sig_index) => {
                // used when crafting digital signature for a specific input index
                // for (i, tx_in) in self.tx_ins.iter().enumerate() {
                //     out.extend(tx_in.encode(sig_index == i.try_into().unwrap()));
                // }
            }
            None => todo!(),
        };
        todo!()
    }
}

pub struct TxIn {
    /// Prev transaction ID: hash256 of prev tx contents.
    prev_tx: Vec<u8>,
    /// UTXO output index in the transaction.
    prev_index: u32,
    /// Unlocking script.
    script_sig: Script,
    /// Almost not use today.
    sequence: u32,
    /// Network.
    net: Net,
}

impl Default for TxIn {
    fn default() -> Self {
        Self {
            prev_tx: Vec::new(),
            prev_index: 0,
            script_sig: Script::new(vec![]),
            sequence: 0,
            net: Net::Test,
        }
    }
}

impl TxIn {
    fn decode_bytes(bytes: &[u8]) -> Result<Self> {
        let mut reader = BufReader::new(bytes);
        Self::decode(&mut reader)
    }

    fn decode(r: &mut dyn Read) -> Result<Self> {
        let mut prev_tx_bytes = [0u8; 32];
        r.read_exact(&mut prev_tx_bytes)?;
        let mut prev_tx: Vec<u8> = prev_tx_bytes.to_vec();
        prev_tx.reverse();

        let prev_index = decode_int(r, 4)? as u32;
        let script_sig = Script::decode(r)?;
        let sequence = decode_int(r, 4)? as u32;
        Ok(Self {
            prev_tx,
            prev_index,
            script_sig,
            sequence,
            net: Net::Test,
        })
    }

    fn encode(&self, script_override: Option<bool>) -> Result<Vec<u8>> {
        let mut out: Vec<u8> = vec![];
        // little endian vs big endian encodings... sigh
        out.extend(self.prev_tx.iter().rev());
        out.extend(encode_int(self.prev_index as u64, 4)?);

        match script_override {
            Some(true) => {
                // True = override the script with the script_pubkey of the associated input
                todo!("TxFetcher")
            }
            Some(false) => {
                // False = override with an empty script
                out.extend(Script::new(vec![]).encode()?);
            }
            None => {
                // None = just use the actual script
                out.extend(self.script_sig.encode()?);
            }
        };

        out.extend(encode_int(self.sequence as u64, 4)?);
        Ok(out)
    }
}

pub struct TxOut {
    /// In units of satoshi(1e-8 of a bitcoin)
    amount: u64,
    /// Locking script.
    script_pubkey: Script,
}

impl Default for TxOut {
    fn default() -> Self {
        Self {
            amount: 0,
            script_pubkey: Script::new(vec![]),
        }
    }
}

impl TxOut {
    pub fn decode_bytes(bytes: &[u8]) -> Result<Self> {
        let mut reader = BufReader::new(bytes);
        Self::decode(&mut reader)
    }
    pub fn decode(r: &mut dyn Read) -> Result<Self> {
        let amount = decode_int(r, 8)?;
        let script_pubkey = Script::decode(r)?;
        Ok(Self {
            amount,
            script_pubkey,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = vec![];
        out.extend(encode_int(self.amount, 8)?);
        out.extend(self.script_pubkey.encode()?);
        Ok(out)
    }
}

/// Lazily fetches transactions using an api on demand.
struct TxFetcher;

impl TxFetcher {
    fn fetch(tx_id: &str, net: Net) -> Result<Tx> {
        if !tx_id.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(CryptosError::Internal("invalid tx_id".to_string()));
        }
        let tx_id = tx_id.to_lowercase();
        let txdb_dir = "txdb";
        let cache_file = format!("{}/{}", txdb_dir, tx_id);

        let raw = if Path::new(&cache_file).is_file() {
            // fetch bytes from local disk store
            // println!("reading transaction {} from disk cache", tx_id);
            fs::read(&cache_file).unwrap()
        } else {
            let url = match net {
                Net::Main => format!("https://blockstream.info/api/tx/{}/hex", tx_id),
                Net::Test => format!("https://blockstream.info/testnet/api/tx/{}/hex", tx_id),
            };
            let response = reqwest::blocking::get(&url)?.text()?.trim().to_string();
            let raw = hex::decode(&response)?;
            fs::create_dir_all(txdb_dir)?;
            let mut file = fs::File::create(&cache_file)?;
            file.write_all(&raw)?;
            raw
        };
        todo!("create tx")
    }
}

#[cfg(test)]
mod tests {
    use crate::script::Cmd;

    use super::*;

    #[test]
    fn test_tx_in_encode() -> Result<()> {
        let script = Script::new(vec![Cmd::Op(128), Cmd::Op(127)]);
        let prev_tx = (0..32).collect::<Vec<u8>>();
        let tx_in = TxIn {
            prev_tx: prev_tx.clone(),
            prev_index: 100,
            script_sig: script,
            sequence: 0,
            net: Net::Test,
        };
        let bytes: Vec<u8> = prev_tx
            .iter()
            .rev()
            .chain(vec![100, 0, 0, 0, 2, 128, 127, 0, 0, 0, 0].iter())
            .cloned()
            .collect();
        assert_eq!(tx_in.encode(None)?, bytes);
        Ok(())
    }

    #[test]
    fn test_tx_in_decode() -> Result<()> {
        let script = Script::new(vec![Cmd::Op(128), Cmd::Op(127)]);

        let prev_tx = (0..32).collect::<Vec<u8>>();
        let bytes: Vec<u8> = prev_tx
            .iter()
            .rev()
            .chain(vec![100, 0, 0, 0, 2, 128, 127, 0, 0, 0, 0].iter())
            .cloned()
            .collect();

        let decode_tx_in = TxIn::decode_bytes(&bytes)?;

        assert_eq!(decode_tx_in.prev_tx, prev_tx);
        assert_eq!(decode_tx_in.prev_index, 100);
        assert_eq!(decode_tx_in.script_sig, script);
        assert_eq!(decode_tx_in.sequence, 0);

        Ok(())
    }

    #[test]
    fn test_tx_out_encode() -> Result<()> {
        let script = Script::new(vec![Cmd::Op(128), Cmd::Op(127)]);
        let tx_out = TxOut {
            amount: 100,
            script_pubkey: script,
        };
        assert_eq!(
            tx_out.encode()?,
            vec![100, 0, 0, 0, 0, 0, 0, 0, 2, 128, 127]
        );
        Ok(())
    }

    #[test]
    fn test_tx_out_decode() -> Result<()> {
        let script = Script::new(vec![Cmd::Op(128), Cmd::Op(127)]);
        let tx_out = TxOut {
            amount: 100,
            script_pubkey: script,
        };

        let bytes = tx_out.encode()?;
        let decode_tx_out = TxOut::decode_bytes(&bytes)?;
        assert_eq!(decode_tx_out.amount, 100);
        assert_eq!(
            decode_tx_out.script_pubkey,
            Script::new(vec![Cmd::Op(128), Cmd::Op(127)])
        );

        Ok(())
    }
}
