use std::{
    fs,
    io::{BufReader, Read, Write},
    path::Path,
};

use hex::ToHex;

use crate::{
    crypto::sha256::sha256,
    encoding::{decode_int, decode_varint, encode_int, encode_varint},
    network::Net,
    script::Script,
    CryptosError, Result,
};

pub(crate) struct Tx {
    version: i32,
    tx_ins: Vec<TxIn>,
    tx_outs: Vec<TxOut>,
    locktime: u64,
    /// Segregated Witness
    segwit: bool,
    net: Net,
}

impl Tx {
    pub fn new(version: i32, tx_ins: Vec<TxIn>, tx_outs: Vec<TxOut>) -> Self {
        Self {
            version,
            tx_ins,
            tx_outs,
            locktime: 0,
            segwit: false,
            net: Net::Test,
        }
    }

    pub fn inputs(&self) -> &Vec<TxIn> {
        &self.tx_ins
    }

    pub fn decode_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = BufReader::new(bytes);
        Self::decode(&mut r)
    }

    pub fn decode(s: &mut dyn Read) -> Result<Self> {
        // decode version
        let version = decode_int(s, 4)? as i32;
        // decode inputs + detect segwit transactions
        let mut segwit = false;
        let mut num_inputs = decode_varint(s)?;
        if num_inputs == 0 {
            // detect segwit marker b'\x00'
            if decode_int(s, 1)? != 1 {
                return Err(CryptosError::Internal("decode tx err".to_string()));
            }
            num_inputs = decode_varint(s)?;
            segwit = true;
        }

        let mut tx_ins: Vec<TxIn> = vec![];

        for _ in 0..num_inputs {
            tx_ins.push(TxIn::decode(s)?);
        }

        // decode outputs
        let num_outputs = decode_varint(s)?;
        let mut tx_outs: Vec<TxOut> = vec![];
        for _ in 0..num_outputs {
            tx_outs.push(TxOut::decode(s)?);
        }

        // decode witness in the case of segwit
        if segwit {
            todo!()
        }

        // decode locktime
        let locktime = decode_int(s, 4)?;
        Ok(Self {
            version,
            tx_ins,
            tx_outs,
            locktime,
            segwit,
            net: Net::Test,
        })
    }

    pub fn set_net(&mut self, net: Net) {
        self.net = net;
        self.tx_ins.iter_mut().for_each(|tx_in| tx_in.net = net);
    }

    // Encode this transaction as bytes.
    // If sig_index is given then return the modified transaction
    // encoding of this tx with respect to the single input index.
    // This result then constitutes the "message" that gets signed
    // by the aspiring transactor of this input.
    pub fn encode(&self, force_legacy: bool, sig_index: Option<u64>) -> Result<Vec<u8>> {
        let mut out = vec![];
        // encode metadata
        out.extend(encode_int(self.version as u64, 4)?);
        // encode inputs
        if self.segwit && !force_legacy {
            // segwit marker + flag bytes
            out.extend([0x00, 0x01]);
        }
        // encode inputs
        out.extend(encode_varint(self.tx_ins.len() as u64)?);
        match sig_index {
            Some(sig_index) => {
                // Used when crafting digital signature for a specific input index.
                // This is for signing tx for sspecific input index. The sign message
                // incudes the whole tx infomation. So it need to make all other tx input's
                // script empty, because these will be changed after they are signed.
                for (i, tx_in) in self.tx_ins.iter().enumerate() {
                    out.extend(tx_in.encode(Some(sig_index == i as u64))?);
                }
            }
            None => {
                // In this case, needn't to sign this tx, just encode tx to bytes.
                for tx_in in self.tx_ins.iter() {
                    out.extend(tx_in.encode(None)?);
                }
            }
        };
        // encode outputs
        out.extend(encode_varint(self.tx_outs.len() as u64)?);
        for tx_out in self.tx_outs.iter() {
            out.extend(tx_out.encode()?);
        }
        // encode witnesses
        if self.segwit && !force_legacy {
            todo!()
        }
        // encode other metadata
        out.extend(encode_int(self.locktime, 4)?);
        if sig_index.is_some() {
            // In this case, tx is being signed. Use SIGHASH_ALL(1) to hash the
            // whole tx infomation.
            out.extend(encode_int(1, 4)?);
        }
        Ok(out)
    }

    pub fn id(&self) -> Result<String> {
        Ok(hex::encode(
            sha256(&sha256(&self.encode(true, None)?))
                .into_iter()
                .rev()
                .collect::<Vec<_>>(),
        ))
    }

    pub fn fee(&self) -> Result<u64> {
        let mut input_total = 0;
        for tx_in in self.tx_ins.iter() {
            input_total += tx_in.value()?;
        }

        let output_total = self.tx_outs.iter().map(|tx_in| tx_in.amount).sum::<u64>();
        Ok(input_total - output_total)
    }

    pub fn validate(&self) -> Result<bool> {
        // todo for segwits
        assert!(!self.segwit);

        for (i, tx_in) in self.tx_ins.iter().enumerate() {
            // note: here we should be decoding the sighash-type, which is the
            // last byte appended on top of the DER signature in the script_sig,
            // and encoding the signing bytes accordingly. For now we assume the
            // most common type of signature, which is 1 = SIGHASH_ALL
            let mod_tx_enc = self.encode(true, Some(i as u64))?;
            let combined = tx_in.script_sig.clone() + tx_in.script_pubkey()?;
            let valid = combined.evalueate(&mod_tx_enc)?;
            if !valid {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub fn is_coinbase(&self) -> bool {
        self.tx_ins.len() == 1
            && self.tx_ins[0].prev_tx == [0; 32].to_vec()
            && self.tx_ins[0].prev_index == 0xffffffff
    }

    /// returns the block number of a given transaction, following BIP0034
    pub fn coinbase_height(&self) -> Option<u64> {
        if self.is_coinbase() {
            let mut bytes = self.tx_ins[0].script_sig.cmds[0].encode();
            assert!(bytes.len() <= 8);
            bytes.resize(8, 0);
            Some(u64::from_le_bytes(bytes.try_into().unwrap()))
        } else {
            None
        }
    }
}

pub struct TxIn {
    /// Prev transaction ID: hash256 of prev tx contents.
    prev_tx: Vec<u8>,
    /// UTXO output index in the transaction.
    prev_index: u32,
    /// Unlocking script.
    /// signature + public key
    script_sig: Script,
    /// Almost not use today.
    sequence: u32,
    /// Witness data.
    witness: Vec<Vec<u8>>,
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
            witness: vec![],
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
            witness: vec![],
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
                // True = replace the script with the script_pubkey of the associated input
                let prev_tx_id: String = self.prev_tx.encode_hex();
                let prev_tx = fetch(&prev_tx_id, self.net)?;
                let script = prev_tx.tx_outs[self.prev_index as usize]
                    .script_pubkey
                    .encode()?;
                out.extend(script);
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

    fn value(&self) -> Result<u64> {
        let prev_tx_id: String = self.prev_tx.encode_hex();
        let prev_tx = fetch(&prev_tx_id, self.net)?;
        let amount = prev_tx.tx_outs[self.prev_index as usize].amount;
        Ok(amount)
    }

    fn script_pubkey(&self) -> Result<Script> {
        let prev_tx_id: String = self.prev_tx.encode_hex();
        let prev_tx = fetch(&prev_tx_id, self.net)?;
        let script = prev_tx
            .tx_outs
            .into_iter()
            .nth(self.prev_index as usize)
            .ok_or(CryptosError::Internal(
                "invalid prev_index of prev tx".to_string(),
            ))?
            .script_pubkey;
        Ok(script)
    }

    pub fn script_sig(&self) -> &Script {
        &self.script_sig
    }
}

pub struct TxOut {
    /// In units of satoshi(1e-8 of a bitcoin)
    amount: u64,
    /// Locking script.
    /// p2pkh script
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
fn fetch(tx_id: &str, net: Net) -> Result<Tx> {
    if !tx_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(CryptosError::Internal("invalid tx_id".to_string()));
    }
    let tx_id = tx_id.to_lowercase();
    let txdb_dir = "txdb";
    let cache_file = format!("{}/{}", txdb_dir, tx_id);

    let raw = if Path::new(&cache_file).is_file() {
        // fetch bytes from local disk store
        fs::read(&cache_file)?
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
    let tx = Tx::decode_bytes(&raw)?;
    if tx.id()? != tx_id {
        return Err(CryptosError::Internal("wrong tx id".to_string()));
    }
    Ok(tx)
}

#[cfg(test)]
mod tests {
    use crate::{
        crypto::ecdsa::sign,
        key::{address_to_pkb_hash, PublicKey},
        script::Cmd,
    };

    use super::*;

    use num_bigint::BigInt;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_tx_in_encode() -> Result<()> {
        let script = Script::new(vec![Cmd::Op(128), Cmd::Op(127)]);
        let prev_tx = (0..32).collect::<Vec<u8>>();
        let tx_in = TxIn {
            prev_tx: prev_tx.clone(),
            prev_index: 100,
            script_sig: script,
            sequence: 0,
            witness: vec![],
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

    #[test]
    fn test_legacy_decode() -> Result<()> {
        // Example taken from Programming Bitcoin, Chapter 5
        let raw = hex::decode("0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600")?;

        let mut tx = Tx::decode_bytes(&raw)?;

        tx.set_net(Net::Main);

        // metadata parsing
        assert_eq!(tx.version, 1);
        assert_eq!(tx.segwit, false);

        // input parsing
        assert_eq!(tx.tx_ins.len(), 1);
        assert_eq!(
            tx.tx_ins[0].prev_tx,
            hex::decode("d1c789a9c60383bf715f3f6ad9d14b91fe55f3deb369fe5d9280cb1a01793f81")?
        );
        assert_eq!(tx.tx_ins[0].prev_index, 0);
        assert_eq!(tx.tx_ins[0].sequence, 0xfffffffe);
        assert_eq!(tx.tx_ins[0].witness, Vec::<Vec<u8>>::new());

        // output parsing
        assert_eq!(tx.tx_outs.len(), 2);
        assert_eq!(tx.tx_outs[0].amount, 32454049);
        assert_eq!(tx.tx_outs[1].amount, 10011545);

        // locktime parsing
        assert_eq!(tx.locktime, 410393);

        // id caculation
        assert_eq!(
            &tx.id()?,
            "452c629d67e41baec3ac6f04fe744b4b9617f8f859c63b3002f8684e7a4fee03"
        );
        // fee calculation
        assert_eq!(tx.fee()?, 40000);

        let raw2 = tx.encode(true, None)?;
        assert_eq!(raw, raw2);

        // validate the transaction as Bitcoin law-abiding and cryptographically authentic
        assert_eq!(tx.validate()?, true);

        // fudge the r in the (r,s) digital signature tuple, this should break validation because CHECKSIG will fail
        let sig1 = tx.tx_ins[0].script_sig.cmds[0].encode();
        let sig2 = [
            sig1[..6].to_vec(),
            [(sig1[6] + 1) % 255].to_vec(),
            sig1[7..].to_vec(),
        ]
        .concat();
        let cmd1 = Cmd::decode(&sig1)?;
        let cmd2 = Cmd::decode(&sig2)?;
        tx.tx_ins[0].script_sig.cmds[0] = cmd2;
        assert_eq!(tx.validate()?, false);
        tx.tx_ins[0].script_sig.cmds[0] = cmd1;
        assert_eq!(tx.validate()?, true);

        // fudge the public key, should again break validation because pk hash won't match
        let pk1 = tx.tx_ins[0].script_sig.cmds[1].encode();
        let pk2 = [
            pk1[..6].to_vec(),
            [(pk1[6] + 1) % 255].to_vec(),
            pk1[7..].to_vec(),
        ]
        .concat();
        let cmd1 = Cmd::decode(&pk1)?;
        let cmd2 = Cmd::decode(&pk2)?;
        tx.tx_ins[0].script_sig.cmds[1] = cmd2;
        assert_eq!(tx.validate()?, false);
        tx.tx_ins[0].script_sig.cmds[1] = cmd1;
        assert_eq!(tx.validate()?, true);

        Ok(())
    }

    #[test]
    fn test_create_tx() -> Result<()> {
        // this example follows Programming Bitcoin Chapter 7

        // define the inputs of our aspiring transaction
        let prev_tx =
            hex::decode("0d6fe5213c0b3291f208cba8bfb59b7476dffacc4e5cb66f6eb20a080843a299")?;
        let prev_index = 13;

        let tx_in = TxIn {
            prev_tx,
            prev_index,
            script_sig: Script::new(vec![]),
            sequence: 0,
            witness: vec![],
            net: Net::Test,
        };

        // change output that goes back to us
        // 0.33 tBTC in units of satoshi
        let amount = (0.33 * 1e8) as u64;
        let pkb_hash = address_to_pkb_hash("mzx5YhAH9kNHtcN481u6WkjeHjYtVeKVh2")?;

        // OP_DUP, OP_HASH160, <hash>, OP_EQUALVERIFY, OP_CHECKSIG
        let script_pubkey = Script::new(
            [
                Cmd::Op(118),
                Cmd::Op(169),
                Cmd::Bytes(pkb_hash),
                Cmd::Op(136),
                Cmd::Op(172),
            ]
            .to_vec(),
        );
        let tx_out_change = TxOut {
            amount,
            script_pubkey,
        };

        // target output that goes to a lucky recepient
        // 0.1 tBTC in units of satoshi
        let amount = (0.1 * 1e8) as u64;
        let pkb_hash = address_to_pkb_hash("mnrVtF8DWjMu839VW3rBfgYaAfKk8983Xf")?;
        // OP_DUP, OP_HASH160, <hash>, OP_EQUALVERIFY, OP_CHECKSIG
        let script_pubkey = Script::new(
            [
                Cmd::Op(118),
                Cmd::Op(169),
                Cmd::Bytes(pkb_hash),
                Cmd::Op(136),
                Cmd::Op(172),
            ]
            .to_vec(),
        );
        let tx_out_target = TxOut {
            amount,
            script_pubkey,
        };

        // create the desired transaction object
        let mut tx = Tx::new(1, vec![tx_in], vec![tx_out_change, tx_out_target]);

        assert_eq!(tx.fee()?, (0.01 * 1e8) as u64);

        // produce the unlocking script for this p2pkh tx: [<signature>, <pubkey>]

        // first produce the <pubkey> that will satisfy OP_EQUALVERIFY on the locking script
        let sk = BigInt::from(8675309);
        let pk = PublicKey::from_sk(&sk);
        let sec = pk.encode(true, false)?;
        // now produce the digital signature that will satisfy the OP_CHECKSIG on the locking script
        let tx_encode = tx.encode(true, Some(0))?;
        let sig = sign(&sk, &tx_encode);
        let der = sig.encode();
        // 1 = SIGHASH_ALL, indicating this der signature encoded "ALL" of the tx
        let der_and_type = [der.clone(), vec![1u8]].concat();

        // set the unlocking script into the transaction
        tx.tx_ins[0].script_sig =
            Script::new(vec![Cmd::Bytes(der_and_type), Cmd::Bytes(sec.clone())]);

        // final check: ensure that our manually constructed transaction is all valid and ready to send out to the wild
        assert_eq!(tx.validate()?, true);

        // peace of mind: fudge the signature and try again
        let der = [
            der[..6].to_vec(),
            [(der[6] + 1) % 255].to_vec(),
            der[7..].to_vec(),
        ]
        .concat();
        let der_and_type = [der.clone(), vec![1u8]].concat();
        tx.tx_ins[0].script_sig = Script::new(vec![Cmd::Bytes(der_and_type), Cmd::Bytes(sec)]);

        assert_eq!(tx.validate()?, false);
        Ok(())
    }

    #[test]
    fn test_is_coinbase() -> Result<()> {
        // not coinbase
        let raw = hex::decode("0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600")?;
        let tx = Tx::decode_bytes(&raw)?;
        assert_eq!(tx.is_coinbase(), false);

        // is coinbase
        let raw = hex::decode("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff5e03d71b07254d696e656420627920416e74506f6f6c20626a31312f4542312f4144362f43205914293101fabe6d6d678e2c8c34afc36896e7d9402824ed38e856676ee94bfdb0c6c4bcd8b2e5666a0400000000000000c7270000a5e00e00ffffffff01faf20b58000000001976a914338c84849423992471bffb1a54a8d9b1d69dc28a88ac00000000")?;
        let mut tx = Tx::decode_bytes(&raw)?;
        assert_eq!(tx.is_coinbase(), true);
        tx.tx_ins = vec![];
        assert_eq!(tx.is_coinbase(), false);

        Ok(())
    }

    #[test]
    fn test_coinbase_height() -> Result<()> {
        // not coinbase
        let raw = hex::decode("0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600")?;
        let tx = Tx::decode_bytes(&raw)?;
        assert_eq!(tx.coinbase_height(), None);

        // is coinbase
        let raw = hex::decode("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff5e03d71b07254d696e656420627920416e74506f6f6c20626a31312f4542312f4144362f43205914293101fabe6d6d678e2c8c34afc36896e7d9402824ed38e856676ee94bfdb0c6c4bcd8b2e5666a0400000000000000c7270000a5e00e00ffffffff01faf20b58000000001976a914338c84849423992471bffb1a54a8d9b1d69dc28a88ac00000000")?;
        let tx = Tx::decode_bytes(&raw)?;
        assert_eq!(tx.coinbase_height(), Some(465879));

        Ok(())
    }
}
