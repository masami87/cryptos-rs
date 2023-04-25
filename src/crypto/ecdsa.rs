use std::{
    io::{Cursor, Read},
    ops::Mul,
};

use num_bigint::{BigInt, Sign};
use num_integer::Integer;

use crate::{
    crypto::secp256k1::secp256k1_generator,
    key::{gen_secret_key, PublicKey},
};

use super::{
    secp256k1::{inv, SECP256K1},
    sha256::sha256,
};

pub struct Signature {
    r: BigInt,
    s: BigInt,
}

impl Signature {
    // According to https://en.bitcoin.it/wiki/BIP_0062#DER_encoding DER has the following format:
    // 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S] [sighash-type]
    //
    // total-length: 1-byte length descriptor of everything that follows, excluding the sighash byte.
    // R-length: 1-byte length descriptor of the R value that follows.
    // R: arbitrary-length big-endian encoded R value. It cannot start with any 0x00 bytes, unless the first byte that follows is 0x80 or higher, in which case a single 0x00 is required.
    // S-length: 1-byte length descriptor of the S value that follows.
    // S: arbitrary-length big-endian encoded S value. The same rules apply as for R.
    // sighash-type: 1-byte hashtype flag (only 0x01, 0x02, 0x03, 0x81, 0x82 and 0x83 are allowed).
    //
    // NOTE: the sighash type is just appended at the end of the DER signature at the end in
    // Bitcoin transactions, and isn't actually part of the DER signature. Here we already assume
    // it has been cropped out.
    pub fn decode(der: &[u8]) -> Signature {
        let mut s = Cursor::new(der);
        let mut buf = [0u8; 1];

        // Read first byte and assert it's 0x30
        s.read_exact(&mut buf).unwrap();
        assert_eq!(buf[0], 0x30);

        // Read and validate the total length of the encoding
        s.read_exact(&mut buf).unwrap();
        let length = buf[0] as usize;
        assert_eq!(length, der.len() - 2);

        // Read 0x02
        s.read_exact(&mut buf).unwrap();
        assert_eq!(buf[0], 0x02);

        // Read r
        s.read_exact(&mut buf).unwrap();
        let rlength = buf[0] as usize;
        let mut r_bytes = vec![0u8; rlength];
        s.read_exact(&mut r_bytes).unwrap();
        let r = BigInt::from_signed_bytes_be(&r_bytes);

        // Read 0x02
        s.read_exact(&mut buf).unwrap();
        assert_eq!(buf[0], 0x02);

        // Read s
        s.read_exact(&mut buf).unwrap();
        let slength = buf[0] as usize;
        let mut s_bytes = vec![0u8; slength];
        s.read_exact(&mut s_bytes).unwrap();
        let s = BigInt::from_signed_bytes_be(&s_bytes);

        // Validate total length and return
        assert_eq!(der.len(), 6 + rlength + slength);
        Signature { r, s }
    }

    /// return the DER encoding of this signature
    pub fn encode(&self) -> Vec<u8> {
        let rb = dern(&self.r);
        let sb = dern(&self.s);
        let content = [
            [vec![0x02], vec![rb.len() as u8]].concat(),
            rb,
            [vec![0x02], vec![sb.len() as u8]].concat(),
            sb,
        ]
        .concat();
        let frame = [vec![0x30], vec![content.len() as u8], content].concat();
        frame
    }
}

fn dern(n: &BigInt) -> Vec<u8> {
    let mut nb = n.to_bytes_be().1;
    nb = nb.into_iter().skip_while(|b| b == &0x0).collect();
    let mut pre = if nb[0] >= 0x80 { vec![0x0] } else { vec![] };
    pre.extend(nb);
    pre
}

pub fn sign(secret_key: &BigInt, message: &[u8]) -> Signature {
    let n = &SECP256K1.n;
    let z = BigInt::from_bytes_be(Sign::Plus, &sha256(&sha256(message)));

    // generate a new secret/public key pair at random
    let k = gen_secret_key(n);
    let p = PublicKey::from_sk(&k);

    // caculate the signature
    let r = p.x();
    let mut s = (inv(&k, n) * (z + secret_key * r.clone())).mod_floor(n);
    if s > n / 2 {
        s = n - s;
    }
    Signature { r, s }
}

pub fn verify(publick_key: &PublicKey, message: &[u8], sig: &Signature) -> bool {
    let n = &SECP256K1.n;
    assert!(sig.r.ge(&BigInt::from(1)));
    assert!(sig.r.lt(n));
    assert!(sig.s.ge(&BigInt::from(1)));
    assert!(sig.s.lt(n));

    // hash the message and convert to integer
    let z = BigInt::from_bytes_be(Sign::Plus, &sha256(&sha256(message)));

    // verify signature
    let w = inv(&sig.s, n);
    let u1 = z.mul(&w).mod_floor(n);
    let u2 = sig.r.clone().mul(&w).mod_floor(n);
    let g = secp256k1_generator();
    let p = (u1 * g) + (u2 * &publick_key.0);
    p.x == sig.r.clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{key::gen_key_pair, script::Cmd, transaction::Tx, Result};
    use num_bigint::RandBigInt;
    use num_traits::Num;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_ecdsa() {
        let mut rng = rand::thread_rng();
        let n = &SECP256K1.n;

        // create two identities
        let (pk1, sk1) = gen_key_pair();
        let (_pk2, sk2) = gen_key_pair();

        let message = "user pk1 would like to pay user pk2 1 BTC kkthx"
            .as_bytes()
            .to_vec();

        // random sk
        let sig = Signature {
            r: rng.gen_bigint_range(&BigInt::from(1), n),
            s: rng.gen_bigint_range(&BigInt::from(1), n),
        };
        let is_legit = verify(&pk1, &message, &sig);
        assert_eq!(is_legit, false);

        // wrong sk
        let sig = sign(&sk2, &message);
        let is_legit = verify(&pk1, &message, &sig);
        assert_eq!(is_legit, false);

        // correct sk
        let sig = sign(&sk1, &message);
        let is_legit = verify(&pk1, &message, &sig);
        assert_eq!(is_legit, true);
    }

    #[test]
    fn test_sig_der() -> Result<()> {
        // a transaction used as an example in programming bitcoin
        let raw = hex::decode("0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600")?;
        let tx = Tx::decode_bytes(&raw)?;
        // this is the DER signature of the first input on this tx.
        let der = tx.inputs()[0].script_sig().cmds[0].clone();
        match der {
            Cmd::Op(_) => Err(crate::CryptosError::Internal(
                "der signature should be bytes".to_string(),
            )),
            Cmd::Bytes(mut bytes) => {
                // Need crops out the sighash-type byte
                bytes.pop();
                // making sure no asserts get tripped up inside this call
                let _ = Signature::decode(&bytes);

                // from programming bitcoin chapter 4
                let der = hex::decode("3045022037206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c60221008ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec")?;
                let sig = Signature::decode(&der);
                assert_eq!(
                    sig.r,
                    BigInt::from_str_radix(
                        "37206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c6",
                        16
                    )
                    .unwrap()
                );

                assert_eq!(
                    sig.s,
                    BigInt::from_str_radix(
                        "8ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec",
                        16
                    )
                    .unwrap()
                );

                // test that we can also recover back the same der encoding
                let der2 = sig.encode();
                assert_eq!(der, der2);

                Ok(())
            }
        }
    }
}
