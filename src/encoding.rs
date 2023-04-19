use std::io::Read;

use crate::{CryptosError, Result};

pub fn encode_int(i: u64, nbytes: usize) -> Result<Vec<u8>> {
    let bytes = i.to_le_bytes();
    if nbytes > bytes.len() {
        return Err(CryptosError::Internal(format!(
            "nbytes too long: {}",
            nbytes
        )));
    }
    Ok(bytes[..nbytes].to_vec())
}

pub fn decode_int(s: &mut dyn Read, nbytes: usize) -> Result<u64> {
    if nbytes > 8 {
        return Err(CryptosError::Internal("bytes too long".to_string()));
    }
    let mut bytes = [0u8; 8];
    let mut chunk = s.take(nbytes as u64);
    chunk.read(&mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}

pub fn encode_varint(i: u64) -> Result<Vec<u8>> {
    if i < 0xfd {
        Ok(vec![u8::try_from(i).unwrap()])
    } else if i <= 0xffff {
        Ok([0xfd].iter().cloned().chain(encode_int(i, 2)?).collect())
    } else if i <= 0xffff_ffff {
        Ok([0xfe].iter().cloned().chain(encode_int(i, 4)?).collect())
    } else {
        Ok([0xff].iter().cloned().chain(encode_int(i, 8)?).collect())
    }
}

pub fn decode_varint(s: &mut dyn Read) -> Result<u64> {
    let i = decode_int(s, 1)?;
    if i == 0xfd {
        decode_int(s, 2)
    } else if i == 0xfe {
        decode_int(s, 4)
    } else if i == 0xff {
        decode_int(s, 8)
    } else {
        Ok(i)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufReader;
    #[test]
    fn test_encode_int() -> Result<()> {
        assert_eq!(encode_int(0, 1)?, vec![0]);
        assert_eq!(encode_int(1, 2)?, vec![0x1, 0x0]);
        assert_eq!(encode_int(5, 3)?, vec![0x5, 0x0, 0x0]);
        assert!(encode_int(5, 10).is_err());
        Ok(())
    }

    #[test]
    fn test_decode_int() -> Result<()> {
        let a = encode_int(17, 4)?;
        let mut reader = BufReader::new(&*a);
        assert_eq!(decode_int(&mut reader, 4)?, 17 as u64);

        let b = encode_int(0xffff_ffff, 8)?;
        reader = BufReader::new(&*b);
        assert_eq!(decode_int(&mut reader, 8)?, 0xffff_ffff as u64);
        Ok(())
    }

    #[test]
    fn test_encode_varint() -> Result<()> {
        assert_eq!(encode_varint(32)?, vec![32]);
        assert_eq!(encode_varint(300)?, vec![0xfd, 0x2c, 0x1]);
        assert_eq!(encode_varint(0xffff_ffff)?.len(), 5);
        assert_eq!(encode_varint(0x10000_0000)?.len(), 9);
        Ok(())
    }

    #[test]
    fn test_decode_varint() -> Result<()> {
        let mut a = encode_varint(32)?;
        let mut reader = BufReader::new(&*a);
        assert_eq!(decode_varint(&mut reader)?, 32 as u64);

        let b = encode_varint(0xffff_ffff)?;
        reader = BufReader::new(&*b);
        assert_eq!(decode_varint(&mut reader)?, 0xffff_ffff as u64);

        let c = encode_varint(0x10000_0000)?;
        reader = BufReader::new(&*c);
        assert_eq!(decode_varint(&mut reader)?, 0x10000_0000 as u64);

        a.extend(b);
        a.extend(c);
        let mut reader = BufReader::new(&*a);
        assert_eq!(decode_varint(&mut reader)?, 32 as u64);
        assert_eq!(decode_varint(&mut reader)?, 0xffff_ffff as u64);
        assert_eq!(decode_varint(&mut reader)?, 0x10000_0000 as u64);
        Ok(())
    }
}
