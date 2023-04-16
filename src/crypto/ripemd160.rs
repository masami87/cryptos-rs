use ripemd::{Digest, Ripemd160};

pub fn ripemd160(data: &[u8]) -> Vec<u8> {
    let mut hasher = Ripemd160::new();
    hasher.update(data);
    let res = hasher.finalize().as_slice().to_vec();
    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;
    #[test]
    fn test_ripemd160() {
        fn repeat_strs(s: &str, n: usize) -> Vec<u8> {
            std::iter::repeat(s).take(n).collect::<String>().into()
        }

        let str1 = repeat_strs("1234567890", 8);
        let str2 = repeat_strs("a", 1000);
        let test_pairs: Vec<(&[u8], &str)> = vec![
            (b"", "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
            (b"a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"),
            (b"abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
            (
                b"message digest",
                "5d0689ef49d2fae572b881b123a85ffa21595f36",
            ),
            (&str1, "9b752e45573d4b39f4dbd3323cab82bf63326bfb"),
            (&str2, "aa69deee9a8922e92f8105e007f76110f381e9cf"),
        ];
        test_pairs
            .iter()
            .for_each(|(data, expect)| assert_eq!(ripemd160(data), hex::decode(expect).unwrap()));
    }
}
