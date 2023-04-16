use ring::digest;

pub(crate) fn sha256(data: &[u8]) -> Vec<u8> {
    digest::digest(&digest::SHA256, data).as_ref().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::test;

    #[test]
    fn test_sha256() {
        assert_eq!(
            sha256(b""),
            test::from_hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                .unwrap()
        );
        assert_eq!(
            sha256(b"hello, world"),
            test::from_hex("09ca7e4eaa6e8ae9c7d261167129184883644d07dfba7cbfbc4c8a2e08360d5b")
                .unwrap()
        );
        assert_eq!(
            sha256(b"here is a random bytes message, cool right?"),
            test::from_hex("69b9779edaa573a509999cbae415d3408c30544bad09727a1d64eff353c95b89")
                .unwrap()
        );
    }
}
