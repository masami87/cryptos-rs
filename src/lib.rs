#[macro_use]
extern crate lazy_static;

mod crypto;
mod encoding;
mod error;
mod key;
mod network;
mod script;
mod transaction;

pub use error::{CryptosError, Result};
pub fn add(left: usize, right: usize) -> usize {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
