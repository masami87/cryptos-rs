use crate::script::Script;

pub struct TxIn {
    /// Prev transaction ID: hash256 of prev tx contents.
    prev_tx: Vec<u8>,
    /// UTXO output index in the transaction.
    prev_index: usize,
    /// Unlocking script.
    script_sig: Script,
    /// Almost not use today.
    sequence: usize,
}

impl Default for TxIn {
    fn default() -> Self {
        Self {
            prev_tx: Vec::new(),
            prev_index: 0,
            script_sig: Script::new(vec![]),
            sequence: 0,
        }
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
