use crate::{
    block::Block,
    crypto::sha256::sha256,
    encoding::{decode_varint, encode_varint},
    CryptosError, Result,
};
use std::{
    collections::HashMap,
    io::{BufReader, Read, Write},
    net::{Ipv4Addr, TcpStream},
};

lazy_static! {
    static ref MAGICS: HashMap<&'static str, [u8; 4]> = [
        ("main", [0xf9, 0xbe, 0xb4, 0xd9]),
        ("test", [0x0b, 0x11, 0x09, 0x07]),
    ]
    .iter()
    .cloned()
    .collect();
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Net {
    Main,
    Test,
}

impl From<&str> for Net {
    fn from(value: &str) -> Self {
        if value == "main" {
            Self::Main
        } else if value == "test" {
            Self::Test
        } else {
            panic!("Unknown Net type: {}", value)
        }
    }
}

impl Into<&str> for Net {
    fn into(self) -> &'static str {
        match self {
            Net::Main => "main",
            Net::Test => "test",
        }
    }
}

#[derive(Debug)]
pub struct NetworkEnvelope {
    pub command: Vec<u8>,
    pub payload: Vec<u8>,
    net: Net,
}

impl NetworkEnvelope {
    fn decode(s: &mut impl Read, net: &str) -> Result<Self> {
        // validate magic bytes
        let mut magic = [0u8; 4];
        s.read_exact(&mut magic)?;
        if magic != MAGICS[net] {
            return Err(CryptosError::Internal("invalid magic number".to_string()));
        }
        // decode the command
        let mut command = [0u8; 12];
        s.read_exact(&mut command)?;
        let command = command.iter().cloned().take_while(|&x| x != 0).collect();
        // decode and validate the payload
        let mut payload_length = [0u8; 4];
        s.read_exact(&mut payload_length)?;
        let payload_length = u32::from_le_bytes(payload_length) as usize;
        let mut checksum = [0u8; 4];
        s.read_exact(&mut checksum)?;
        let mut payload = vec![0u8; payload_length];
        s.read_exact(&mut payload)?;
        let hash = &sha256(&sha256(&payload));
        if &hash[..4] != &checksum {
            return Err(CryptosError::Internal("invalid checksum".to_string()));
        }

        Ok(Self {
            command,
            payload,
            net: net.into(),
        })
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = vec![];

        out.extend_from_slice(&MAGICS[self.net.clone().into()]);
        // encode the command
        assert!(self.command.len() <= 12);
        out.extend_from_slice(&self.command);
        out.resize(out.len() + 12 - self.command.len(), 0); // command padding

        // encode the payload
        assert!(self.payload.len() <= u32::MAX as usize);
        out.extend_from_slice(&(self.payload.len() as u32).to_le_bytes()); // payload length

        let hash = &sha256(&sha256(&self.payload));
        out.extend_from_slice(&hash[..4]); // checksum
        out.extend_from_slice(&self.payload);

        out
    }
}

struct NetAddr {
    // reference: https://en.bitcoin.it/wiki/Protocol_documentation#Network_address
    // currently assumes IPv4 address
    services: u64,
    ip: Ipv4Addr,
    port: u16,
}

impl Default for NetAddr {
    fn default() -> Self {
        Self {
            services: 0,
            ip: Ipv4Addr::new(0, 0, 0, 0),
            port: 8333,
        }
    }
}

impl NetAddr {
    fn decode(s: &mut dyn Read) -> Result<Self> {
        let mut buf = [0u8; 8];
        s.read_exact(&mut buf)?;
        let services = u64::from_le_bytes(buf);

        let mut buf = [0u8; 12];
        s.read_exact(&mut buf)?;

        let mut buf = [0u8; 4];
        s.read_exact(&mut buf)?;
        let ip = Ipv4Addr::from(buf);

        let mut buf = [0u8; 2];
        s.read_exact(&mut buf)?;
        let port = u16::from_be_bytes(buf);

        Ok(Self { services, ip, port })
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = vec![];

        // receiver services is 8 bytes little endian
        out.extend_from_slice(&self.services.to_le_bytes());
        // IPV4 is 10 00 bytes and 2 ff bytes then receiver ip
        out.extend_from_slice(&[0u8; 10]);
        out.extend_from_slice(&[0xffu8; 2]);
        out.extend_from_slice(&self.ip.octets());
        // receiver port is 2 bytes, big endian
        out.extend_from_slice(&self.port.to_be_bytes());

        out
    }
}

// reference: https://en.bitcoin.it/wiki/Protocol_documentation#version
// When a node creates an outgoing connection, it will immediately advertise
// its version. The remote node will respond with its version. No further
// communication is possible until both peers have exchanged their version.
struct VersionMessage {
    /// specifies what messages may be communicated
    version: u32,
    /// info about what capabilities are available
    services: u64,
    /// 8 bytes Unix timestamp in little-endian
    timestamp: u64,
    receiver: NetAddr,
    sender: NetAddr,
    /// uint64_t Node random nonce, randomly generated every time a version
    /// packet is sent. This nonce is used to detect connections to self.
    nonce: [u8; 8],
    user_agent: Vec<u8>,
    latest_block: u32,
    relay: bool,
    command: Vec<u8>,
}

impl VersionMessage {
    pub fn decode(s: &mut dyn Read) -> Result<Self> {
        let mut buf = [0u8; 4];

        s.read_exact(&mut buf)?;
        let version = u32::from_le_bytes(buf);

        let mut buf = [0u8; 8];
        s.read_exact(&mut buf)?;
        let services = u64::from_le_bytes(buf);

        s.read_exact(&mut buf)?;
        let timestamp = u64::from_le_bytes(buf);

        let receiver = NetAddr::decode(s)?;
        let sender = NetAddr::decode(s)?;

        let mut nonce = [0u8; 8];
        s.read_exact(&mut nonce)?;

        let user_agent_len = decode_varint(s)? as usize;
        let mut user_agent = vec![0u8; user_agent_len];
        s.read_exact(&mut user_agent)?;

        let mut latest_block_buf = [0u8; 4];
        s.read_exact(&mut latest_block_buf)?;
        let latest_block = u32::from_le_bytes(latest_block_buf);

        let mut relay_buf = [0u8; 1];
        s.read_exact(&mut relay_buf)?;
        let relay = match relay_buf[0] {
            0x00 => false,
            0x01 => true,
            _ => {
                return Err(CryptosError::File(std::io::Error::from(
                    std::io::ErrorKind::InvalidData,
                )))
            }
        };

        let command = b"version".to_vec(); // command is always "version"

        Ok(VersionMessage {
            version,
            services,
            timestamp,
            receiver,
            sender,
            nonce,
            user_agent,
            latest_block,
            relay,
            command,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();

        // version is 4 bytes little endian
        out.extend_from_slice(&self.version.to_le_bytes());
        // services is 8 bytes little endian
        out.extend_from_slice(&self.services.to_le_bytes());
        // timestamp is 8 bytes little endian
        out.extend_from_slice(&self.timestamp.to_le_bytes());
        // receiver
        out.extend(self.receiver.encode());
        // sender
        out.extend(self.sender.encode());
        // nonce should be 8 bytes
        out.extend(&self.nonce);
        // useragent is a variable string, so varint first
        out.extend(encode_varint(self.user_agent.len() as u64).unwrap());
        out.extend(&self.user_agent);

        // latest block is 4 bytes little endian
        out.extend_from_slice(&self.latest_block.to_le_bytes());
        // relay is 00 if false, 01 if true
        out.push(if self.relay { 0x01 } else { 0x00 });

        out
    }
}

// https://en.bitcoin.it/wiki/Protocol_documentation#verack
// The verack message is sent in reply to version. This message
// consists of only a message header with the command string "verack".
struct VerAckMessage {
    command: Vec<u8>,
}

impl VerAckMessage {
    pub fn decode(_: &mut dyn Read) -> Result<Self> {
        Ok(Self {
            command: b"verack".to_vec(),
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        vec![]
    }
}

// https://en.bitcoin.it/wiki/Protocol_documentation#ping
// The ping message is sent primarily to confirm that the TCP/IP
// connection is still valid. An error in transmission is presumed
// to be a closed connection and the address is removed as a current peer.
struct PingMessage {
    nonce: Vec<u8>,
    command: Vec<u8>,
}

impl PingMessage {
    pub fn decode(s: &mut dyn Read) -> Result<Self> {
        let mut nonce = vec![];
        s.read(&mut nonce)?;
        Ok(Self {
            nonce,
            command: b"ping".to_vec(),
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        self.nonce.clone()
    }
}

// https://en.bitcoin.it/wiki/Protocol_documentation#pong
// The pong message is sent in response to a ping message.
// In modern protocol versions, a pong response is generated
// using a nonce included in the ping.
struct PongMessage {
    nonce: Vec<u8>,
    command: Vec<u8>,
}

impl PongMessage {
    pub fn decode(s: &mut dyn Read) -> Result<Self> {
        let mut nonce = vec![];
        s.read(&mut nonce)?;
        Ok(Self {
            nonce,
            command: b"pong".to_vec(),
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        self.nonce.clone()
    }
}

#[derive(Debug)]
struct GetHeadersMessage {
    /// uint32_t protocol version
    version: u32,
    /// var_int, number of block locator hash entries; can be >1 if there is a chain split
    num_hashes: u64,
    /// char[32] block locator object
    start_block: Vec<u8>,
    /// char[32] hash of the last desired block header; set to zero to get as many blocks as possible
    end_block: Vec<u8>,
    command: Vec<u8>,
}

impl GetHeadersMessage {
    fn new(version: u32, num_hashes: u64, start_block: Vec<u8>, end_block: Vec<u8>) -> Self {
        Self {
            version,
            num_hashes,
            start_block,
            end_block,
            command: b"getheaders".to_vec(),
        }
    }

    fn decode(s: &mut dyn Read) -> Result<Self> {
        todo!()
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&encode_varint(self.num_hashes).unwrap());
        out.extend_from_slice(&self.start_block.iter().rev().cloned().collect::<Vec<u8>>());
        out.extend_from_slice(&self.end_block.iter().rev().cloned().collect::<Vec<u8>>());
        out
    }
}

#[derive(Debug)]
struct HeadersMessage {
    blocks: Vec<Block>,
    command: Vec<u8>,
}

impl HeadersMessage {
    fn new(blocks: Vec<Block>) -> Self {
        Self {
            blocks,
            command: b"headers".to_vec(),
        }
    }

    fn encode(&self) -> Vec<u8> {
        self.blocks
            .iter()
            .map(|b| b.encode().unwrap())
            .collect::<Vec<_>>()
            .concat()
    }

    fn decode(s: &mut dyn Read) -> Result<Self> {
        let count = decode_varint(s)?;
        let mut blocks = Vec::new();
        for _i in 0..count {
            let b = Block::decode(s)?;
            blocks.push(b);
            // the number of transactions is also given and is always zero if we
            // only request the headers. This is done so that the same code can be
            // used to decode the "block" message, which contains the full block
            // information with all the transactions attached. Here we just make
            // sure it is zero.
            let num_transactions = decode_varint(s)?;
            assert_eq!(num_transactions, 0);
        }
        Ok(Self::new(blocks))
    }
}

enum Message {
    Version(VersionMessage),
    VerAck(VerAckMessage),
    Ping(PingMessage),
    Pong(PongMessage),
    GetHeaders(GetHeadersMessage),
    Headers(HeadersMessage),
}

impl Message {
    fn command(&self) -> Vec<u8> {
        match self {
            Message::Version(msg) => msg.command.clone(),
            Message::VerAck(msg) => msg.command.clone(),
            Message::Ping(msg) => msg.command.clone(),
            Message::Pong(msg) => msg.command.clone(),
            Message::GetHeaders(msg) => msg.command.clone(),
            Message::Headers(msg) => msg.command.clone(),
        }
    }

    fn encode(&self) -> Vec<u8> {
        match self {
            Message::Version(msg) => msg.encode(),
            Message::VerAck(msg) => msg.encode(),
            Message::Ping(msg) => msg.encode(),
            Message::Pong(msg) => msg.encode(),
            Message::GetHeaders(msg) => msg.encode(),
            Message::Headers(msg) => msg.encode(),
        }
    }
}

struct SimpleNode {
    net: Net,
    verbose: bool,
    socket: TcpStream,
}

impl SimpleNode {
    pub fn new(host: Ipv4Addr, net: &str, verbose: bool) -> Result<Self> {
        let port = match net {
            "main" => 8333,
            "test" => 18333,
            _ => panic!("Invalid network"),
        };

        let socket = TcpStream::connect((host, port))?;

        Ok(Self {
            net: net.into(),
            verbose,
            socket,
        })
    }

    pub fn send(&mut self, msg: Message) -> Result<()> {
        let env = NetworkEnvelope {
            command: msg.command(),
            payload: msg.encode(),
            net: self.net,
        };
        if self.verbose {
            println!("sending {:?}", env);
        }
        self.socket.write_all(&env.encode())?;
        Ok(())
    }

    pub fn read(&mut self) -> Result<NetworkEnvelope> {
        let mut s = self.socket.try_clone()?;
        let env = NetworkEnvelope::decode(&mut s, self.net.into())?;
        if self.verbose {
            println!("receiving: {:?}", env);
        }
        Ok(env)
    }

    pub fn close(&self) -> Result<()> {
        self.socket.shutdown(std::net::Shutdown::Both)?;
        Ok(())
    }

    pub fn handshake(&mut self) -> Result<()> {
        let version = VersionMessage {
            version: 70015,
            services: 0,
            timestamp: 0,
            receiver: NetAddr::default(),
            sender: NetAddr::default(),
            nonce: [0u8; 8],
            user_agent: b"/programmingbitcoin:0.1/".to_vec(),
            latest_block: 0,
            relay: false,
            command: b"version".to_vec(),
        };
        self.send(Message::Version(version))?;
        self.wait_for(vec!["version"])?;
        self.wait_for(vec!["verack"])?;
        self.send(Message::VerAck(VerAckMessage {
            command: b"verack".to_vec(),
        }))?;

        Ok(())
    }

    fn wait_for(&mut self, message_type: Vec<&str>) -> Result<Message> {
        let mut command = vec![];

        loop {
            let env = self.read()?;
            command = env.command.clone();
            if let Some(m) = message_type.iter().find(|c| {
                let b = c.as_bytes();
                b == &command
            }) {
                return decode_msg(*m, &env.payload);
            }

            if command == b"version" {
                self.send(Message::VerAck(VerAckMessage {
                    command: b"verack".to_vec(),
                }))?;
            } else if command == b"ping" {
                self.send(Message::Pong(PongMessage {
                    nonce: env.payload,
                    command: b"pong".to_vec(),
                }))?;
            }
        }
    }
}

fn decode_msg(msg_type: &str, bytes: &[u8]) -> Result<Message> {
    let mut s = BufReader::new(bytes);
    match msg_type {
        "version" => Ok(Message::Version(VersionMessage::decode(&mut s)?)),
        "verack" => Ok(Message::VerAck(VerAckMessage::decode(&mut s)?)),
        "ping" => Ok(Message::Ping(PingMessage::decode(&mut s)?)),
        "pong" => Ok(Message::Pong(PongMessage::decode(&mut s)?)),
        "headers" => Ok(Message::Headers(HeadersMessage::decode(&mut s)?)),
        "getheaders" => Ok(Message::GetHeaders(GetHeadersMessage::decode(&mut s)?)),
        _ => Err(CryptosError::Internal(format!(
            "invalid msg_type: {}",
            msg_type
        ))),
    }
}

#[cfg(test)]
mod tests {
    use std::{io::BufReader, net::SocketAddr};

    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_encode_decode_network_envelope() -> Result<()> {
        let msg = hex::decode("f9beb4d976657261636b000000000000000000005df6e0e2")?;
        let mut r = BufReader::new(&*msg);
        let envelope = NetworkEnvelope::decode(&mut r, "main")?;
        assert_eq!(envelope.command, b"verack");
        assert_eq!(envelope.payload, b"");
        assert_eq!(envelope.encode(), msg);

        let msg = hex::decode("f9beb4d976657273696f6e0000000000650000005f1a69d2721101000100000000000000bc8f5e5400000000010000000000000000000000000000000000ffffc61b6409208d010000000000000000000000000000000000ffffcb0071c0208d128035cbc97953f80f2f5361746f7368693a302e392e332fcf05050001")?;
        let mut r = BufReader::new(&*msg);
        let envelope = NetworkEnvelope::decode(&mut r, "main")?;
        assert_eq!(envelope.command, b"version");
        assert_eq!(envelope.payload, msg[24..]);
        assert_eq!(envelope.encode(), msg);
        Ok(())
    }

    #[test]
    fn test_encode_version_payload() -> Result<()> {
        let msg = VersionMessage {
            version: 70015,
            services: 0,
            timestamp: 0,
            receiver: NetAddr::default(),
            sender: NetAddr::default(),
            nonce: [0u8; 8],
            user_agent: b"/programmingbitcoin:0.1/".to_vec(),
            latest_block: 0,
            relay: false,
            command: b"version".to_vec(),
        };

        let msg_encode = msg.encode();

        assert_eq!(msg_encode,hex::decode("7f11010000000000000000000000000000000000000000000000000000000000000000000000ffff00000000208d000000000000000000000000000000000000ffff00000000208d0000000000000000182f70726f6772616d6d696e67626974636f696e3a302e312f0000000000")?);

        let mut r = BufReader::new(&*msg_encode);
        let decode = VersionMessage::decode(&mut r)?;
        assert_eq!(decode.version, 70015);
        assert_eq!(decode.user_agent, b"/programmingbitcoin:0.1/".to_vec());

        Ok(())
    }

    #[test]
    fn test_encode_getheaders_payload() -> Result<()> {
        let start_block =
            hex::decode("0000000000000000001237f46acddf58578a37e213d2a6edc4884a2fcad05ba3")?;
        let msg = GetHeadersMessage {
            version: 70015,
            num_hashes: 1,
            start_block,
            end_block: vec![0; 32],
            command: b"getheaders".to_vec(),
        };

        assert_eq!(msg.encode(),hex::decode("7f11010001a35bd0ca2f4a88c4eda6d213e2378a5758dfcd6af437120000000000000000000000000000000000000000000000000000000000000000000000000000000000")?);
        Ok(())
    }

    #[test]
    fn test_decode_headers_payload() -> Result<()> {
        let bytes = hex::decode("0200000020df3b053dc46f162a9b00c7f0d5124e2676d47bbe7c5d0793a500000000000000ef445fef2ed495c275892206ca533e7411907971013ab83e3b47bd0d692d14d4dc7c835b67d8001ac157e670000000002030eb2540c41025690160a1014c577061596e32e426b712c7ca00000000000000768b89f07044e6130ead292a3f51951adbd2202df447d98789339937fd006bd44880835b67d8001ade09204600")?;
        let mut r = BufReader::new(&*bytes);
        let headers = HeadersMessage::decode(&mut r)?;
        assert_eq!(headers.blocks.len(), 2);
        Ok(())
    }

    #[test]
    fn test_handshake() -> Result<()> {
        let socket = TcpStream::connect("testnet.programmingbitcoin.com:18333")?;
        let mut node = SimpleNode {
            net: "test".into(),
            verbose: false,
            socket,
        };
        node.handshake()?;
        node.close()?;

        Ok(())
    }
}
