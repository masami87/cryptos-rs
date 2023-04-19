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
