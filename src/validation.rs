use std::fmt::{self, Display, Formatter};

#[derive(Debug)]
pub struct Hostname {
    hostname: String,
}

impl Hostname {
    pub fn new(hostname: String) -> Self {
        //  TODO: Hostname needs to be validated before running the traceroute

        Self { hostname }
    }

    pub fn hostname(&self) -> &str {
        &self.hostname
    }
}

impl Display for Hostname {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self.hostname)
    }
}
