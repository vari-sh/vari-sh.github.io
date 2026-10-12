use std::collections::HashMap;
use std::fmt;

/// A votive candle: it burns while tallow remains.
#[derive(Debug, Clone, PartialEq)]
pub struct Candle {
    pub altar: String,
    tallow: f32,
    lit: bool,
}

impl Candle {
    pub const MAX_HOURS: f32 = 12.5;

    pub fn new(altar: &str) -> Self {
        Self { altar: altar.to_owned(), tallow: Self::MAX_HOURS, lit: false }
    }

    pub fn burn(&mut self, hours: f32) -> Result<f32, String> {
        if !self.lit {
            return Err(format!("The candle at the {} is out\n", self.altar));
        }
        self.tallow -= hours.min(self.tallow);
        Ok(self.tallow)
    }
}

impl fmt::Display for Candle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "† {} [{:.1}h]", self.altar, self.tallow)
    }
}

fn main() {
    let mut chapel: HashMap<&str, Candle> = HashMap::new();
    for (i, name) in ["Nave", "Apse", "Crypt"].iter().enumerate() {
        let mut candle = Candle::new(name);
        candle.lit = i % 2 == 0;
        chapel.insert(name, candle);
    }
    match chapel.get_mut("Crypt").map(|c| c.burn(3.0)) {
        Some(Ok(left)) => println!("Tallow left for {left} hours"),
        Some(Err(e)) => eprintln!("{e}"),
        None => unreachable!(),
    }
}
