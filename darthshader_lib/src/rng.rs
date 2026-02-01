use rand::{Rng, SeedableRng};
use rand::rngs::SmallRng;

pub struct SimpleRng {
    rng: SmallRng,
}

impl SimpleRng {
    pub fn new(seed: u64) -> Self {
        Self { rng: SmallRng::seed_from_u64(seed) }
    }

    pub fn next_u64(&mut self) -> u64 {
        self.rng.gen()
    }

    pub fn below(&mut self, max: usize) -> usize {
        if max == 0 { 0 } else { self.rng.gen_range(0..max) }
    }

    pub fn probability(&mut self, p: f64) -> bool {
        self.rng.gen_bool(p.clamp(0.0, 1.0))
    }

    pub fn choose_index(&mut self, len: usize) -> Option<usize> {
        if len == 0 { None } else { Some(self.below(len)) }
    }

    pub fn choose<'a, T>(&mut self, slice: &'a [T]) -> Option<&'a T> {
        self.choose_index(slice.len()).map(|i| &slice[i])
    }

    pub fn shuffle<T>(&mut self, s: &mut [T]) {
        // Fisher-Yates
        for i in (1..s.len()).rev() {
            let j = self.rng.gen_range(0..=i);
            s.swap(i, j);
        }
    }
}