use libafl_bolts::rands::Rand;
use rand::{rngs::SmallRng, seq::SliceRandom, Rng, SeedableRng};

pub trait RandExt: Rand {
    /*
    fn choose<'a, T>(&mut self, slice: &'a [T]) -> &'a T {
        let idx = self.below(slice.len() as u64) as usize;
        &slice[idx]
    }
    */

    fn shuffle<T>(&mut self, slice: &mut [T]) {
        let mut rng = SmallRng::seed_from_u64(self.next());
        slice.shuffle(&mut rng);
    }

    fn gen_bool(&mut self, p: f64) -> bool {
        let mut rng = SmallRng::seed_from_u64(self.next());
        rng.gen_bool(p)
    }

    fn random_u32(&mut self) -> u32 { self.next() as u32 }
    fn random_i32(&mut self) -> i32 { self.next() as i32 }
    fn random_u8(&mut self) -> u8 { self.next() as u8 }
    fn random_bool(&mut self) -> bool { (self.next() & 1) != 0 }
    fn random_f32(&mut self) -> f32 {
        // crude but fine for fuzzing:
        let bits = (self.next() as u32) | 1;
        f32::from_bits(bits)
    }
    fn probability(&mut self, p: f64) -> bool {
        // p in [0,1]
        let r = (self.next() as f64) / (u64::MAX as f64);
        r < p
    }
    fn choose_slice<'a, T>(&mut self, s: &'a [T]) -> &'a T {
        let idx = (self.next() as usize) % s.len();
        &s[idx]
    }
    fn choose_slice_mut<'a, T>(&mut self, s: &'a mut [T]) -> &'a mut T {
        let idx = (self.next() as usize) % s.len();
        &mut s[idx]
    }

}

impl<R: Rand + ?Sized> RandExt for R {}



/*
use libafl_bolts::rands::Rand;

pub trait RandExt2: Rand {
    fn random_u32(&mut self) -> u32 { self.next() as u32 }
    fn random_i32(&mut self) -> i32 { self.next() as i32 }
    fn random_u8(&mut self) -> u8 { self.next() as u8 }
    fn random_bool(&mut self) -> bool { (self.next() & 1) != 0 }
    fn random_f32(&mut self) -> f32 {
        // crude but fine for fuzzing:
        let bits = (self.next() as u32) | 1;
        f32::from_bits(bits)
    }
    fn probability(&mut self, p: f64) -> bool {
        // p in [0,1]
        let r = (self.next() as f64) / (u64::MAX as f64);
        r < p
    }
    fn choose_slice<'a, T>(&mut self, s: &'a [T]) -> &'a T {
        let idx = (self.next() as usize) % s.len();
        &s[idx]
    }
    fn choose_slice_mut<'a, T>(&mut self, s: &'a mut [T]) -> &'a mut T {
        let idx = (self.next() as usize) % s.len();
        &mut s[idx]
    }
}
impl<R: Rand + ?Sized> RandExt2 for R {}
*/
