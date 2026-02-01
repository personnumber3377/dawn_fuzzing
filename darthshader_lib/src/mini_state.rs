use libafl::{
    corpus::{InMemoryCorpus, Testcase},
    inputs::UsesInput,
    state::{HasCorpus, HasRand},
};
use libafl_bolts::rands::Lehmer64Rand;

use crate::layeredinput::LayeredInput;

// For the corpus shit...
use libafl::corpus::Corpus;

pub struct MiniState {
    rand: Lehmer64Rand,
    corpus: InMemoryCorpus<LayeredInput>,
}

impl MiniState {
    pub fn new(seed: u64) -> Self {
        Self {
            rand: Lehmer64Rand::with_seed(seed),
            corpus: InMemoryCorpus::new(),
        }
    }

    pub fn add_input_to_corpus(&mut self, input: LayeredInput) {
        let _ = self.corpus.add(Testcase::new(input));
    }
}

impl UsesInput for MiniState {
    type Input = LayeredInput;
}

impl HasRand for MiniState {
    type Rand = Lehmer64Rand;

    fn rand(&self) -> &Self::Rand {
        &self.rand
    }

    fn rand_mut(&mut self) -> &mut Self::Rand {
        &mut self.rand
    }
}

impl HasCorpus for MiniState {
    type Corpus = InMemoryCorpus<LayeredInput>;

    fn corpus(&self) -> &Self::Corpus {
        &self.corpus
    }

    fn corpus_mut(&mut self) -> &mut Self::Corpus {
        &mut self.corpus
    }
}