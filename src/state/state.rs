use std::convert::TryInto;
use std::error::Error;
use std::fmt;

use crate::consensus::ProofOfWork;
use crate::core::Block;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum StateError {
    #[error("Invalid state")]
    InvalidState,
}

impl fmt::Display for StateError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}

pub struct State {
    pub blocks: Vec<Block>,
}

impl State {
    pub fn new() -> Self {
        State { blocks: Vec::new() }
    }

    pub fn add_block(&mut self, block: Block) {
        self.blocks.push(block);
    }

    pub fn get_block(&self, index: usize) -> Option<&Block> {
        self.blocks.get(index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_add_block() {
        // Créer un état
        let mut state = State::new();

        // Créer un bloc
        let block = Block::new();

        // Ajouter le bloc à l'état
        state.add_block(block);

        // Vérifier que le bloc est ajouté
        assert!(state.get_block(0).is_some());
    }
}