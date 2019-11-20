// Interface and an in-memory for key-value database where the key is bytes and is intended to be hash.
// Used to store merkle tree nodes.

use crate::errors::R1CSError;
use std::collections::HashMap;

pub trait HashDb<T: Clone> {
    fn insert(&mut self, hash: Vec<u8>, value: T);

    fn get(&self, hash: &[u8]) -> Result<T, R1CSError>;
}

#[derive(Clone, Debug)]
pub struct InMemoryHashDb<T: Clone> {
    db: HashMap<Vec<u8>, T>,
}

impl<T: Clone> HashDb<T> for InMemoryHashDb<T> {
    fn insert(&mut self, hash: Vec<u8>, value: T) {
        self.db.insert(hash, value);
    }

    fn get(&self, hash: &[u8]) -> Result<T, R1CSError> {
        match self.db.get(hash) {
            Some(val) => Ok(val.clone()),
            None => Err(R1CSError::HashNotFoundInDB {
                hash: hash.to_vec(),
            }),
        }
    }
}

impl<T: Clone> InMemoryHashDb<T> {
    pub fn new() -> Self {
        let db = HashMap::<Vec<u8>, T>::new();
        Self { db }
    }
}

/*pub trait HashFunc<T: Clone> {
    fn hash(&self, hash: Vec<u8>) -> Result<T, R1CSError>;
}*/

/*
TODO: Hash func abstraction
pub trait HashFunc<T: Clone> {
    fn hash(&self, hash: Vec<u8>);
}

struct poseidon {state: Any}

impl poseidon {
    fn new(**args)
}

impl  HashFunc for poseidon {

}*/
