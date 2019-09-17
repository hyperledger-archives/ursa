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
