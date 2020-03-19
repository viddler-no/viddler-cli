//! A vec basically.
//! Used with indexes of the vector as ids,
//! allowing parent and child references.

use std::marker::PhantomData;

// Can be used to newtype ids for clearer types
pub trait ArenaID {
    fn from_usize(idx: usize) -> Self;
    fn as_usize(&self) -> usize;
}

pub struct Arena<T, I: ArenaID> {
    data: Vec<T>,
    _id: PhantomData<I>,
}
