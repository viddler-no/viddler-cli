// Copy from https://github.com/actix/actix-web/blob/a3a78ac6fb50c17b73f9d4ac6cac816ceae68bb3/actix-files/src/lib.rs
// to make it non-private
use std::fs::File;
use std::io::{Read, Seek};
use std::{cmp, io};

use actix_web::error::{BlockingError, Error, ErrorInternalServerError};
use actix_web::web;
use actix_web::web::Bytes;
use futures::{Async, Future, Poll, Stream};

#[doc(hidden)]
/// A helper created from a `std::fs::File` which reads the file
/// chunk-by-chunk on a `ThreadPool`.
pub struct ChunkedReadFile {
    pub size: u64,
    pub offset: u64,
    pub file: Option<File>,
    pub fut: Option<Box<dyn Future<Item = (File, Bytes), Error = BlockingError<io::Error>>>>,
    pub counter: u64,
}

fn handle_error(err: BlockingError<io::Error>) -> Error {
    match err {
        BlockingError::Error(err) => err.into(),
        BlockingError::Canceled => ErrorInternalServerError("Unexpected error").into(),
    }
}

impl Stream for ChunkedReadFile {
    type Item = Bytes;
    type Error = Error;

    fn poll(&mut self) -> Poll<Option<Bytes>, Error> {
        if self.fut.is_some() {
            return match self.fut.as_mut().unwrap().poll().map_err(handle_error)? {
                Async::Ready((file, bytes)) => {
                    self.fut.take();
                    self.file = Some(file);
                    self.offset += bytes.len() as u64;
                    self.counter += bytes.len() as u64;
                    Ok(Async::Ready(Some(bytes)))
                }
                Async::NotReady => Ok(Async::NotReady),
            };
        }

        let size = self.size;
        let offset = self.offset;
        let counter = self.counter;

        if size == counter {
            Ok(Async::Ready(None))
        } else {
            let mut file = self.file.take().expect("Use after completion");
            self.fut = Some(Box::new(web::block(move || {
                let max_bytes: usize;
                max_bytes = cmp::min(size.saturating_sub(counter), 65_536) as usize;
                let mut buf = Vec::with_capacity(max_bytes);
                file.seek(io::SeekFrom::Start(offset))?;
                let nbytes = file.by_ref().take(max_bytes as u64).read_to_end(&mut buf)?;
                if nbytes == 0 {
                    return Err(io::ErrorKind::UnexpectedEof.into());
                }
                Ok((file, Bytes::from(buf)))
            })));
            self.poll()
        }
    }
}
