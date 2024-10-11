/* Implementation of the Split Stream file format
 *
 * See doc/splitstream.md
 */

use std::{
    collections::VecDeque,
    io::{
        Read,
        Write,
    },
};

use anyhow::{
    Result,
    bail,
};
use sha2::{
    Digest,
    Sha256
};

use crate::{
    repository::Repository,
    fsverity::{
        FsVerityHashValue,
        Sha256HashValue,
    },
    util::read_exactish,
};

// utility class to help write splitstreams
type SplitStreamZstdEncoder = zstd::stream::write::Encoder<'static, Vec<u8>>;

pub struct SplitStreamWriter<'a> {
    repo: &'a Repository,
    inline_content: Vec<u8>,
    writer: SplitStreamZstdEncoder,
    sha256: Option<(Sha256, Sha256HashValue)>,
}

impl<'a> SplitStreamWriter<'a> {
    pub fn new(repo: &Repository, sha256: Option<Sha256HashValue>) -> SplitStreamWriter {
        SplitStreamWriter {
            repo,
            inline_content: vec![],
            // SAFETY: we surely can't get an error writing the header to a Vec<u8>
            writer: zstd::stream::write::Encoder::new(vec![], 0).unwrap(),
            sha256: sha256.map(|x| (Sha256::new(), x))
        }
    }

    fn write_fragment(writer: &mut SplitStreamZstdEncoder, size: usize, data: &[u8]) -> Result<()> {
        writer.write_all(&(size as u64).to_le_bytes())?;
        Ok(writer.write_all(data)?)
    }

    /// flush any buffered inline data, taking new_value as the new value of the buffer
    fn flush_inline(&mut self, new_value: Vec<u8>) -> Result<()> {
        if !self.inline_content.is_empty() {
            SplitStreamWriter::write_fragment(&mut self.writer, self.inline_content.len(), &self.inline_content)?;
            self.inline_content = new_value;
        }
        Ok(())
    }

    /// really, "add inline content to the buffer"
    /// you need to call .flush_inline() later
    pub fn write_inline(&mut self, data: &[u8]) {
        if let Some((ref mut sha256, ..)) = self.sha256 {
            sha256.update(data);
        }
        self.inline_content.extend(data);
    }

    /// write a reference to external data to the stream.  If the external data had padding in the
    /// stream which is not stored in the object then pass it here as well and it will be stored
    /// inline after the reference.
    fn write_reference(&mut self, reference: Sha256HashValue, padding: Vec<u8>) -> Result<()> {
        // Flush the inline data before we store the external reference.  Any padding from the
        // external data becomes the start of a new inline block.
        self.flush_inline(padding)?;

        SplitStreamWriter::write_fragment(&mut self.writer, 0, &reference)
    }

    pub fn write_external(&mut self, data: &[u8], padding: Vec<u8>) -> Result<()> {
        if let Some((ref mut sha256, ..)) = self.sha256 {
            sha256.update(data);
            sha256.update(&padding);
        }
        let id = self.repo.ensure_object(data)?;
        self.write_reference(id, padding)
    }

    pub fn done(mut self) -> Result<Sha256HashValue> {
        self.flush_inline(vec![])?;

        if let Some((context, expected)) = self.sha256 {
            if Into::<Sha256HashValue>::into(context.finalize()) != expected {
                bail!("Content doesn't have expected SHA256 hash value!");
            }
        }

        self.repo.ensure_object(&self.writer.finish()?)
    }
}

pub enum SplitStreamData {
    Inline(Vec<u8>),
    External(Sha256HashValue),
}

pub fn read_splitstream_chunk<R: Read>(reader: &mut R) -> Result<Option<SplitStreamData>> {
    let mut buf = [0u8; 8];
    match read_exactish(reader, &mut buf)? {
        false => Ok(None),
        true => match u64::from_le_bytes(buf) as usize {
            0 => {
                let mut data = Sha256HashValue::EMPTY;
                reader.read_exact(&mut data)?;
                Ok(Some(SplitStreamData::External(data)))
            },
            size => {
                let mut data = vec![0u8; size];
                reader.read_exact(&mut data)?;
                Ok(Some(SplitStreamData::Inline(data)))
            }
        }
    }
}

// utility class to help read splitstreams
pub struct SplitStreamReader<'w, R: Read> {
    inline_content: VecDeque<u8>,
    reader: &'w mut R
}

impl<'r, R: Read> SplitStreamReader<'r, R> {
    pub fn new(reader: &'r mut R) -> SplitStreamReader<'r, R> {
        SplitStreamReader { inline_content: VecDeque::new(), reader }
    }

    /// assumes that the data cannot be split across chunks
    pub fn read_inline_exact(&mut self, data: &mut [u8]) -> Result<bool> {
        if self.inline_content.is_empty() {
            match read_splitstream_chunk(&mut self.reader)? {
                None => { return Ok(false); }
                Some(SplitStreamData::Inline(data)) => { self.inline_content = data.into() },
                Some(SplitStreamData::External(_)) => { bail!("Expecting inline data but found external chunk") }
            }
        }

        self.inline_content.read_exact(data)?;
        Ok(true)
    }

    pub fn read_exact(&mut self, actual_size: usize, stored_size: usize) -> Result<SplitStreamData> {
        if self.inline_content.is_empty() {
            match read_splitstream_chunk(&mut self.reader)? {
                None => { bail!("Unexpected EOF") },
                Some(SplitStreamData::Inline(data)) => { self.inline_content = data.into() },
                Some(ext) => {
                    if actual_size != stored_size {
                        // need to eat the padding...
                        match read_splitstream_chunk(&mut self.reader)? {
                            None => { bail!("bad eof") },
                            Some(SplitStreamData::Inline(data)) => { self.inline_content = data.into() },
                            Some(SplitStreamData::External(_)) => { bail!("Expecting inline data but found external chunk") }
                        }
                        // TODO: make this suck less
                        let mut padding = vec![0u8; stored_size - actual_size];
                        self.inline_content.read_exact(&mut padding)?;
                    }

                    return Ok(ext)
                }
            }
        }

        // must be inline
        let mut data = vec![0u8; stored_size];
        self.inline_content.read_exact(&mut data)?;
        data.truncate(actual_size);
        Ok(SplitStreamData::Inline(data))
    }
}

pub fn splitstream_merge<R: Read, W: Write, F: FnMut(Sha256HashValue) -> Result<Vec<u8>>>(
    split_stream: &mut R, result: &mut W, mut load_data: F,
) -> Result<()> {
    while let Some(data) = read_splitstream_chunk(split_stream)? {
        match data {
            SplitStreamData::Inline(data) => result.write_all(&data)?,
            SplitStreamData::External(id) => result.write_all(&load_data(id)?)?,
        }
    }

    Ok(())
}

pub fn splitstream_objects<R: Read, F: FnMut(Sha256HashValue)>(
    split_stream: &mut R, mut callback: F
) -> Result<()> {
    while let Some(data) = read_splitstream_chunk(split_stream)? {
        match data {
            SplitStreamData::Inline(_) => { /* no op */ },
            SplitStreamData::External(id) => callback(id)
        }
    }

    Ok(())
}
