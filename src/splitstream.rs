/* Implementation of the Split Stream file format
 *
 * Split Stream is a trivial way of storing file formats (like tar) with the "data blocks" stored
 * in the composefs object tree.  It's something like tar-split, but is based on content-addressed
 * storage of the file data and is implemented using a trivial binary-ish format.
 *
 * It is expected that the splitstream will be compressed before being stored on disk.
 *
 * The file format consists of a number of data blocks.
 *
 *
 * Each block starts with a u64 le "size" field followed by some amount of data.
 *
 *      64bit    variable
 *    +--------+---------------....
 *    | size   | data...
 *    +--------+---------------....
 *
 * There are two kinds of blocks.
 *
 *   - size != 0: in this case the length of the data is equal to the size.  This is "inline data".
 *     There is no padding, which implies that the size fields after the first may be unaligned.
 *
 *   - size == 0: in this case the length of the data is 32 bytes.  This is the binary form of a
 *     sha256 hash value and is a reference to an object in the composefs repository.
 *
 * That's it, really.  There's no header.  The file is over when there's no more blocks.
 */

use std::io::{
    Read,
    Write,
};

use anyhow::Result;

use crate::{
    fsverity::{
        FsVerityHashValue,
        Sha256HashValue,
    },
    util::read_exactish,
};

// utility class to help write splitstreams
pub struct SplitStreamWriter<'w, W: Write> {
    inline_content: Vec<u8>,
    writer: &'w mut W

}

impl<'w, W: Write> SplitStreamWriter<'w, W> {
    pub fn new(writer: &'w mut W) -> SplitStreamWriter<'w, W> {
        SplitStreamWriter { inline_content: vec![], writer }
    }

    fn write_fragment(writer: &mut W, size: usize, data: &[u8]) -> Result<()> {
        writer.write_all(&(size as u64).to_le_bytes())?;
        Ok(writer.write_all(data)?)
    }

    /// flush any buffered inline data, taking new_value as the new value of the buffer
    fn flush_inline(&mut self, new_value: Vec<u8>) -> Result<()> {
        if !self.inline_content.is_empty() {
            SplitStreamWriter::write_fragment(self.writer, self.inline_content.len(), &self.inline_content)?;
            self.inline_content = new_value;
        }
        Ok(())
    }

    /// really, "add inline content to the buffer"
    /// you need to call .flush_inline() later
    pub fn write_inline(&mut self, data: &[u8]) {
        self.inline_content.extend(data);
    }

    /// write a reference to external data to the stream.  If the external data had padding in the
    /// stream which is not stored in the object then pass it here as well and it will be stored
    /// inline after the reference.
    pub fn write_reference(&mut self, reference: Sha256HashValue, padding: Vec<u8>) -> Result<()> {
        // Flush the inline data before we store the external reference.  Any padding from the
        // external data becomes the start of a new inline block.
        self.flush_inline(padding)?;

        SplitStreamWriter::write_fragment(self.writer, 0, &reference)
    }

    pub fn done(&mut self) -> Result<()> {
        self.flush_inline(vec![])
    }
}

fn read_u64_le<R: Read>(reader: &mut R) -> Result<Option<u64>> {
    let mut buf = [0u8; 8];
    if read_exactish(reader, &mut buf)? {
        Ok(Some(u64::from_le_bytes(buf)))
    } else {
        Ok(None)
    }
}

// TODO: reader side...
pub fn splitstream_merge<R: Read, W: Write, F: FnMut(Sha256HashValue) -> Result<Vec<u8>>>(
    split_stream: &mut R, result: &mut W, mut load_data: F,
) -> Result<()> {
    while let Some(size) = read_u64_le(split_stream)? {
        if size == 0 {
            let mut hash = Sha256HashValue::EMPTY;
            split_stream.read_exact(&mut hash)?;
            let data = load_data(hash)?;
            result.write_all(&data)?;
        } else {
            let mut data = vec![0u8; size as usize]; // TODO: bzzt bzzt
            split_stream.read_exact(&mut data)?;
            result.write_all(&data)?;
        }
    }

    Ok(())
}
