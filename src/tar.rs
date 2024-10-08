use std::io::{Read, Write};

use anyhow::Result;
use tar::{
    EntryType,
    Header,
};

use crate::{
    fsverity::Sha256HashValue,
    splitstream::{
        SplitStreamData,
        SplitStreamReader,
        SplitStreamWriter,
    },
    util::read_exactish,
};

fn read_header<R: Read>(reader: &mut R) -> Result<Option<Header>> {
    let mut header = Header::new_gnu();
    if read_exactish(reader, header.as_mut_bytes())? {
        Ok(Some(header))
    } else {
        Ok(None)
    }
 }

/// Splits the tar file from tar_stream into a Split Stream.  The store_data function is
/// responsible for ensuring that "external data" is in the composefs repository and returns the
/// fsverity hash value of that data.
pub fn split<R: Read, W: Write, F: FnMut(&[u8]) -> Result<Sha256HashValue>>(
    tar_stream: &mut R,
    split_stream: &mut W,
    mut store_data: F,
) -> Result<()> {
    let mut writer = SplitStreamWriter::new(split_stream);

    while let Some(header) = read_header(tar_stream)? {
        // the header always gets stored as inline data
        writer.write_inline(header.as_bytes());

        if header.as_bytes() == &[0u8; 512] {
            continue;
        }

        // read the corresponding data, if there is any
        let actual_size = header.entry_size()? as usize;
        let storage_size = (actual_size + 511) & !511;
        let mut buffer = vec![0u8; storage_size];
        tar_stream.read_exact(&mut buffer)?;

        if header.entry_type() == EntryType::Regular && storage_size > 0 {
            // non-empty regular file: store the data in the object store
            let padding = buffer.split_off(actual_size);
            let reference = store_data(&buffer)?;
            writer.write_reference(reference, padding)?;
        } else {
            // else: store the data inline in the split stream
            writer.write_inline(&buffer);
        }
    }

    // flush out any remaining inline data
    writer.done()
}

pub fn ls<R: Read>(split_stream: &mut R) -> Result<()> {
    let mut reader = SplitStreamReader::new(split_stream);

    loop {
        let mut buf = [0u8; 512];
        if !reader.read_inline_exact(&mut buf)? {
            return Ok(());
        }

        if buf == [0u8; 512] {
            return Ok(());
        }

        let header = tar::Header::from_byte_slice(&buf);
        let actual_size = header.size()? as usize;
        let stored_size = (actual_size + 511) & !511;
        println!("{:?}", header.path()?);
        match reader.read_exact(actual_size, stored_size)? {
            SplitStreamData::Inline(data) => println!("{} data bytes inline", data.len()),
            SplitStreamData::External(id) => println!("ext {}", hex::encode(id))
        }
        println!();
    }
}
