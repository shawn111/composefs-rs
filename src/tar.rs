use std::io::{Read, Write};
use crate::fsverity::Sha256HashValue;
use crate::splitstream::SplitStreamWriter;

struct TarHeader {
    data: [u8; 512],
}

impl TarHeader {
    // we can't use Read::read_exact() because we need to be able to detect EOF
    fn read<R: Read>(reader: &mut R) -> std::io::Result<Option<TarHeader>> {
        let mut header = TarHeader { data: [0u8; 512] };
        let mut todo: &mut [u8] = &mut header.data;

        while !todo.is_empty() {
            match reader.read(todo) {
                Ok(0) => match todo.len() {
                    512 => return Ok(None),
                    _ => return Err(std::io::ErrorKind::UnexpectedEof.into()),
                },
                Ok(n) => {
                    todo = &mut todo[n..];
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }

        Ok(Some(header))
    }

    fn get_size(&self) -> usize {
        let size_field = &self.data[124..124 + 12];
        let mut value = 0usize;

        if size_field[0] & 0x80 != 0 {
            // binary representation
            for byte in &size_field[4..12] {
                value <<= 8;
                value += *byte as usize;
            }
        } else {
            // octal representation with nul terminator
            for byte in size_field {
                if *byte == b'\0' {
                    break;
                } else {
                    // add octal digit value (no error checking)
                    value <<= 3;
                    value += (*byte - b'0') as usize;
                }
            }
        }

        // TODO: not too big, I hope...
        value
    }

    fn get_storage_size(&self) -> usize {
        // round up to nearest multiple of 512
        (self.get_size() + 511) & !511
    }

    fn is_reg(&self) -> bool {
        self.data[156] == b'0'
    }
}

/// Splits the tar file from tar_stream into a Split Stream.  The store_data function is
/// responsible for ensuring that "external data" is in the composefs repository and returns the
/// fsverity hash value of that data.
pub fn split<R: Read, W: Write, F: FnMut(Vec<u8>) -> std::io::Result<Sha256HashValue>>(
    tar_stream: &mut R,
    split_stream: &mut W,
    mut store_data: F,
) -> std::io::Result<()> {
    let mut writer = SplitStreamWriter::new(split_stream);

    while let Some(header) = TarHeader::read(tar_stream)? {
        // the header always gets stored as inline data
        writer.write_inline(&header.data);

        // read the corresponding data, if there is any
        let storage_size = header.get_storage_size();
        let mut buffer = vec![0u8; storage_size];
        tar_stream.read_exact(&mut buffer)?;

        if header.is_reg() && storage_size > 0 {
            // non-empty regular file: store the data in the object store
            let actual_size = header.get_size();
            let padding = buffer.split_off(actual_size);
            let reference = store_data(buffer)?;
            writer.write_reference(reference, padding)?;
        } else {
            // else: store the data inline in the split stream
            writer.write_inline(&buffer);
        }
    }

    // flush out any remaining inline data
    writer.done()
}
