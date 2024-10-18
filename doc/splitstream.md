# Split Stream

Split Stream is a trivial way of storing file formats (like tar) with the "data
blocks" stored in the composefs object tree with the goal that it's possible to
bit-for-bit recreate the entire file.  It's something like the idea behind
[tar-split](https://github.com/vbatts/tar-split), with some important differences:

 - although it's designed with `tar` files in mind, it's not specific to `tar`,
   or even to the idea of an archive file: any file format can be stored as a
   splitstream, and it might make sense to do so for any file format that
   contains large chunks of embedded data

 - it's based on storing external objects in the composefs object store

 - it's based on a trivial binary format

It is expected that the splitstream will be compressed before being stored on
disk.  In composefs, this is done using zstd.  The main reason for this is
that, after removing the actual file data, the remaining `tar` metadata
contains a very large amount of padding and empty space and compresses
extremely well.

## File format

The file format consists of a header, plus a number of data blocks.

### Mappings

The file starts with a single u64 le integer which is the number of mapping
structures present in the file.  A mapping is a relationship between a file
identified by its sha256 content hash and the fsverity hash of that same file.
These entries are encoded simply as the sha256 hash value (32 bytes) plus the
fsverity hash value (32 bytes) combined together into a single 64 byte record.

For example, if we had a file that mapped `1234..` to `abcd..` and `5678..` to
`efab..`, the header would look like:

```
     64bit    32 bytes   32 bytes + 32 bytes + 32 bytes
   +--------+----------+----------+----------+---------+
   | 2      | 1234     | abcd     | 5678     | efab    |
   +--------+----------+----------+----------+---------+
```

The mappings in the header are always sorted by their sha256 content hash
values.

The mappings serve two purposes:

 - in the case of splitstreams which refer to other splitstreams without
   directly embedding the content of the other stream, this provides a
   mechanism to find out which other streams are referenced.  This is used for
   garbage collection.

 - for the same usecase, it provides a mechanism to be able to verify the
   content of the referred splitstream (by checking its fsverity digest) before
   starting to iterate it

### Data blocks

After the header comes a number of data blocks.  Each block starts with a u64
le "size" field followed by some amount of data.

```
     64bit    variable-sized
   +--------+---------------....
   | size   | data...
   +--------+---------------....
```

There are two kinds of blocks:

  - "Inline" blocks (`size != 0`): in this case the length of the data is equal
    to the size.  This is "inline data" and is usually used for the metadata
    and padding present in the source file.  The Split Stream format itself
    doesn't have any padding, which implies that the size fields after the
    first may be unaligned.  This decision was taken to keep the format simple,
    and because the data is compressed before being stored, which removes the
    main advantages of aligned data.

  - "External" blocks (`size == 0`): in this case the length of the data is 32
    bytes.  This is the binary form of a sha256 hash value and is a reference
    to an object in the composefs repository (by its fs-verity digest).

That's it, really.  There's no header.  The stream is over when there are no
more blocks.
