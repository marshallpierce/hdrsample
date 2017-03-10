use super::{V2_COOKIE, V2_HEADER_SIZE};
use super::super::{Counter, Histogram};
use std::io::Write;
use std;
use super::byteorder::{BigEndian, LittleEndian, WriteBytesExt};

/// Errors that occur during serialization.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum SerializeError {
    /// A count above i64::max_value() cannot be zig-zag encoded, and therefore cannot be
    /// serialized.
    CountNotSerializable,
    /// Internal calculations cannot be represented in `usize`. Use smaller histograms or beefier
    /// hardware.
    UsizeTypeTooSmall,
    /// An i/o operation failed.
    IoError
}

impl std::convert::From<std::io::Error> for SerializeError {
    fn from(_: std::io::Error) -> Self {
        SerializeError::IoError
    }
}

/// Serializer for the V2 binary format.
/// Serializers are intended to be re-used for many histograms.
pub struct V2Serializer {
    buf: Vec<u8>
}

impl V2Serializer {
    /// Create a new serializer.
    pub fn new() -> V2Serializer {
        V2Serializer {
            buf: Vec::new()
        }
    }

    /// Serialize the histogram.
    /// Returns the number of bytes written, or an io error.
    pub fn serialize<T: Counter, W: Write>(&mut self, h: &Histogram<T>, writer: &mut W)
                                           -> Result<usize, SerializeError> {
        self.buf.clear();
        let max_size = max_encoded_size(h).ok_or(SerializeError::UsizeTypeTooSmall)?;
        self.buf.reserve(max_size);

        self.buf.write_u32::<BigEndian>(V2_COOKIE)?;
        // placeholder for length
        self.buf.write_u32::<BigEndian>(0)?;
        // normalizing index offset
        self.buf.write_u32::<BigEndian>(0)?;
        self.buf.write_u32::<BigEndian>(h.significant_value_digits as u32)?;
        self.buf.write_u64::<BigEndian>(h.lowest_discernible_value)?;
        self.buf.write_u64::<BigEndian>(h.highest_trackable_value)?;
        // int to double conversion
        self.buf.write_f64::<BigEndian>(1.0)?;

        debug_assert_eq!(V2_HEADER_SIZE, self.buf.len());

        unsafe {
            // want to treat the rest of the vec as a slice, and we've already reserved this
            // space, so this way we don't have to resize() on a lot of dummy bytes.
            self.buf.set_len(max_size);
        }

        let counts_len = encode_counts(h, &mut self.buf[V2_HEADER_SIZE..])?;
        let total_len = V2_HEADER_SIZE + counts_len;

        // TODO benchmark fastest buffer management scheme
        // counts is always under 2^24
        (&mut self.buf[4..8]).write_u32::<BigEndian>(counts_len as u32)?;

        writer.write_all(&mut self.buf[0..(total_len)])
            .map(|_| total_len)
            .map_err(|_| SerializeError::IoError)
    }
}

fn max_encoded_size<T: Counter>(h: &Histogram<T>) -> Option<usize> {
    counts_array_max_encoded_size(h.index_for(h.max()) + 1)
        .and_then(|x| x.checked_add(V2_HEADER_SIZE))
}

pub fn counts_array_max_encoded_size(length: usize) -> Option<usize> {
    // LEB128-64b9B uses at most 9 bytes
    // Won't overflow (except sometimes on 16 bit systems) because largest possible counts
    // len is 47 buckets, each with 2^17 half count, for a total of 6e6. This product will
    // therefore be about 5e7 (50 million) at most.
    length.checked_mul(9)
}

/// Encode counts array into slice.
/// The slice must be at least 9 * the number of counts that will be encoded.
pub fn encode_counts<T: Counter>(h: &Histogram<T>, buf: &mut [u8]) -> Result<usize, SerializeError> {
    let index_limit = h.index_for(h.max()) + 1;
    let mut index = 0;
    let mut bytes_written = 0;

    assert!(index_limit <= h.counts.len());

    while index < index_limit {
        // index is inside h.counts because of the assert above
        let count = unsafe { *(h.counts.get_unchecked(index)) };
        index += 1;

        // Non-negative values are positive counts or 1 zero, negative values are repeated zeros.

        let mut zero_count = 0;
        if count == T::zero() {
            zero_count = 1;

            // index is inside h.counts because of the assert above
            while (index < index_limit) && (unsafe { *(h.counts.get_unchecked(index)) } == T::zero()) {
                zero_count += 1;
                index += 1;
            }
        }

        let count_or_zeros: i64 = if zero_count > 1 {
            // zero count can be at most the entire counts array, which is at most 2^24, so will fit.
            -zero_count
        } else {
            count.to_i64().ok_or(SerializeError::CountNotSerializable)?
        };

        let zz = zig_zag_encode(count_or_zeros);

        bytes_written += varint_write(zz, &mut buf[bytes_written..]);
    }

    Ok(bytes_written)
}

// lookup table. Row = number of bytes to output, column = byte index in the 9 byte output.
// No column for the 9th byte since it's just the untouched highest 8 bits of input.
// The low byte (lexically last) will be first in the output.
const MARK_BIT_LOOKUP_TABLE: [u64; 9] = [
    0x00_00_00_00_00_00_00_00,
    0x00_00_00_00_00_00_00_80,
    0x00_00_00_00_00_00_80_80,
    0x00_00_00_00_00_80_80_80,
    0x00_00_00_00_80_80_80_80,
    0x00_00_00_80_80_80_80_80,
    0x00_00_80_80_80_80_80_80,
    0x00_80_80_80_80_80_80_80,
    0x80_80_80_80_80_80_80_80,
];

// Mapping of leading zeros to how many bytes of output there will be
const OUTPUT_BYTES_LOOKUP_TABLE: [u8; 65] = [
    // if any of the top 8 bits are set, there will be a full 9th byte
    9, 9, 9, 9, 9, 9, 9, 9,
    8, 8, 8, 8, 8, 8, 8,
    7, 7, 7, 7, 7, 7, 7,
    6, 6, 6, 6, 6, 6, 6,
    5, 5, 5, 5, 5, 5, 5,
    4, 4, 4, 4, 4, 4, 4,
    3, 3, 3, 3, 3, 3, 3,
    2, 2, 2, 2, 2, 2, 2,
    1, 1, 1, 1, 1, 1, 1,
    // 64 leading zeros still gets 1 byte
    1
];


/// Write a number as a LEB128-64b9B little endian base 128 varint to buf. This is not
/// quite the same as Protobuf's LEB128 as it encodes 64 bit values in a max of 9 bytes, not 10.
/// The first 8 7-bit chunks are encoded normally (up through the first 7 bytes of input). The last
/// byte is added to the buf as-is. This limits the input to 8 bytes, but that's all we need.
/// Returns the number of bytes written (in [1, 9]).
#[inline]
pub fn varint_write(input: u64, mut buf: &mut [u8]) -> usize {

    let leading_zeros = input.leading_zeros();
    // TODO do arithmetic instead?
    let bytes_of_output = OUTPUT_BYTES_LOOKUP_TABLE[leading_zeros as usize] as usize;
    let mark_bits = MARK_BIT_LOOKUP_TABLE[bytes_of_output - 1];

    let first_8_bytes: u64 =
        (input & 0b00000000_00000000_00000000_00000000_00000000_00000000_00000000_01111111) |
            ((input & 0b00000000_00000000_00000000_00000000_00000000_00000000_00111111_10000000) << 1) |
            ((input & 0b00000000_00000000_00000000_00000000_00000000_00011111_11000000_00000000) << 2) |
            ((input & 0b00000000_00000000_00000000_00000000_00001111_11100000_00000000_00000000) << 3) |
            ((input & 0b00000000_00000000_00000000_00000111_11110000_00000000_00000000_00000000) << 4) |
            ((input & 0b00000000_00000000_00000011_11111000_00000000_00000000_00000000_00000000) << 5) |
            ((input & 0b00000000_00000001_11111100_00000000_00000000_00000000_00000000_00000000) << 6) |
            ((input & 0b00000000_11111110_00000000_00000000_00000000_00000000_00000000_00000000) << 7) |
            mark_bits;

//    println!("buf len: {}, bytes: {}, mark: 0x{:016X}, first 8: 0x{:016X}, input: 0x{:016X}",
//             buf.len(), bytes_of_output, mark_bits, first_8_bytes, input);

    // least significant byte goes first
    buf.write_u64::<LittleEndian>(first_8_bytes).unwrap();
    // buf has advanced, the next byte is the high one
    buf[0] = (input >> 56) as u8;

    return bytes_of_output;
}

/// Map signed numbers to unsigned: 0 to 0, -1 to 1, 1 to 2, -2 to 3, etc
#[inline]
pub fn zig_zag_encode(num: i64) -> u64 {
    // If num < 0, num >> 63 is all 1 and vice versa.
    ((num << 1) ^ (num >> 63)) as u64
}
