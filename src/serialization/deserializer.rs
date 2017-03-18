use super::V2_COOKIE;
use super::super::{Counter, Histogram, RestatState};
use super::super::num::ToPrimitive;
use std::io::{self, Cursor, ErrorKind, Read};
use std::marker::PhantomData;
use std;
use super::byteorder::{BigEndian, ReadBytesExt};

// Read payload in chunks. The number doesn't seem to make a major difference, so we'll just pick
// the default page table entry size since that will fit certainly in L1 and also a 16-bit usize.
const PAYLOAD_CHUNK_LEN: usize = 4096;
const VARINT_MAX_LEN: usize = 9;

/// Errors that can happen during deserialization.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum DeserializeError {
    /// An i/o operation failed.
    IoError(ErrorKind),
    /// The cookie (first 4 bytes) did not match that for any supported format.
    InvalidCookie,
    /// The histogram uses features that this implementation doesn't support (yet), so it cannot
    /// be deserialized correctly.
    UnsupportedFeature,
    /// A count exceeded what can be represented in the chosen counter type.
    UnsuitableCounterType,
    /// The histogram instance could not be created because the serialized parameters were invalid
    /// (e.g. lowest value, highest value, etc.)
    InvalidParameters,
    /// The current system's pointer width cannot represent the encoded histogram.
    UsizeTypeTooSmall,
    /// The encoded array is longer than it should be for the histogram's value range.
    EncodedArrayTooLong
}

impl std::convert::From<std::io::Error> for DeserializeError {
    fn from(e: std::io::Error) -> Self {
        DeserializeError::IoError(e.kind())
    }
}

/// Deserializer for all supported formats.
///
/// Since the serialization formats all include some magic bytes that allow reliable identification
/// of the different formats, only one Deserializer implementation is needed.
pub struct Deserializer {
    payload_buf: Vec<u8>
}

impl Deserializer {
    /// Create a new deserializer.
    pub fn new() -> Deserializer {
        let mut d = Deserializer {
            payload_buf: Vec::with_capacity(PAYLOAD_CHUNK_LEN)
        };

        d.payload_buf.resize(PAYLOAD_CHUNK_LEN, 0);

        d
    }

    /// Deserialize an encoded histogram from the provided reader.
    ///
    /// Note that `&[u8]` and `Cursor` are convenient implementations of `Read` if you have some
    /// bytes already in slice or `Vec` form.
    pub fn deserialize<T: Counter, R: Read>(&mut self, reader: &mut R)
                                            -> Result<Histogram<T>, DeserializeError> {
        let cookie = reader.read_u32::<BigEndian>()?;

        if cookie != V2_COOKIE {
            return Err(DeserializeError::InvalidCookie);
        }

        let payload_len = reader.read_u32::<BigEndian>()?;
        let normalizing_offset = reader.read_u32::<BigEndian>()?;
        if normalizing_offset != 0 {
            return Err(DeserializeError::UnsupportedFeature);
        }
        let num_digits = reader.read_u32::<BigEndian>()?.to_u8()
            .ok_or(DeserializeError::InvalidParameters)?;
        let low = reader.read_u64::<BigEndian>()?;
        let high = reader.read_u64::<BigEndian>()?;
        let int_double_ratio = reader.read_f64::<BigEndian>()?;
        if int_double_ratio != 1.0 {
            return Err(DeserializeError::UnsupportedFeature);
        }

        let mut h = Histogram::new_with_bounds(low, high, num_digits)
            .map_err(|_| DeserializeError::InvalidParameters)?;

        let mut bytes_read_in_chunk: usize = 0;
        let mut restat_state = RestatState::new();
        let mut decode_state = DecodeLoopState::new();
        // how many un-processed bytes were copied from the end of the previous chunk to this one
        let mut chunk_leftover_len: usize = 0;
        // How many bytes have been read and deserialized in all previous chunks.
        // May exceed usize type, but we don't allocate a contiguous array this big.
        let mut total_payload_bytes_deserialized: u32 = 0;

        {
            let mut payload_chunk = &mut self.payload_buf[0..PAYLOAD_CHUNK_LEN];
            // Cast is safe: chunk length is much lower than u32 max.
            let first_invalid_chunk_start = payload_len.saturating_sub(PAYLOAD_CHUNK_LEN as u32);
            // There will be some carryover from the previous chunk, so the loop can't just be as
            // many chunks as would fit perfectly into payload_len.
            // Subtract off chunk_leftover_len because we will need to read that many fewer bytes
            // than a full chunk. Subtraction is safe because either it's the first iteration and
            // chunk_leftover_len is 0 or it's a subsequent iteration and total is at least
            // min_varints_per_chunk. Cast is safe because chunk_leftover_len is in [0, 8].
            while total_payload_bytes_deserialized - (chunk_leftover_len as u32) < first_invalid_chunk_start {
                // read into the slice, starting just after the leftover bytes from previous chunk
                reader.read_exact(&mut payload_chunk[chunk_leftover_len..])?;

                while bytes_read_in_chunk <= PAYLOAD_CHUNK_LEN - VARINT_MAX_LEN {
                    let (zz_num, bytes_read) = varint_read_slice(
                        &payload_chunk[bytes_read_in_chunk..(bytes_read_in_chunk + VARINT_MAX_LEN)]);
                    bytes_read_in_chunk += bytes_read;

                    let count_or_zeros = zig_zag_decode(zz_num);
                    decode_state.on_decoded_num(count_or_zeros, &mut restat_state, &mut h)?;
                };

                // The next deserialize would have gone out of bounds
                debug_assert!(bytes_read_in_chunk + VARINT_MAX_LEN > PAYLOAD_CHUNK_LEN);

                // VARINT_MAX_LEN or fewer bytes left over; copy them to the beginning.
                chunk_leftover_len = PAYLOAD_CHUNK_LEN.checked_sub(bytes_read_in_chunk)
                    .expect("Read more bytes in the chunk than the chunk length?");
                debug_assert!(chunk_leftover_len <= 8);
                // No risk of reading what we write because we're at opposite ends of a much larger
                // (PAYLOAD_CHUNK_LEN) slice.
                for i in 0..chunk_leftover_len {
                    payload_chunk[i] = payload_chunk[bytes_read_in_chunk + i];
                };

                // Cast is safe, PAYLOAD_CHUNK_LEN is much lower than u32 max
                total_payload_bytes_deserialized += bytes_read_in_chunk as u32;
                bytes_read_in_chunk = 0;
            };
        };

        // Read the last partial chunk. Cast is safe: chunk_leftover_len in [0, 8].
        let bytes_read = total_payload_bytes_deserialized + chunk_leftover_len as u32;
        let bytes_to_read_last_chunk = (payload_len - bytes_read).to_usize()
            .expect("Chunk calculation error: too many bytes to read for last chunk");
        assert!(bytes_to_read_last_chunk < PAYLOAD_CHUNK_LEN,
            "Chunk calculation error: last chunk too big");
        // This is always at least chunk_leftover_len
        let last_chunk_len = chunk_leftover_len.checked_add(bytes_to_read_last_chunk)
            .expect("Last chunk too big");

        {
            let mut last_read_slice = &mut self.payload_buf[chunk_leftover_len..last_chunk_len];
            reader.read_exact(&mut last_read_slice)?;
        }

        let last_chunk = &mut self.payload_buf[0..last_chunk_len];

        while bytes_read_in_chunk < last_chunk_len.saturating_sub(VARINT_MAX_LEN) {
            let (zz_num, bytes_read) = varint_read_slice(
                &last_chunk[bytes_read_in_chunk..(bytes_read_in_chunk + VARINT_MAX_LEN)]);
            bytes_read_in_chunk += bytes_read;

            let count_or_zeros = zig_zag_decode(zz_num);
            decode_state.on_decoded_num(count_or_zeros, &mut restat_state, &mut h)?;
        };

        // Read the last few bytes with a slower, EOF-capable varint function
        let slow_loop_slice = &last_chunk[bytes_read_in_chunk..];
        let mut cursor = Cursor::new(&slow_loop_slice);
        while cursor.position() < slow_loop_slice.len() as u64 {
            let count_or_zeros = zig_zag_decode(varint_read(&mut cursor)?);
            decode_state.on_decoded_num(count_or_zeros, &mut restat_state, &mut h)?;
        }

        restat_state.update_histogram(&mut h);

        Ok(h)
    }
}

// Only public for testing.
/// Read from a slice that must be 9 bytes long or longer. Returns the decoded number and how many
/// bytes were consumed.
#[inline]
pub fn varint_read_slice(slice: &[u8]) -> (u64, usize) {
    let mut b = slice[0];

    // take low 7 bits
    let mut value: u64 = low_7_bits(b);
    if !is_high_bit_set(b) {
        return (value, 1);
    }
    // high bit set, keep reading
    b = slice[1];
    value |= low_7_bits(b) << 7;
    if !is_high_bit_set(b) {
        return (value, 2);
    }
    b = slice[2];
    value |= low_7_bits(b) << 7 * 2;
    if !is_high_bit_set(b) {
        return (value, 3);
    }
    b = slice[3];
    value |= low_7_bits(b) << 7 * 3;
    if !is_high_bit_set(b) {
        return (value, 4);
    }
    b = slice[4];
    value |= low_7_bits(b) << 7 * 4;
    if !is_high_bit_set(b) {
        return (value, 5);
    }
    b = slice[5];
    value |= low_7_bits(b) << 7 * 5;
    if !is_high_bit_set(b) {
        return (value, 6);
    }
    b = slice[6];
    value |= low_7_bits(b) << 7 * 6;
    if !is_high_bit_set(b) {
        return (value, 7);
    }
    b = slice[7];
    value |= low_7_bits(b) << 7 * 7;
    if !is_high_bit_set(b) {
        return (value, 8);
    }

    b = slice[8];
    // special case: use last byte as is
    value |= (b as u64) << 7 * 8;

    (value, 9)
}

// Only public for testing.
/// Read a LEB128-64b9B from the buffer
pub fn varint_read<R: Read>(reader: &mut R) -> io::Result<u64> {
    let mut b = reader.read_u8()?;

    // take low 7 bits
    let mut value: u64 = low_7_bits(b);

    if is_high_bit_set(b) {
        // high bit set, keep reading
        b = reader.read_u8()?;
        value |= low_7_bits(b) << 7;
        if is_high_bit_set(b) {
            b = reader.read_u8()?;
            value |= low_7_bits(b) << 7 * 2;
            if is_high_bit_set(b) {
                b = reader.read_u8()?;
                value |= low_7_bits(b) << 7 * 3;
                if is_high_bit_set(b) {
                    b = reader.read_u8()?;
                    value |= low_7_bits(b) << 7 * 4;
                    if is_high_bit_set(b) {
                        b = reader.read_u8()?;
                        value |= low_7_bits(b) << 7 * 5;
                        if is_high_bit_set(b) {
                            b = reader.read_u8()?;
                            value |= low_7_bits(b) << 7 * 6;
                            if is_high_bit_set(b) {
                                b = reader.read_u8()?;
                                value |= low_7_bits(b) << 7 * 7;
                                if is_high_bit_set(b) {
                                    b = reader.read_u8()?;
                                    // special case: use last byte as is
                                    value |= (b as u64) << 7 * 8;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(value)
}

/// truncate byte to low 7 bits, cast to u64
#[inline]
fn low_7_bits(b: u8) -> u64 {
    (b & 0x7F) as u64
}

#[inline]
fn is_high_bit_set(b: u8) -> bool {
    (b & 0x80) != 0
}

// Only public for testing.
#[inline]
pub fn zig_zag_decode(encoded: u64) -> i64 {
    ((encoded >> 1) as i64) ^ -((encoded & 1) as i64)
}

/// We need to perform the same logic in two different decode loops while carrying over a modicum
/// of state.
struct DecodeLoopState<T: Counter> {
    dest_index: usize,
    phantom: PhantomData<T>
}

impl<T: Counter> DecodeLoopState<T> {
    fn new() -> DecodeLoopState<T> {
        DecodeLoopState {
            dest_index: 0,
            phantom: PhantomData
        }
    }

    #[inline]
    fn on_decoded_num(&mut self, count_or_zeros: i64, restat_state: &mut RestatState<T>,
                      h: &mut Histogram<T>) -> Result<(), DeserializeError> {
        if count_or_zeros < 0 {
            let zero_count = (-count_or_zeros).to_usize()
                .ok_or(DeserializeError::UsizeTypeTooSmall)?;
            // skip the zeros
            self.dest_index = self.dest_index.checked_add(zero_count)
                .ok_or(DeserializeError::UsizeTypeTooSmall)?;
        } else {
            let count: T = T::from_i64(count_or_zeros)
                .ok_or(DeserializeError::UnsuitableCounterType)?;

            if count > T::zero() {
                h.set_count_at_index(self.dest_index, count)
                    .map_err(|_| DeserializeError::EncodedArrayTooLong)?;

                restat_state.on_nonzero_count(self.dest_index, count);
            }

            self.dest_index = self.dest_index.checked_add(1)
                .ok_or(DeserializeError::UsizeTypeTooSmall)?;
        }

        Ok(())
    }
}
