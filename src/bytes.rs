//! Panic-free byte cursor — the single chokepoint for *indexing or slicing*
//! raw packet bytes; every accessor here is bounds-checked and returns
//! `Result`, which is what makes the crate-wide "never panics on hostile
//! input" claim provable. (A few consumers read the bytes it yields through
//! safe std APIs — `str::from_utf8`, `windows()` — which cannot panic
//! either; `clippy::indexing_slicing` is denied everywhere else.)
#![deny(clippy::arithmetic_side_effects)]

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::error::DecodeError;
use crate::types::MacAddr;

// Deliberately NOT `Copy`: a callee that received the cursor by value would
// silently advance its own copy while the caller's position stays put —
// exactly the bug class the single-chokepoint design exists to prevent.
#[derive(Debug, Clone)]
pub struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    #[must_use]
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// A cursor over the same buffer positioned at `offset` — used by DNS name
    /// decompression, which must jump to earlier offsets in the message.
    pub fn at(data: &'a [u8], offset: usize) -> Result<Self, DecodeError> {
        if offset > data.len() {
            return Err(DecodeError::truncated(offset, data.len()));
        }
        Ok(Self { data, pos: offset })
    }

    #[must_use]
    pub const fn pos(&self) -> usize {
        self.pos
    }

    #[must_use]
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Take the next `n` bytes, advancing the cursor.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| DecodeError::truncated(n, self.remaining()))?;
        let slice = self
            .data
            .get(self.pos..end)
            .ok_or_else(|| DecodeError::truncated(n, self.remaining()))?;
        self.pos = end;
        Ok(slice)
    }

    pub fn skip(&mut self, n: usize) -> Result<(), DecodeError> {
        self.take(n).map(|_| ())
    }

    /// The next byte without consuming it, if any.
    #[must_use]
    pub fn peek_first(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }

    /// All bytes from the current position to the end; advances to the end.
    pub fn rest(&mut self) -> &'a [u8] {
        let slice = self.data.get(self.pos..).unwrap_or(&[]);
        self.pos = self.data.len();
        slice
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        // `try_into` keeps even this conversion provably panic-free (a
        // `copy_from_slice` would panic on length mismatch — unreachable,
        // but "unreachable" is a weaker proof than "no panic path exists").
        self.take(N)?
            .try_into()
            .map_err(|_| DecodeError::truncated(N, 0))
    }

    pub fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.array::<1>()?[0])
    }

    pub fn u16_be(&mut self) -> Result<u16, DecodeError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    pub fn u16_le(&mut self) -> Result<u16, DecodeError> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    pub fn u32_be(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    pub fn u32_le(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    pub fn mac(&mut self) -> Result<MacAddr, DecodeError> {
        Ok(MacAddr(self.array()?))
    }

    pub fn ipv4(&mut self) -> Result<Ipv4Addr, DecodeError> {
        Ok(Ipv4Addr::from(self.array::<4>()?))
    }

    pub fn ipv6(&mut self) -> Result<Ipv6Addr, DecodeError> {
        Ok(Ipv6Addr::from(self.array::<16>()?))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn reads_in_order() {
        let data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let mut cur = Cursor::new(&data);
        assert_eq!(cur.u8().unwrap(), 0x01);
        assert_eq!(cur.u16_be().unwrap(), 0x0203);
        assert_eq!(cur.u16_le().unwrap(), 0x0504);
        assert_eq!(cur.remaining(), 2);
        assert_eq!(cur.take(2).unwrap(), &[0x06, 0x07]);
        assert!(cur.is_empty());
    }

    #[test]
    fn truncation_reports_needed_vs_have() {
        let data = [0xAA];
        let mut cur = Cursor::new(&data);
        let err = cur.u32_be().unwrap_err();
        assert_eq!(err, DecodeError::Truncated { needed: 4, have: 1 });
        // a failed read consumes nothing
        assert_eq!(cur.u8().unwrap(), 0xAA);
    }

    #[test]
    fn take_zero_always_succeeds() {
        let mut cur = Cursor::new(&[]);
        assert_eq!(cur.take(0).unwrap(), &[] as &[u8]);
        assert!(cur.u8().is_err());
    }

    #[test]
    fn rest_drains() {
        let data = [1, 2, 3];
        let mut cur = Cursor::new(&data);
        cur.skip(1).unwrap();
        assert_eq!(cur.rest(), &[2, 3]);
        assert_eq!(cur.rest(), &[] as &[u8]);
    }

    #[test]
    fn position_arithmetic_cannot_overflow() {
        // pos + n overflowing usize must be an error, not a wrap-around.
        let data = [0u8; 4];
        let mut cur = Cursor::new(&data);
        cur.skip(1).unwrap();
        assert!(cur.take(usize::MAX).is_err());
        assert_eq!(cur.pos(), 1, "failed take must not move the cursor");
    }

    #[test]
    fn peek_and_skip_cover_their_edges() {
        let data = [7u8, 8];
        let mut cur = Cursor::new(&data);
        assert_eq!(cur.peek_first(), Some(7));
        assert_eq!(cur.pos(), 0, "peek must not consume");
        cur.skip(2).unwrap();
        assert_eq!(cur.peek_first(), None);
        assert!(cur.skip(1).is_err());
    }

    #[test]
    fn at_rejects_out_of_bounds() {
        assert!(Cursor::at(&[1, 2], 3).is_err());
        assert!(Cursor::at(&[1, 2], 2).is_ok()); // at end is legal, just empty
    }
}
