//! Legacy pcap writer (little-endian, µs, Ethernet). Powers the fixture
//! generator and the `pincer gen` subcommand — the reader and writer form a
//! closed test loop, with `etherparse` as the independent referee in tests.
#![deny(clippy::arithmetic_side_effects)]

use std::io::{self, Write};

use crate::types::Timestamp;

const SNAPLEN: u32 = 65_535;

#[derive(Debug)]
pub struct PcapWriter<W: Write> {
    writer: W,
}

impl<W: Write> PcapWriter<W> {
    /// Writes the 24-byte global header immediately.
    pub fn new(mut writer: W) -> io::Result<Self> {
        writer.write_all(&0xA1B2_C3D4u32.to_le_bytes())?; // magic, µs resolution
        writer.write_all(&2u16.to_le_bytes())?; // version major
        writer.write_all(&4u16.to_le_bytes())?; // version minor
        writer.write_all(&0u32.to_le_bytes())?; // thiszone
        writer.write_all(&0u32.to_le_bytes())?; // sigfigs
        writer.write_all(&SNAPLEN.to_le_bytes())?;
        writer.write_all(&1u32.to_le_bytes())?; // DLT_EN10MB
        Ok(Self { writer })
    }

    pub fn write_packet(&mut self, ts: Timestamp, frame: &[u8]) -> io::Result<()> {
        let len = u32::try_from(frame.len())
            .ok()
            .filter(|&len| len <= SNAPLEN)
            .ok_or_else(|| io::Error::other("packet exceeds snaplen"))?;
        let ts_sec =
            u32::try_from(ts.secs).map_err(|_| io::Error::other("timestamp beyond u32 seconds"))?;

        self.writer.write_all(&ts_sec.to_le_bytes())?;
        self.writer.write_all(&(ts.nanos / 1000).to_le_bytes())?;
        self.writer.write_all(&len.to_le_bytes())?; // incl_len
        self.writer.write_all(&len.to_le_bytes())?; // orig_len
        self.writer.write_all(frame)
    }

    pub fn finish(mut self) -> io::Result<W> {
        self.writer.flush()?;
        Ok(self.writer)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::pcap::{CaptureReader, LinkType};

    #[test]
    fn round_trips_through_reader() {
        let mut writer = PcapWriter::new(Vec::new()).unwrap();
        let frame = [0xAAu8; 60];
        writer
            .write_packet(Timestamp::new(1_781_049_600, 123_456_000), &frame)
            .unwrap();
        let bytes = writer.finish().unwrap();

        let mut reader = CaptureReader::new(bytes.as_slice()).unwrap();
        let record = reader.next_record().unwrap().unwrap();
        assert_eq!(record.data, frame);
        assert_eq!(record.orig_len, 60);
        assert_eq!(record.link_type, LinkType::Ethernet);
        assert_eq!(record.ts, Timestamp::new(1_781_049_600, 123_456_000));
        assert!(reader.next_record().unwrap().is_none());
    }

    #[test]
    fn oversized_packet_rejected() {
        let mut writer = PcapWriter::new(Vec::new()).unwrap();
        let too_big = vec![0u8; 70_000];
        assert!(writer.write_packet(Timestamp::ZERO, &too_big).is_err());
    }
}
