//! Frame-by-frame access to a trace journal: the streaming event reader, the
//! checks that decide whether a frame can be genuine, the sparse index that
//! lets a finalized journal be resumed without rescanning it, and the chunked
//! compressor that makes such an index possible.

use crate::{ACTIVE_JOURNAL, EncryptionKey, FINAL_JOURNAL, TraceEvent, TraceManifest, seal};
use anyhow::{Context, Result, anyhow, bail};
use prost::Message;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::Path;

/// Hard cap on one journal frame, enforced identically by writers and readers.
pub(crate) const MAX_FRAME_BYTES: usize = 64 * 1024 * 1024;

/// Uncompressed bytes after which the finalized journal starts a new zstd
/// frame. Every zstd frame holds whole event frames, so a reader can start
/// decoding at any of them.
const ZSTD_CHUNK_BYTES: u64 = 1024 * 1024;

/// How reading a journal stopped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JournalEnd {
    /// The journal ended exactly at a frame boundary.
    Clean,
    /// The journal ended inside a frame: the recorder was interrupted while
    /// writing it, or is still writing it.
    TornTail,
    /// A complete frame cannot be genuine. Nothing after it is trusted.
    Invalid {
        reason: String,
        /// The frame does not chain from its predecessor, so one of the two
        /// was altered and neither can be vouched for.
        chain_break: bool,
    },
}

/// Compressed journal file as the zstd decoder consumes it, counting and
/// optionally hashing exactly the bytes that were used.
struct CompressedInput {
    inner: BufReader<File>,
    consumed: u64,
    hasher: Option<Sha256>,
}

impl Read for CompressedInput {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let available = self.fill_buf()?;
        let count = available.len().min(buffer.len());
        buffer[..count].copy_from_slice(&available[..count]);
        self.consume(count);
        Ok(count)
    }
}

impl BufRead for CompressedInput {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.inner.fill_buf()
    }

    fn consume(&mut self, amount: usize) {
        if let Some(hasher) = self.hasher.as_mut() {
            hasher.update(&self.inner.buffer()[..amount]);
        }
        self.inner.consume(amount);
        self.consumed += amount as u64;
    }
}

/// A finalized journal decoded one zstd frame at a time, so the compressed
/// offset at which each zstd frame starts is known.
struct ZstdFrames {
    decoder: Option<zstd::stream::read::Decoder<'static, CompressedInput>>,
    /// The input between two zstd frames.
    idle: Option<CompressedInput>,
    decompressed: u64,
    /// Compressed and decompressed offset at which the current zstd frame starts.
    boundary: (u64, u64),
}

impl ZstdFrames {
    fn new(file: File, compressed_offset: u64, decompressed_offset: u64, hash: bool) -> Self {
        Self {
            decoder: None,
            idle: Some(CompressedInput {
                inner: BufReader::new(file),
                consumed: compressed_offset,
                hasher: hash.then(Sha256::new),
            }),
            decompressed: decompressed_offset,
            boundary: (compressed_offset, decompressed_offset),
        }
    }
}

impl Read for ZstdFrames {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        loop {
            if self.decoder.is_none() {
                let mut input = self
                    .idle
                    .take()
                    .ok_or_else(|| io::Error::other("journal reader already failed"))?;
                if input.fill_buf()?.is_empty() {
                    self.idle = Some(input);
                    return Ok(0);
                }
                self.boundary = (input.consumed, self.decompressed);
                self.decoder =
                    Some(zstd::stream::read::Decoder::with_buffer(input)?.single_frame());
            }
            let count = self
                .decoder
                .as_mut()
                .expect("decoder was just installed")
                .read(buffer)?;
            if count > 0 {
                self.decompressed += count as u64;
                return Ok(count);
            }
            self.idle = self.decoder.take().map(|decoder| decoder.finish());
        }
    }
}

enum Source {
    Active(BufReader<File>),
    Final(Box<ZstdFrames>),
}

impl Read for Source {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Active(reader) => reader.read(buffer),
            Self::Final(frames) => frames.read(buffer),
        }
    }
}

/// One resume point of a finalized journal.
#[derive(Clone, Debug)]
struct IndexEntry {
    /// Highest sequence stored before this point.
    max_sequence: u64,
    compressed_offset: u64,
    decompressed_offset: u64,
}

/// Sparse map from event sequence to a position in a finalized journal where
/// decoding can start, built while the journal is read once. It is valid only
/// for the journal file it was built from.
#[derive(Clone, Debug)]
pub struct JournalIndex {
    journal_sha256: String,
    entries: Vec<IndexEntry>,
}

impl JournalIndex {
    /// Number of positions decoding can resume from.
    pub fn resume_points(&self) -> usize {
        self.entries.len()
    }
}

/// Position in an active journal that a live reader resumes from: the byte
/// offset after the last frame it read, and what the next frame must follow.
#[derive(Clone, Debug, Default)]
pub struct ActiveCursor {
    byte_offset: u64,
    sequence: u64,
    chain_head: Option<String>,
    /// False when only the byte offset is known, so the first frame read
    /// cannot be checked against a predecessor.
    anchored: bool,
}

impl ActiveCursor {
    /// The beginning of the journal.
    pub fn start() -> Self {
        Self {
            anchored: true,
            ..Self::default()
        }
    }

    /// A bare byte offset, as older callers kept it.
    pub fn at_byte(byte_offset: u64) -> Self {
        Self {
            byte_offset,
            anchored: byte_offset == 0,
            ..Self::default()
        }
    }

    pub fn byte_offset(&self) -> u64 {
        self.byte_offset
    }

    /// Sequence of the last event read through this cursor, 0 before any.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
}

enum Step {
    Event(Box<TraceEvent>),
    Clean,
    Torn,
    Invalid(anyhow::Error, bool),
}

/// Iterator over the events of a journal that holds one frame in memory at a
/// time.
///
/// A finalized journal must end at a frame boundary: ending anywhere else, or
/// holding a frame that does not decode, is an error. Whether its events are
/// the recorded ones is decided by verification, not here.
///
/// An active journal has no digest to check against, so every frame must
/// carry the trace id, follow its predecessor's sequence and, from format
/// version 2 on, chain from its predecessor's hash. The iterator ends at the
/// first frame that is incomplete or fails those checks; [`EventStream::end`]
/// says which.
pub struct EventStream {
    source: Source,
    key: Option<EncryptionKey>,
    trace_id: String,
    strict: bool,
    chained: bool,
    expected_sequence: Option<u64>,
    head: Option<String>,
    offset: u64,
    /// Offset and chain head before the most recently returned event.
    previous: Option<(u64, Option<String>)>,
    count: u64,
    max_sequence: u64,
    frame: Vec<u8>,
    end: Option<JournalEnd>,
    failed: bool,
    journal_sha256: Option<String>,
    index: Option<Vec<IndexEntry>>,
}

impl EventStream {
    /// Open the journal the manifest designates: the finalized journal once
    /// the manifest names one, otherwise the active journal.
    pub(crate) fn open(
        root: &Path,
        manifest: &TraceManifest,
        key: Option<EncryptionKey>,
    ) -> Result<Self> {
        let final_path = root.join("events").join(FINAL_JOURNAL);
        let active_path = root.join("events").join(ACTIVE_JOURNAL);
        if manifest.journal.is_none() && active_path.exists() {
            Self::active(&active_path, manifest, key, &ActiveCursor::start())
        } else if final_path.exists() {
            Self::finalized(&final_path, manifest, key, false)
        } else {
            bail!("trace has no event journal")
        }
    }

    /// Read a finalized journal from its beginning. With `hash`, the SHA-256
    /// of the compressed file is computed along the way.
    pub(crate) fn finalized(
        path: &Path,
        manifest: &TraceManifest,
        key: Option<EncryptionKey>,
        hash: bool,
    ) -> Result<Self> {
        let frames = ZstdFrames::new(File::open(path)?, 0, 0, hash);
        let mut stream = Self::new(Source::Final(Box::new(frames)), manifest, key, false);
        stream.index = Some(Vec::new());
        Ok(stream)
    }

    /// Read a finalized journal from the resume point covering `after_sequence`.
    fn resumed(
        path: &Path,
        manifest: &TraceManifest,
        key: Option<EncryptionKey>,
        index: &JournalIndex,
        after_sequence: u64,
    ) -> Result<Self> {
        let position = index
            .entries
            .partition_point(|entry| entry.max_sequence <= after_sequence);
        let (compressed, decompressed) = position
            .checked_sub(1)
            .map(|position| &index.entries[position])
            .map_or((0, 0), |entry| {
                (entry.compressed_offset, entry.decompressed_offset)
            });
        let mut file = File::open(path)?;
        file.seek(SeekFrom::Start(compressed))?;
        let frames = ZstdFrames::new(file, compressed, decompressed, false);
        let mut stream = Self::new(Source::Final(Box::new(frames)), manifest, key, false);
        stream.offset = decompressed;
        Ok(stream)
    }

    /// Read an active journal from `cursor`, checking every frame.
    pub(crate) fn active(
        path: &Path,
        manifest: &TraceManifest,
        key: Option<EncryptionKey>,
        cursor: &ActiveCursor,
    ) -> Result<Self> {
        let mut file = File::open(path)?;
        file.seek(SeekFrom::Start(cursor.byte_offset))?;
        let mut stream = Self::new(Source::Active(BufReader::new(file)), manifest, key, true);
        stream.offset = cursor.byte_offset;
        stream.max_sequence = cursor.sequence;
        if cursor.anchored {
            stream.expected_sequence = Some(cursor.sequence + 1);
            if stream.chained {
                stream.head = Some(match (&cursor.chain_head, cursor.sequence) {
                    (Some(head), _) => head.clone(),
                    (None, _) => seal::chain_genesis(&manifest.trace_id),
                });
            }
        }
        Ok(stream)
    }

    fn new(
        source: Source,
        manifest: &TraceManifest,
        key: Option<EncryptionKey>,
        strict: bool,
    ) -> Self {
        Self {
            source,
            key,
            trace_id: manifest.trace_id.clone(),
            strict,
            chained: manifest.format_version >= 2,
            expected_sequence: None,
            head: None,
            offset: 0,
            previous: None,
            count: 0,
            max_sequence: 0,
            frame: Vec::new(),
            end: None,
            failed: false,
            journal_sha256: manifest
                .journal
                .as_ref()
                .map(|journal| journal.sha256.clone()),
            index: None,
        }
    }

    /// How the journal ended, once the iterator has returned `None`. A stream
    /// that returned an error has no end.
    pub fn end(&self) -> Option<&JournalEnd> {
        self.end.as_ref()
    }

    /// Fail when an active journal stopped at a frame that cannot be genuine,
    /// for callers that must not pass off its valid prefix as the whole
    /// journal. An incomplete trailing frame is not an error: a recorder may
    /// still be writing it.
    pub fn ensure_intact(&self) -> Result<()> {
        if let Some(JournalEnd::Invalid { reason, .. }) = &self.end {
            bail!(
                "active journal is damaged after {} valid events ({reason}); `premier recover` finalizes the valid part",
                self.count
            )
        }
        Ok(())
    }

    /// Number of events returned so far.
    pub fn events_read(&self) -> u64 {
        self.count
    }

    /// Uncompressed journal offset after the last event returned.
    pub fn byte_offset(&self) -> u64 {
        self.offset
    }

    /// Chain head after the last event returned. Tracked for active journals
    /// of format version 2 read from a known position.
    pub fn chain_head(&self) -> Option<&str> {
        self.head.as_deref()
    }

    /// Body of the frame the last returned event was decoded from.
    pub(crate) fn last_frame(&self) -> &[u8] {
        &self.frame
    }

    /// Offset and chain head before the last returned event.
    pub(crate) fn before_last_event(&self) -> Option<&(u64, Option<String>)> {
        self.previous.as_ref()
    }

    /// Where a live reader continues from.
    pub(crate) fn cursor(&self) -> ActiveCursor {
        ActiveCursor {
            byte_offset: self.offset,
            sequence: self.max_sequence,
            chain_head: self.head.clone(),
            anchored: self.expected_sequence.is_some(),
        }
    }

    /// SHA-256 of the compressed journal, available once a hashing stream has
    /// been read to a clean end.
    pub(crate) fn finish_digest(&mut self) -> Result<Option<String>> {
        if self.end != Some(JournalEnd::Clean) {
            return Ok(None);
        }
        let Source::Final(frames) = &mut self.source else {
            return Ok(None);
        };
        let Some(input) = frames.idle.as_mut() else {
            return Ok(None);
        };
        // The decoder stops at the end of the file, so this consumes nothing
        // unless the file grew; hashing it keeps the digest that of the file.
        loop {
            let available = input.fill_buf()?.len();
            if available == 0 {
                break;
            }
            input.consume(available);
        }
        Ok(input
            .hasher
            .take()
            .map(|hasher| format!("{:x}", hasher.finalize())))
    }

    /// The resume points seen while reading a finalized journal from its
    /// beginning to a clean end.
    pub fn into_index(self) -> Option<JournalIndex> {
        if self.end != Some(JournalEnd::Clean) {
            return None;
        }
        Some(JournalIndex {
            journal_sha256: self.journal_sha256?,
            entries: self.index?,
        })
    }

    fn read_event(&mut self) -> Result<Step> {
        let start = self.offset;
        let mut prefix = [0_u8; 4];
        let mut filled = 0;
        while filled < prefix.len() {
            match self.source.read(&mut prefix[filled..]) {
                Ok(0) => break,
                Ok(count) => filled += count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error.into()),
            }
        }
        if filled == 0 {
            return Ok(Step::Clean);
        }
        if filled < prefix.len() {
            return Ok(Step::Torn);
        }
        if let (Some(index), Source::Final(frames)) = (self.index.as_mut(), &self.source) {
            let (compressed_offset, decompressed_offset) = frames.boundary;
            if decompressed_offset == start
                && index
                    .last()
                    .is_none_or(|entry| entry.compressed_offset != compressed_offset)
            {
                index.push(IndexEntry {
                    max_sequence: self.max_sequence,
                    compressed_offset,
                    decompressed_offset,
                });
            }
        }
        let length = u32::from_le_bytes(prefix) as usize;
        if length == 0 {
            return Ok(Step::Invalid(anyhow!("zero-length event frame"), false));
        }
        if length > MAX_FRAME_BYTES {
            return Ok(Step::Invalid(
                anyhow!("event frame exceeds the 64 MiB safety limit"),
                false,
            ));
        }
        // Grow with the data that is really there instead of trusting the
        // length prefix with one large allocation.
        self.frame.clear();
        let read = (&mut self.source)
            .take(length as u64)
            .read_to_end(&mut self.frame)?;
        if read < length {
            return Ok(Step::Torn);
        }
        let event = match decode_frame(&self.frame, self.key.as_ref(), &self.trace_id) {
            Ok(event) => event,
            Err(error) => return Ok(Step::Invalid(error, false)),
        };
        if event.sequence == 0 && event.event_id.is_empty() {
            return Ok(Step::Invalid(anyhow!("empty event frame"), false));
        }
        if self.strict
            && let Err((reason, chain_break)) = self.check_follows(&event)
        {
            return Ok(Step::Invalid(anyhow!(reason), chain_break));
        }
        self.previous = Some((start, self.head.clone()));
        if self.strict && self.chained {
            self.head = Some(seal::event_hash(&event));
        }
        if self.strict {
            self.expected_sequence = Some(event.sequence + 1);
        }
        self.offset = start + 4 + length as u64;
        self.count += 1;
        self.max_sequence = self.max_sequence.max(event.sequence);
        Ok(Step::Event(Box::new(event)))
    }

    /// Whether `event` can be the next event of this trace's active journal.
    fn check_follows(&self, event: &TraceEvent) -> std::result::Result<(), (String, bool)> {
        if event.trace_id != self.trace_id {
            return Err(("event from a different trace".into(), false));
        }
        if event.event_id.is_empty() || event.sequence == 0 {
            return Err(("event without an id or sequence".into(), false));
        }
        if let Some(expected) = self.expected_sequence
            && event.sequence != expected
        {
            return Err((
                format!(
                    "event sequence {} does not follow {}",
                    event.sequence,
                    expected - 1
                ),
                false,
            ));
        }
        if self.chained {
            match self.head.as_deref() {
                Some(head) if event.prev_hash != head => {
                    return Err((
                        format!(
                            "event chain is broken at sequence {}: an event was edited, inserted, removed or reordered",
                            event.sequence
                        ),
                        true,
                    ));
                }
                None if event.prev_hash.len() != 64
                    || !event.prev_hash.bytes().all(|byte| byte.is_ascii_hexdigit()) =>
                {
                    return Err(("event without a chain hash".into(), false));
                }
                _ => {}
            }
        }
        Ok(())
    }
}

impl Iterator for EventStream {
    type Item = Result<TraceEvent>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.end.is_some() {
            return None;
        }
        let step = match self.read_event() {
            Ok(step) => step,
            Err(error) => {
                self.failed = true;
                // The zstd decoder reports a stream cut short as an I/O error.
                let truncated = error
                    .downcast_ref::<io::Error>()
                    .is_some_and(|error| error.kind() == io::ErrorKind::UnexpectedEof);
                return Some(Err(if truncated {
                    error.context("journal is truncated: the compressed stream ends early")
                } else {
                    error.context("cannot read the event journal")
                }));
            }
        };
        match step {
            Step::Event(event) => Some(Ok(*event)),
            Step::Clean => {
                self.end = Some(JournalEnd::Clean);
                None
            }
            Step::Torn if self.strict => {
                self.end = Some(JournalEnd::TornTail);
                None
            }
            Step::Invalid(error, chain_break) if self.strict => {
                self.end = Some(JournalEnd::Invalid {
                    reason: format!("{error:#}"),
                    chain_break,
                });
                None
            }
            Step::Torn => {
                self.failed = true;
                Some(Err(anyhow!(
                    "journal is truncated: it ends inside an event frame after {} events",
                    self.count
                )))
            }
            Step::Invalid(error, _) => {
                self.failed = true;
                Some(Err(error))
            }
        }
    }
}

/// One page of a finalized journal, decoded from the resume point of `index`
/// that covers `after_sequence` instead of from the beginning.
pub(crate) fn read_indexed_page(
    root: &Path,
    manifest: &TraceManifest,
    key: Option<EncryptionKey>,
    index: &JournalIndex,
    after_sequence: u64,
    limit: usize,
) -> Result<Option<Vec<TraceEvent>>> {
    let current = manifest.journal.as_ref().map(|journal| &journal.sha256);
    if current != Some(&index.journal_sha256) {
        return Ok(None);
    }
    let path = root.join("events").join(FINAL_JOURNAL);
    let stream = EventStream::resumed(&path, manifest, key, index, after_sequence)?;
    collect_page(stream, after_sequence, limit).map(Some)
}

pub(crate) fn collect_page(
    stream: EventStream,
    after_sequence: u64,
    limit: usize,
) -> Result<Vec<TraceEvent>> {
    let mut events = Vec::with_capacity(limit.min(1024));
    if limit == 0 {
        return Ok(events);
    }
    for event in stream {
        let event = event?;
        if event.sequence > after_sequence {
            events.push(event);
            if events.len() >= limit {
                break;
            }
        }
    }
    Ok(events)
}

/// Number of frames in the part of an active journal that recovery discards,
/// when that can be known: the bytes from `from` must split, by their length
/// prefixes, into frames that (after the first, which is the one that failed)
/// decode as events of this trace, optionally ending in one incomplete frame.
pub(crate) fn count_discarded_frames(
    path: &Path,
    from: u64,
    key: Option<&EncryptionKey>,
    trace_id: &str,
) -> Result<Option<u64>> {
    let mut file = File::open(path)?;
    let total = file.metadata()?.len();
    file.seek(SeekFrom::Start(from))?;
    let mut reader = BufReader::new(file);
    let mut offset = from;
    let mut frames = 0_u64;
    let mut body = Vec::new();
    while offset < total {
        if total - offset < 4 {
            return Ok(Some(frames + 1));
        }
        let mut prefix = [0_u8; 4];
        reader.read_exact(&mut prefix)?;
        let length = u32::from_le_bytes(prefix) as u64;
        if length == 0 || length > MAX_FRAME_BYTES as u64 {
            return Ok(None);
        }
        if total - offset - 4 < length {
            return Ok(Some(frames + 1));
        }
        body.clear();
        (&mut reader).take(length).read_to_end(&mut body)?;
        if frames > 0
            && decode_frame(&body, key, trace_id).map_or(true, |event| event.trace_id != trace_id)
        {
            return Ok(None);
        }
        frames += 1;
        offset += 4 + length;
    }
    Ok(Some(frames))
}

/// Writes the finalized journal as a series of zstd frames, each holding
/// whole event frames. Concatenated zstd frames are one valid zstd stream.
pub(crate) struct JournalCompressor<W: Write> {
    encoder: Option<zstd::stream::write::Encoder<'static, W>>,
    chunk_bytes: u64,
}

impl<W: Write> JournalCompressor<W> {
    pub(crate) fn new(writer: W) -> Result<Self> {
        Ok(Self {
            encoder: Some(zstd::stream::write::Encoder::new(writer, 3)?),
            chunk_bytes: 0,
        })
    }

    /// Call before writing each event frame.
    pub(crate) fn begin_frame(&mut self) -> Result<()> {
        if self.chunk_bytes < ZSTD_CHUNK_BYTES {
            return Ok(());
        }
        let writer = self
            .encoder
            .take()
            .context("journal compressor already failed")?
            .finish()?;
        self.encoder = Some(zstd::stream::write::Encoder::new(writer, 3)?);
        self.chunk_bytes = 0;
        Ok(())
    }

    pub(crate) fn finish(mut self) -> Result<W> {
        Ok(self
            .encoder
            .take()
            .context("journal compressor already failed")?
            .finish()?)
    }
}

impl<W: Write> Write for JournalCompressor<W> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let encoder = self
            .encoder
            .as_mut()
            .ok_or_else(|| io::Error::other("journal compressor already failed"))?;
        let count = encoder.write(buffer)?;
        self.chunk_bytes += count as u64;
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.encoder.as_mut() {
            Some(encoder) => encoder.flush(),
            None => Ok(()),
        }
    }
}

pub(crate) fn write_frame(
    writer: &mut impl Write,
    event: &TraceEvent,
    encryption_key: Option<&EncryptionKey>,
    trace_id: &str,
) -> Result<()> {
    let plaintext = event.encode_to_vec();
    let bytes = if let Some(key) = encryption_key {
        let mut envelope = event.sequence.to_le_bytes().to_vec();
        envelope.extend_from_slice(
            key.encrypt(&plaintext, event_aad(trace_id, event.sequence).as_bytes())?
                .as_bytes(),
        );
        envelope
    } else {
        plaintext
    };
    write_frame_body(writer, &bytes)
}

/// Write an already encoded frame body behind its length prefix.
pub(crate) fn write_frame_body(writer: &mut impl Write, body: &[u8]) -> Result<()> {
    if body.len() > MAX_FRAME_BYTES {
        bail!("event frame exceeds the 64 MiB safety limit")
    }
    let length = u32::try_from(body.len()).expect("frame length fits in u32");
    writer.write_all(&length.to_le_bytes())?;
    writer.write_all(body)?;
    Ok(())
}

fn decode_frame(
    bytes: &[u8],
    encryption_key: Option<&EncryptionKey>,
    trace_id: &str,
) -> Result<TraceEvent> {
    let Some(key) = encryption_key else {
        return Ok(TraceEvent::decode(bytes)?);
    };
    if bytes.len() < 8 {
        bail!("encrypted event frame is truncated")
    }
    let sequence = u64::from_le_bytes(bytes[..8].try_into().unwrap());
    let envelope = std::str::from_utf8(&bytes[8..]).context("invalid encrypted event envelope")?;
    let plaintext = key.decrypt(envelope, event_aad(trace_id, sequence).as_bytes())?;
    let decoded = TraceEvent::decode(plaintext.as_slice())?;
    if decoded.sequence != sequence {
        bail!("encrypted event sequence binding mismatch")
    }
    Ok(decoded)
}

fn event_aad(trace_id: &str, sequence: u64) -> String {
    format!("premier:journal-frame:v1:{trace_id}:{sequence}")
}
