//! Whether a trace without a finalized journal is still being recorded.
//!
//! `premier list`, `premier verify`, and the viewer API all answer this the
//! same way, from the recorder lease.

use premier_trace::{
    ACTIVE_JOURNAL, IntegrityReport, IntegrityStatus, RECORDER_LEASE, RecoveryOptions,
    TraceManifest,
};
use std::fs;
use std::path::Path;
use std::time::Duration;

/// Why a trace without a finalized journal is in that state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnfinalizedState {
    /// The recorder named in the lease is alive and heartbeating.
    Recording,
    /// The recorder is gone; `recover` needs `--force` only while the
    /// journal is still inside its idle guard.
    Abandoned { needs_force: bool },
}

impl UnfinalizedState {
    /// The command that finalizes an abandoned trace.
    pub fn recover_command(&self, trace: &Path) -> String {
        let force = matches!(self, Self::Abandoned { needs_force: true });
        format!(
            "premier recover {}{}",
            if force { "--force " } else { "" },
            trace.display()
        )
    }

    pub fn describe(&self, trace: &Path) -> String {
        match self {
            Self::Recording => "still recording".into(),
            Self::Abandoned { .. } => format!(
                "abandoned: the recorder is no longer running — run `{}`",
                self.recover_command(trace)
            ),
        }
    }
}

/// Classify an unfinalized trace from its recorder lease, exactly as
/// `premier recover` does.
pub fn unfinalized_state(trace: &Path, manifest: &TraceManifest) -> Option<UnfinalizedState> {
    if manifest.journal.is_some() {
        return None;
    }
    let needs_force = match recorder_liveness(trace) {
        RecorderLiveness::Alive(_) => return Some(UnfinalizedState::Recording),
        RecorderLiveness::Dead => false,
        // `premier recover` then guards on the newer of the journal and the lease.
        RecorderLiveness::Unknown => [
            trace.join(RECORDER_LEASE),
            trace.join("events").join(ACTIVE_JOURNAL),
        ]
        .iter()
        .filter_map(|path| idle_time(path))
        .any(|idle| idle < RecoveryOptions::default().minimum_idle),
    };
    Some(UnfinalizedState::Abandoned { needs_force })
}

/// What the recorder lease says about the process that owns a trace. The
/// lease holds the recorder's process id and start time (see
/// [`lease_contents`]) and is rewritten every two seconds while it runs.
#[derive(Debug, PartialEq, Eq)]
pub enum RecorderLiveness {
    /// The named process is the recorder and it still exists, even if it has
    /// been suspended for a long time. For a lease without a start time: the
    /// process exists and the lease is still heartbeating.
    Alive(u32),
    /// The named process no longer exists, or its id now belongs to a
    /// process that started at a different time.
    Dead,
    /// No usable lease, or one whose process cannot be identified: its id is
    /// alive but the start time is unavailable and the heartbeat stopped long
    /// ago (the id was most likely reused by an unrelated process).
    Unknown,
}

/// What a recorder writes into its lease: `<pid> start=<start time>`, where
/// the start time is [`process_start_time`] of the recorder itself. A process
/// id alone cannot tell a suspended recorder from an unrelated process that
/// was later given the same id; the pair can. The start time is left out
/// when the platform cannot report it.
pub fn lease_contents() -> String {
    let pid = std::process::id();
    match process_start_time(pid) {
        Some(start) => format!("{pid} {LEASE_START_KEY}{start}"),
        None => pid.to_string(),
    }
}

const LEASE_START_KEY: &str = "start=";

/// The process id in a lease, and the start time when the lease records one.
/// A lease from an older recorder holds the process id alone.
fn parse_lease(text: &str) -> Option<(u32, Option<u64>)> {
    let mut fields = text.split_whitespace();
    let pid = fields.next()?.parse().ok()?;
    let start = match fields.next() {
        Some(field) => Some(field.strip_prefix(LEASE_START_KEY)?.parse().ok()?),
        None => None,
    };
    Some((pid, start))
}

pub fn recorder_liveness(trace: &Path) -> RecorderLiveness {
    let lease = trace.join(RECORDER_LEASE);
    let Some((pid, recorded_start)) = fs::read_to_string(&lease)
        .ok()
        .and_then(|text| parse_lease(&text))
    else {
        return RecorderLiveness::Unknown;
    };
    if !process_is_alive(pid) {
        return RecorderLiveness::Dead;
    }
    // The same id and the same start time is the same process, however long
    // ago it last renewed the lease (a stopped process, a sleeping laptop).
    if let Some(recorded_start) = recorded_start
        && let Some(start) = process_start_time(pid)
    {
        return if start == recorded_start {
            RecorderLiveness::Alive(pid)
        } else {
            RecorderLiveness::Dead
        };
    }
    // Without a start time to compare, a stale heartbeat is the only hint
    // that the id was reused.
    let heartbeating =
        idle_time(&lease).is_some_and(|idle| idle < RecoveryOptions::default().minimum_idle);
    if heartbeating {
        RecorderLiveness::Alive(pid)
    } else {
        RecorderLiveness::Unknown
    }
}

/// How long ago a file was last modified, when that can be determined.
fn idle_time(path: &Path) -> Option<Duration> {
    fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .ok()
        .and_then(|modified| modified.elapsed().ok())
}

/// Integrity of an unfinalized trace as the viewer API reports it: `live`
/// while the recorder runs, otherwise `abandoned` with the recover command.
/// The command names the artifact (the trace directory's own name), never
/// its location: API clients must not learn server-side paths. The CLI
/// prints the real path through [`UnfinalizedState::describe`].
pub fn unfinalized_integrity(trace: &Path, manifest: &TraceManifest) -> Option<IntegrityReport> {
    let artifact = trace.file_name().map_or(trace, Path::new);
    Some(match unfinalized_state(trace, manifest)? {
        UnfinalizedState::Recording => IntegrityReport::new(IntegrityStatus::Live, None),
        state @ UnfinalizedState::Abandoned { .. } => IntegrityReport::new(
            IntegrityStatus::Abandoned,
            Some(format!(
                "The recorder is no longer running. Run `{}` to finalize this trace.",
                state.recover_command(artifact)
            )),
        ),
    })
}

#[cfg(unix)]
fn process_is_alive(pid: u32) -> bool {
    let Ok(pid) = i32::try_from(pid) else {
        return false;
    };
    // SAFETY: signal 0 performs only the existence and permission check.
    // EPERM still means a process with this id exists.
    pid > 0
        && (unsafe { libc::kill(pid, 0) } == 0
            || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM))
}

/// Without a portable liveness probe, rely on the lease heartbeat alone.
#[cfg(not(unix))]
fn process_is_alive(_pid: u32) -> bool {
    true
}

/// When process `pid` started, as an opaque number that is stable for the
/// life of the process and differs for a later process given the same id.
/// `None` when the platform or the process's owner does not allow reading it.
///
/// Linux: field 22 (`starttime`, clock ticks since boot) of `/proc/<pid>/stat`.
#[cfg(target_os = "linux")]
pub fn process_start_time(pid: u32) -> Option<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // The command name (field 2) is parenthesized and may itself contain
    // spaces and parentheses; the fields after it are plain.
    let after_command = &stat[stat.rfind(')')? + 1..];
    after_command.split_whitespace().nth(19)?.parse().ok()
}

/// macOS: the start time `proc_pidinfo` reports, in microseconds since the epoch.
#[cfg(target_os = "macos")]
pub fn process_start_time(pid: u32) -> Option<u64> {
    let pid = i32::try_from(pid).ok()?;
    // SAFETY: proc_bsdinfo is a plain C structure; proc_pidinfo writes at
    // most `size` bytes into it and returns how many it wrote.
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = i32::try_from(std::mem::size_of::<libc::proc_bsdinfo>()).ok()?;
    let written = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            (&raw mut info).cast::<libc::c_void>(),
            size,
        )
    };
    (written == size).then(|| info.pbi_start_tvsec * 1_000_000 + info.pbi_start_tvusec)
}

/// No start time on other platforms: the lease heartbeat stays in charge.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn process_start_time(_pid: u32) -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use premier_trace::{TraceWriter, read_manifest};

    fn unfinished(root: &Path, lease: Option<String>) -> TraceManifest {
        let mut writer = TraceWriter::create(root, vec!["agent".into()]).unwrap();
        writer
            .append("session.start", "test", serde_json::json!({}))
            .unwrap();
        drop(writer);
        if let Some(lease) = lease {
            fs::write(root.join(RECORDER_LEASE), lease).unwrap();
        }
        read_manifest(root).unwrap()
    }

    #[test]
    fn a_trace_with_a_running_recorder_is_live() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("live.atrace");
        // This test process stands in for a recorder that is still running.
        let manifest = unfinished(&root, Some(std::process::id().to_string()));
        let report = unfinalized_integrity(&root, &manifest).unwrap();
        assert_eq!(report.status, IntegrityStatus::Live);
        assert!(report.detail.is_none());
    }

    #[test]
    fn a_trace_without_a_recorder_is_abandoned_and_names_recover() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("abandoned.atrace");
        let manifest = unfinished(&root, None);
        let report = unfinalized_integrity(&root, &manifest).unwrap();
        assert_eq!(report.status, IntegrityStatus::Abandoned);
        let detail = report.detail.unwrap();
        // The journal was written a moment ago, so recover still needs --force.
        assert!(
            detail.contains("`premier recover --force abandoned.atrace`"),
            "{detail}"
        );
        // API clients learn the artifact name, never where it is stored.
        assert!(
            !detail.contains(&temp.path().display().to_string()),
            "{detail}"
        );
        // The CLI keeps naming the real path.
        let state = unfinalized_state(&root, &manifest).unwrap();
        assert!(state.describe(&root).contains(&root.display().to_string()));
    }

    /// Make the lease look as if it was last renewed ten minutes ago.
    fn age_lease(root: &Path) {
        let lease = fs::File::options()
            .write(true)
            .open(root.join(RECORDER_LEASE))
            .unwrap();
        lease
            .set_modified(std::time::SystemTime::now() - Duration::from_secs(600))
            .unwrap();
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_suspended_recorder_stays_alive_however_old_its_lease_is() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("suspended.atrace");
        // This test process stands in for a recorder that stopped renewing
        // its lease (SIGSTOP, a sleeping laptop) but still exists.
        let manifest = unfinished(&root, Some(lease_contents()));
        assert!(lease_contents().contains(LEASE_START_KEY));
        age_lease(&root);
        assert_eq!(
            recorder_liveness(&root),
            RecorderLiveness::Alive(std::process::id())
        );
        assert_eq!(
            unfinalized_state(&root, &manifest),
            Some(UnfinalizedState::Recording)
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_reused_process_id_is_a_dead_recorder_even_with_a_fresh_lease() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("reused.atrace");
        // Same process id, different start time: not the recorder.
        let other_start = process_start_time(std::process::id()).unwrap() + 1;
        let lease = format!("{} {LEASE_START_KEY}{other_start}", std::process::id());
        let manifest = unfinished(&root, Some(lease));
        assert_eq!(recorder_liveness(&root), RecorderLiveness::Dead);
        // A recorder that is certainly gone needs no --force.
        assert_eq!(
            unfinalized_state(&root, &manifest),
            Some(UnfinalizedState::Abandoned { needs_force: false })
        );
    }

    #[test]
    fn a_lease_without_a_start_time_falls_back_to_the_heartbeat() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("old-format.atrace");
        unfinished(&root, Some(std::process::id().to_string()));
        assert_eq!(
            recorder_liveness(&root),
            RecorderLiveness::Alive(std::process::id())
        );
        // A live id with a heartbeat that stopped long ago may be reused.
        age_lease(&root);
        if cfg!(unix) {
            assert_eq!(recorder_liveness(&root), RecorderLiveness::Unknown);
        }
    }

    #[test]
    fn leases_parse_in_both_formats_and_reject_anything_else() {
        assert_eq!(parse_lease("42"), Some((42, None)));
        assert_eq!(parse_lease("42\n"), Some((42, None)));
        assert_eq!(parse_lease("42 start=1700"), Some((42, Some(1700))));
        assert_eq!(parse_lease("not-a-pid"), None);
        assert_eq!(parse_lease("42 start=soon"), None);
        assert_eq!(parse_lease("42 began=1700"), None);
        assert_eq!(parse_lease(""), None);
    }

    #[test]
    fn a_lease_naming_a_dead_recorder_is_abandoned() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("dead.atrace");
        let manifest = unfinished(&root, Some("not-a-pid".into()));
        assert!(matches!(
            unfinalized_state(&root, &manifest),
            Some(UnfinalizedState::Abandoned { .. })
        ));
    }

    #[test]
    fn finalized_traces_have_no_unfinalized_state() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("done.atrace");
        let manifest = TraceWriter::create(&root, vec!["agent".into()])
            .unwrap()
            .finish(0)
            .unwrap();
        assert!(unfinalized_state(&root, &manifest).is_none());
        assert!(unfinalized_integrity(&root, &manifest).is_none());
    }
}
