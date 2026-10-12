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
/// lease holds the recorder's process id and is rewritten every two seconds
/// while it runs.
pub enum RecorderLiveness {
    /// The named process exists and the lease is still heartbeating.
    Alive(u32),
    /// The named process no longer exists.
    Dead,
    /// No usable lease, or its process id is alive but the heartbeat stopped
    /// long ago (the id was most likely reused by an unrelated process).
    Unknown,
}

pub fn recorder_liveness(trace: &Path) -> RecorderLiveness {
    let lease = trace.join(RECORDER_LEASE);
    let Some(pid) = fs::read_to_string(&lease)
        .ok()
        .and_then(|text| text.trim().parse::<u32>().ok())
    else {
        return RecorderLiveness::Unknown;
    };
    if !process_is_alive(pid) {
        return RecorderLiveness::Dead;
    }
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
pub fn unfinalized_integrity(trace: &Path, manifest: &TraceManifest) -> Option<IntegrityReport> {
    Some(match unfinalized_state(trace, manifest)? {
        UnfinalizedState::Recording => IntegrityReport {
            status: IntegrityStatus::Live,
            detail: None,
        },
        state @ UnfinalizedState::Abandoned { .. } => IntegrityReport {
            status: IntegrityStatus::Abandoned,
            detail: Some(format!(
                "The recorder is no longer running. Run `{}` to finalize this trace.",
                state.recover_command(trace)
            )),
        },
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
            detail.contains(&format!("premier recover --force {}", root.display())),
            "{detail}"
        );
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
