//! `premier delete` and `premier prune`: removing trace directories.
//!
//! Both go through [`assess`], so neither removes a trace that is still
//! being recorded, anything that is not recognisably a trace directory, or
//! (without `--include-abandoned`) a trace whose recorder died before
//! finalizing it. Removal never follows a symbolic link: a link named on the
//! command line or found in the trace directory is refused, a trace that
//! contains one is not a recognisable trace, and `remove_dir_all` unlinks
//! links instead of descending into them.

use crate::issues;
use crate::liveness::{RecorderLiveness, UnfinalizedState, recorder_liveness, unfinalized_state};
use anyhow::{Result, bail};
use chrono::{DateTime, Duration, Utc};
use premier_trace::{
    ACTIVE_JOURNAL, RECORDER_LEASE, TerminationKind, TraceManifest, read_events, read_manifest,
    require_trace_directory,
};
use std::fs;
use std::path::{Path, PathBuf};

/// What is known about a trace directory that may be removed.
struct Removable {
    /// `None` when the manifest cannot be read here: an encrypted trace
    /// without its key, or one written in a later format.
    manifest: Option<TraceManifest>,
    abandoned: bool,
}

/// Whether `path` may be removed, or why not.
fn assess(path: &Path, include_abandoned: bool) -> std::result::Result<Removable, String> {
    require_trace_directory(path).map_err(|error| error.to_string())?;
    let manifest = read_manifest(path).ok();
    let state = match &manifest {
        Some(manifest) => unfinalized_state(path, manifest),
        // Without the manifest's private part, the recorder's own files say
        // whether the trace was finalized: both are removed when it is.
        None => match recorder_liveness(path) {
            RecorderLiveness::Alive(_) => Some(UnfinalizedState::Recording),
            _ if path.join(RECORDER_LEASE).exists()
                || path.join("events").join(ACTIVE_JOURNAL).exists() =>
            {
                Some(UnfinalizedState::Abandoned { needs_force: false })
            }
            _ => None,
        },
    };
    match state {
        Some(UnfinalizedState::Recording) => {
            Err("it is still being recorded; stop the recording first".into())
        }
        Some(state @ UnfinalizedState::Abandoned { .. }) if !include_abandoned => Err(format!(
            "it was abandoned by its recorder and never finalized; run `{}` to keep what it holds, or pass --include-abandoned to delete it",
            state.recover_command(path)
        )),
        state => Ok(Removable {
            manifest,
            abandoned: state.is_some(),
        }),
    }
}

/// Bytes of the files under `path`. Links are counted as themselves, never followed.
fn directory_size(path: &Path) -> u64 {
    let Ok(entries) = fs::read_dir(path) else {
        return 0;
    };
    entries
        .flatten()
        .map(|entry| match entry.file_type() {
            Ok(kind) if kind.is_dir() => directory_size(&entry.path()),
            _ => entry
                .path()
                .symlink_metadata()
                .map_or(0, |metadata| metadata.len()),
        })
        .sum()
}

fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["KiB", "MiB", "GiB", "TiB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64 / 1024.0;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

/// Removes the traces it is given and keeps count for the closing line.
struct Remover {
    dry_run: bool,
    removed: usize,
    bytes: u64,
    failed: usize,
}

impl Remover {
    fn new(dry_run: bool) -> Self {
        Self {
            dry_run,
            removed: 0,
            bytes: 0,
            failed: 0,
        }
    }

    fn refuse(&mut self, path: &Path, reason: &str) {
        self.failed += 1;
        eprintln!("premier: not removed: {}: {reason}", path.display());
    }

    /// Remove one trace that [`assess`] allowed.
    fn remove(&mut self, path: &Path, note: &str) {
        let bytes = directory_size(path);
        if !self.dry_run
            && let Err(error) = fs::remove_dir_all(path)
        {
            return self.refuse(path, &format!("{error}"));
        }
        self.removed += 1;
        self.bytes += bytes;
        println!(
            "{}  {}  ({}{note})",
            if self.dry_run {
                "would remove"
            } else {
                "removed"
            },
            path.display(),
            human_size(bytes)
        );
    }

    fn finish(self, kept: &str) -> Result<()> {
        let traces = |count: usize| format!("{count} trace{}", if count == 1 { "" } else { "s" });
        println!(
            "{} {} ({}){kept}",
            if self.dry_run {
                "would remove"
            } else {
                "removed"
            },
            traces(self.removed),
            human_size(self.bytes)
        );
        if self.failed > 0 {
            bail!("{} could not be removed", traces(self.failed));
        }
        Ok(())
    }
}

/// `premier delete <trace>...`
pub fn delete(traces: Vec<PathBuf>, include_abandoned: bool, dry_run: bool) -> Result<()> {
    let mut remover = Remover::new(dry_run);
    for path in traces {
        match assess(&path, include_abandoned) {
            Ok(removable) => remover.remove(
                &path,
                if removable.abandoned {
                    ", abandoned"
                } else {
                    ""
                },
            ),
            Err(reason) => remover.refuse(&path, &reason),
        }
    }
    remover.finish("")
}

/// A duration such as `30d`, `12h`, `45m`, `90s` or `2w`.
pub fn parse_age(value: &str) -> std::result::Result<Duration, String> {
    let invalid = || {
        format!(
            "'{value}' is not a duration: use a whole number and a unit, such as 30d, 12h, 45m, 90s, or 2w"
        )
    };
    let value = value.trim();
    let split = value
        .find(|character: char| !character.is_ascii_digit())
        .ok_or_else(invalid)?;
    let amount: i64 = value[..split].parse().map_err(|_| invalid())?;
    let seconds_per_unit = match &value[split..] {
        "s" => 1,
        "m" => 60,
        "h" => 3_600,
        "d" => 86_400,
        "w" => 604_800,
        _ => return Err(invalid()),
    };
    amount
        .checked_mul(seconds_per_unit)
        .and_then(Duration::try_seconds)
        .ok_or_else(invalid)
}

/// Whether the run failed or recorded an issue event. A trace whose events
/// cannot be read is treated as having issues: `--keep-issues` keeps it.
fn has_issues(path: &Path, manifest: &TraceManifest) -> bool {
    manifest.exit_code.is_some_and(|code| code != 0)
        || manifest.termination.as_ref().is_some_and(|termination| {
            matches!(
                termination.kind,
                TerminationKind::Signal | TerminationKind::Interrupted
            )
        })
        || read_events(path).map_or(true, |events| events.iter().any(issues::is_issue))
}

/// When an abandoned trace was last written to.
fn last_written(path: &Path) -> Option<DateTime<Utc>> {
    [
        path.join("events").join(ACTIVE_JOURNAL),
        path.join(RECORDER_LEASE),
        path.join("manifest.json"),
    ]
    .iter()
    .filter_map(|file| {
        fs::metadata(file)
            .and_then(|metadata| metadata.modified())
            .ok()
    })
    .max()
    .map(DateTime::<Utc>::from)
}

pub struct PruneOptions {
    pub trace_dir: PathBuf,
    pub older_than: Duration,
    pub dry_run: bool,
    pub keep_issues: bool,
    pub include_abandoned: bool,
}

/// `premier prune --older-than <DURATION>`
pub fn prune(options: PruneOptions) -> Result<()> {
    let PruneOptions {
        trace_dir,
        older_than,
        dry_run,
        keep_issues,
        include_abandoned,
    } = options;
    let mut remover = Remover::new(dry_run);
    if !trace_dir.exists() {
        return remover.finish(&format!("; {} does not exist", trace_dir.display()));
    }
    let cutoff = Utc::now() - older_than;
    let (mut newer, mut recording, mut abandoned, mut with_issues, mut unreadable) =
        (0, 0, 0, 0, 0);
    let mut entries = fs::read_dir(&trace_dir)?
        .collect::<std::io::Result<Vec<_>>>()?
        .into_iter()
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    entries.sort();
    for path in entries {
        // Dot-prefixed directories are working copies of `encrypt` and
        // `demo`; a directory without a manifest is not a trace; a link is
        // never followed.
        let hidden = path
            .file_name()
            .is_some_and(|name| name.as_encoded_bytes().starts_with(b"."));
        let is_directory = fs::symlink_metadata(&path).is_ok_and(|metadata| metadata.is_dir());
        if hidden || !is_directory || !path.join("manifest.json").is_file() {
            continue;
        }
        let removable = match assess(&path, true) {
            Ok(removable) => removable,
            Err(reason) if reason.contains("still being recorded") => {
                recording += 1;
                continue;
            }
            Err(reason) => {
                unreadable += 1;
                eprintln!("premier: skipped: {reason}");
                continue;
            }
        };
        if removable.abandoned && !include_abandoned {
            abandoned += 1;
            continue;
        }
        let ended = match (&removable.manifest, removable.abandoned) {
            (_, true) => last_written(&path),
            (Some(manifest), false) => Some(manifest.ended_at.unwrap_or(manifest.started_at)),
            (None, false) => None,
        };
        let Some(ended) = ended else {
            unreadable += 1;
            eprintln!(
                "premier: skipped: {}: its end time cannot be read here (encrypted without its key, or written by a newer premier)",
                path.display()
            );
            continue;
        };
        if ended > cutoff {
            newer += 1;
            continue;
        }
        if keep_issues
            && removable
                .manifest
                .as_ref()
                .is_none_or(|manifest| has_issues(&path, manifest))
        {
            with_issues += 1;
            continue;
        }
        remover.remove(
            &path,
            &format!(
                ", {}{}",
                if removable.abandoned {
                    "abandoned, last written "
                } else {
                    "ended "
                },
                ended.format("%Y-%m-%d %H:%M UTC")
            ),
        );
    }
    let kept = [
        (newer, "newer"),
        (recording, "still recording"),
        (abandoned, "abandoned (--include-abandoned removes them)"),
        (with_issues, "with issues"),
        (unreadable, "skipped"),
    ]
    .iter()
    .filter(|(count, _)| *count > 0)
    .map(|(count, label)| format!("{count} {label}"))
    .collect::<Vec<_>>();
    remover.finish(&if kept.is_empty() {
        String::new()
    } else {
        format!("; kept {}", kept.join(", "))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ages_are_a_whole_number_and_a_unit() {
        assert_eq!(parse_age("30d"), Ok(Duration::days(30)));
        assert_eq!(parse_age("12h"), Ok(Duration::hours(12)));
        assert_eq!(parse_age("45m"), Ok(Duration::minutes(45)));
        assert_eq!(parse_age("90s"), Ok(Duration::seconds(90)));
        assert_eq!(parse_age("2w"), Ok(Duration::weeks(2)));
        assert_eq!(parse_age("0d"), Ok(Duration::zero()));
        for invalid in [
            "",
            "30",
            "d",
            "1.5d",
            "-3d",
            "3 d",
            "3days",
            "99999999999999999999d",
        ] {
            assert!(parse_age(invalid).is_err(), "{invalid}");
        }
        assert!(parse_age("9223372036854775807w").is_err());
    }

    #[test]
    fn sizes_are_printed_in_binary_units() {
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(1023), "1023 B");
        assert_eq!(human_size(1536), "1.5 KiB");
        assert_eq!(human_size(5 * 1024 * 1024), "5.0 MiB");
    }
}
