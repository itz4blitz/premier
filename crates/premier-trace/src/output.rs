//! Safe preparation of `.atrace` output directories.

use crate::{RECORDER_LEASE, TraceManifest};
use anyhow::{Result, bail};
use std::fs;
use std::path::Path;

/// Prepare `output` as a destination for a new Premier trace.
///
/// - Creates parent directories as needed.
/// - If `output` does not exist, succeeds.
/// - If `output` is recognisably an existing Premier trace directory (its
///   `manifest.json` parses as a trace manifest and it holds only trace files), replaces it.
/// - Otherwise refuses to delete or overwrite (prevents `demo --output /important` disasters).
/// - Never replaces the current directory or one of its ancestors.
pub fn prepare_trace_output(output: &Path) -> Result<()> {
    if let Some(parent) = output.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }
    // `symlink_metadata` so a link to a directory is refused rather than followed.
    let Ok(metadata) = fs::symlink_metadata(output) else {
        return Ok(());
    };
    if metadata.is_dir() {
        refuse_working_directory(output)?;
        if let Some(foreign) = first_foreign_entry(output)? {
            bail!(
                "refusing to overwrite non-trace path: {} ({foreign}; only an existing Premier .atrace may be replaced)",
                output.display()
            );
        }
        fs::remove_dir_all(output)?;
        return Ok(());
    }
    bail!(
        "refusing to overwrite non-trace path: {} (only an existing Premier .atrace with manifest.json may be replaced)",
        output.display()
    );
}

/// `remove_dir_all` on the working directory (or a parent of it) would empty
/// the user's project before failing on the final `rmdir`.
fn refuse_working_directory(output: &Path) -> Result<()> {
    if let Ok(current) = std::env::current_dir()
        && contains_directory(output, &current)?
    {
        bail!(
            "refusing to overwrite {}: it is the current directory or one of its ancestors",
            output.display()
        );
    }
    Ok(())
}

fn contains_directory(target: &Path, directory: &Path) -> Result<bool> {
    let target = fs::canonicalize(target)?;
    Ok(fs::canonicalize(directory)
        .unwrap_or_else(|_| directory.to_path_buf())
        .starts_with(target))
}

/// Describe the first thing in `root` that a Premier recorder would not have
/// written, or `None` when the directory is recognisably a trace.
fn first_foreign_entry(root: &Path) -> Result<Option<String>> {
    let manifest = fs::read(root.join("manifest.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<TraceManifest>(&bytes).ok());
    if !manifest.is_some_and(|manifest| !manifest.trace_id.trim().is_empty()) {
        return Ok(Some(
            "manifest.json is missing or is not a Premier trace manifest".into(),
        ));
    }
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let file_type = entry.file_type()?;
        let expected = if file_type.is_dir() {
            match name.as_ref() {
                "events" => only_journal_files(&entry.path())?,
                "blobs" | "indexes" => true,
                _ => false,
            }
        } else {
            file_type.is_file()
                && matches!(
                    name.as_ref(),
                    "manifest.json" | "manifest.json.tmp" | RECORDER_LEASE
                )
        };
        if !expected {
            return Ok(Some(format!("unexpected entry `{name}`")));
        }
    }
    Ok(None)
}

fn only_journal_files(events: &Path) -> Result<bool> {
    for entry in fs::read_dir(events)? {
        let entry = entry?;
        if !entry.file_type()?.is_file()
            || !entry.file_name().to_string_lossy().contains(".events.pb")
        {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;

    #[test]
    fn creates_parent_when_missing() {
        let temp = tempfile::tempdir().unwrap();
        let output = temp.path().join("nested").join("run.atrace");
        prepare_trace_output(&output).unwrap();
        assert!(output.parent().unwrap().is_dir());
        assert!(!output.exists());
    }

    #[test]
    fn replaces_existing_trace_directory() {
        let temp = tempfile::tempdir().unwrap();
        let output = temp.path().join("old.atrace");
        crate::TraceWriter::create(&output, vec!["agent".into()])
            .unwrap()
            .finish(0)
            .unwrap();
        prepare_trace_output(&output).unwrap();
        assert!(!output.exists());
    }

    #[test]
    fn replaces_a_live_trace_directory() {
        let temp = tempfile::tempdir().unwrap();
        let output = temp.path().join("live.atrace");
        drop(crate::TraceWriter::create(&output, vec!["agent".into()]).unwrap());
        fs::write(output.join(crate::RECORDER_LEASE), "lease").unwrap();
        prepare_trace_output(&output).unwrap();
        assert!(!output.exists());
    }

    #[test]
    fn refuses_a_foreign_project_that_merely_has_a_manifest_json() {
        let temp = tempfile::tempdir().unwrap();
        let extension = temp.path().join("my-extension");
        fs::create_dir_all(extension.join("src")).unwrap();
        fs::write(
            extension.join("manifest.json"),
            br#"{"manifest_version":3,"name":"My extension"}"#,
        )
        .unwrap();
        fs::write(extension.join("src").join("main.js"), "keep me").unwrap();
        let error = prepare_trace_output(&extension).unwrap_err().to_string();
        assert!(error.contains("refusing to overwrite"), "{error}");
        assert!(extension.join("src").join("main.js").exists());
    }

    #[test]
    fn refuses_a_trace_directory_that_also_holds_foreign_files() {
        let temp = tempfile::tempdir().unwrap();
        let output = temp.path().join("mixed.atrace");
        crate::TraceWriter::create(&output, vec!["agent".into()])
            .unwrap()
            .finish(0)
            .unwrap();
        fs::write(output.join("notes.txt"), "keep me").unwrap();
        let error = prepare_trace_output(&output).unwrap_err().to_string();
        assert!(error.contains("notes.txt"), "{error}");
        assert!(output.join("notes.txt").exists());
        fs::remove_file(output.join("notes.txt")).unwrap();
        fs::write(output.join("events").join("keep-me"), "keep me").unwrap();
        assert!(prepare_trace_output(&output).is_err());
        assert!(output.join("events").join("keep-me").exists());
    }

    #[test]
    fn refuses_the_current_directory_and_its_ancestors() {
        // Another test changes the process cwd, so check the containment rule
        // against an explicit directory instead of the ambient one.
        let temp = tempfile::tempdir().unwrap();
        let current = temp.path().join("project").join("src");
        fs::create_dir_all(&current).unwrap();
        fs::create_dir_all(temp.path().join("sibling.atrace")).unwrap();
        assert!(contains_directory(&current, &current).unwrap());
        assert!(contains_directory(&temp.path().join("project"), &current).unwrap());
        assert!(contains_directory(&current.join(".."), &current).unwrap());
        assert!(!contains_directory(&temp.path().join("sibling.atrace"), &current).unwrap());
    }

    #[test]
    fn refuses_to_delete_arbitrary_directory() {
        let temp = tempfile::tempdir().unwrap();
        let precious = temp.path().join("user-data");
        fs::create_dir_all(&precious).unwrap();
        File::create(precious.join("important.txt"))
            .unwrap()
            .write_all(b"keep me")
            .unwrap();
        let error = prepare_trace_output(&precious).unwrap_err().to_string();
        assert!(error.contains("refusing to overwrite"), "{error}");
        assert!(precious.join("important.txt").exists());
    }

    #[test]
    fn refuses_to_overwrite_a_plain_file() {
        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join("notes.txt");
        fs::write(&file, "notes").unwrap();
        let error = prepare_trace_output(&file).unwrap_err().to_string();
        assert!(error.contains("refusing to overwrite"), "{error}");
        assert_eq!(fs::read_to_string(&file).unwrap(), "notes");
    }

    #[test]
    fn accepts_a_relative_filename_with_an_empty_parent() {
        let temp = tempfile::tempdir().unwrap();
        let previous = std::env::current_dir().unwrap();
        std::env::set_current_dir(temp.path()).unwrap();
        let result = prepare_trace_output(Path::new("local.atrace"));
        std::env::set_current_dir(previous).unwrap();
        result.unwrap();
        assert!(!temp.path().join("local.atrace").exists());
    }

    #[test]
    fn refuses_directory_without_manifest() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("almost-trace");
        fs::create_dir_all(dir.join("events")).unwrap();
        let error = prepare_trace_output(&dir).unwrap_err().to_string();
        assert!(error.contains("refusing to overwrite"), "{error}");
        assert!(dir.join("events").exists());
    }
}
