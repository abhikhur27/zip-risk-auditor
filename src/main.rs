use serde::Serialize;
use std::collections::{BTreeSet, HashMap};
use std::env;
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use zip::ZipArchive;

#[derive(Debug)]
struct CliOptions {
    inputs: Vec<PathBuf>,
    json_out: Option<PathBuf>,
    markdown_out: Option<PathBuf>,
    ratio_threshold: f64,
    total_size_threshold_mb: f64,
    fail_on_risk: bool,
    top: usize,
}

#[derive(Debug, Serialize)]
struct AuditReport {
    generated_at: String,
    inputs: Vec<String>,
    ratio_threshold: f64,
    total_size_threshold_mb: f64,
    archives_scanned: usize,
    flagged_archives: usize,
    rows: Vec<ArchiveFinding>,
}

#[derive(Debug, Serialize)]
struct ArchiveFinding {
    archive_path: String,
    risk_score: u32,
    entry_count: usize,
    duplicate_paths: usize,
    traversal_entries: usize,
    absolute_path_entries: usize,
    executable_entries: usize,
    nested_archives: usize,
    max_expansion_ratio: f64,
    archive_expansion_ratio: f64,
    total_uncompressed_bytes: u64,
    total_compressed_bytes: u64,
    signals: Vec<String>,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let options = parse_args(env::args().skip(1).collect())?;
    let archives = collect_archives(&options.inputs)?;
    if archives.is_empty() {
        return Err("No .zip files were found in the selected inputs.".to_string());
    }

    let mut rows = Vec::new();
    for archive_path in &archives {
        rows.push(analyze_archive(
            archive_path,
            options.ratio_threshold,
            options.total_size_threshold_mb,
        )?);
    }

    rows.sort_by(|left, right| {
        right
            .risk_score
            .cmp(&left.risk_score)
            .then_with(|| right.max_expansion_ratio.total_cmp(&left.max_expansion_ratio))
            .then_with(|| left.archive_path.cmp(&right.archive_path))
    });

    let report = AuditReport {
        generated_at: iso_timestamp(),
        inputs: options
            .inputs
            .iter()
            .map(|path| path.display().to_string())
            .collect(),
        ratio_threshold: options.ratio_threshold,
        total_size_threshold_mb: options.total_size_threshold_mb,
        archives_scanned: rows.len(),
        flagged_archives: rows.iter().filter(|row| row.risk_score > 0).count(),
        rows,
    };

    print_console(&report, options.top);

    if let Some(path) = &options.json_out {
        write_parent_dir(path).map_err(|error| error.to_string())?;
        let payload = serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?;
        fs::write(path, payload).map_err(|error| error.to_string())?;
        println!("Wrote JSON report: {}", path.display());
    }

    if let Some(path) = &options.markdown_out {
        write_parent_dir(path).map_err(|error| error.to_string())?;
        fs::write(path, render_markdown(&report)).map_err(|error| error.to_string())?;
        println!("Wrote Markdown report: {}", path.display());
    }

    if options.fail_on_risk && report.flagged_archives > 0 {
        return Err(format!(
            "{} archive(s) crossed the configured risk checks.",
            report.flagged_archives
        ));
    }

    Ok(())
}

fn parse_args(args: Vec<String>) -> Result<CliOptions, String> {
    if args.is_empty() {
        return Err(usage());
    }

    let mut inputs = Vec::new();
    let mut json_out = None;
    let mut markdown_out = None;
    let mut ratio_threshold = 15.0;
    let mut total_size_threshold_mb = 256.0;
    let mut fail_on_risk = false;
    let mut top = 5usize;
    let mut index = 0usize;

    while index < args.len() {
        match args[index].as_str() {
            "--input" => {
                index += 1;
                let value = args.get(index).ok_or_else(usage)?;
                inputs.push(PathBuf::from(value));
            }
            "--json-out" => {
                index += 1;
                let value = args.get(index).ok_or_else(usage)?;
                json_out = Some(PathBuf::from(value));
            }
            "--markdown-out" => {
                index += 1;
                let value = args.get(index).ok_or_else(usage)?;
                markdown_out = Some(PathBuf::from(value));
            }
            "--ratio-threshold" => {
                index += 1;
                let value = args.get(index).ok_or_else(usage)?;
                ratio_threshold = value
                    .parse::<f64>()
                    .map_err(|_| "--ratio-threshold must be a number.".to_string())?;
                if ratio_threshold <= 1.0 {
                    return Err("--ratio-threshold must be greater than 1.0.".to_string());
                }
            }
            "--total-size-threshold-mb" => {
                index += 1;
                let value = args.get(index).ok_or_else(usage)?;
                total_size_threshold_mb = value
                    .parse::<f64>()
                    .map_err(|_| "--total-size-threshold-mb must be a number.".to_string())?;
                if total_size_threshold_mb <= 0.0 {
                    return Err("--total-size-threshold-mb must be greater than 0.".to_string());
                }
            }
            "--fail-on-risk" => {
                fail_on_risk = true;
            }
            "--top" => {
                index += 1;
                let value = args.get(index).ok_or_else(usage)?;
                top = value
                    .parse::<usize>()
                    .map_err(|_| "--top must be a positive integer.".to_string())?;
                if top == 0 {
                    return Err("--top must be at least 1.".to_string());
                }
            }
            "--help" | "-h" => return Err(usage()),
            unknown => return Err(format!("Unknown argument: {unknown}\n\n{}", usage())),
        }
        index += 1;
    }

    if inputs.is_empty() {
        return Err("At least one --input path is required.\n\n".to_string() + &usage());
    }

    Ok(CliOptions {
        inputs,
        json_out,
        markdown_out,
        ratio_threshold,
        total_size_threshold_mb,
        fail_on_risk,
        top,
    })
}

fn usage() -> String {
    [
        "Usage:",
        "  zip-risk-auditor --input <path> [--input <path> ...] [--json-out report.json] [--markdown-out report.md]",
        "                    [--ratio-threshold 15] [--total-size-threshold-mb 256] [--fail-on-risk] [--top 5]",
    ]
    .join("\n")
}

fn collect_archives(inputs: &[PathBuf]) -> Result<Vec<PathBuf>, String> {
    let mut archives = BTreeSet::new();
    for input in inputs {
        if input.is_file() {
            if is_zip_path(input) {
                archives.insert(input.to_path_buf());
            }
            continue;
        }
        if input.is_dir() {
            walk_dir(input, &mut archives).map_err(|error| {
                format!("Could not walk {}: {error}", input.display())
            })?;
            continue;
        }
        return Err(format!("Input path does not exist: {}", input.display()));
    }
    Ok(archives.into_iter().collect())
}

fn walk_dir(root: &Path, archives: &mut BTreeSet<PathBuf>) -> io::Result<()> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            walk_dir(&path, archives)?;
        } else if is_zip_path(&path) {
            archives.insert(path);
        }
    }
    Ok(())
}

fn is_zip_path(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.eq_ignore_ascii_case("zip"))
        .unwrap_or(false)
}

fn analyze_archive(
    path: &Path,
    ratio_threshold: f64,
    total_size_threshold_mb: f64,
) -> Result<ArchiveFinding, String> {
    let file = File::open(path).map_err(|error| format!("Could not open {}: {error}", path.display()))?;
    let mut archive = ZipArchive::new(file)
        .map_err(|error| format!("Could not read {} as a zip archive: {error}", path.display()))?;

    let mut normalized_paths = HashMap::<String, usize>::new();
    let mut traversal_entries = 0usize;
    let mut absolute_path_entries = 0usize;
    let mut executable_entries = 0usize;
    let mut nested_archives = 0usize;
    let mut max_expansion_ratio = 0.0f64;
    let mut total_uncompressed_bytes = 0u64;
    let mut total_compressed_bytes = 0u64;

    for index in 0..archive.len() {
        let entry = archive
            .by_index(index)
            .map_err(|error| format!("Could not inspect entry {index} in {}: {error}", path.display()))?;

        if entry.is_dir() {
            continue;
        }

        let name = entry.name().replace('\\', "/");
        let normalized = normalize_archive_path(&name);
        *normalized_paths.entry(normalized.clone()).or_insert(0) += 1;

        if is_traversal_entry(&normalized) {
            traversal_entries += 1;
        }
        if is_absolute_entry(&normalized) {
            absolute_path_entries += 1;
        }
        if is_executable_like(&normalized) {
            executable_entries += 1;
        }
        if is_nested_archive(&normalized) {
            nested_archives += 1;
        }

        let compressed = entry.compressed_size();
        let uncompressed = entry.size();
        total_compressed_bytes += compressed;
        total_uncompressed_bytes += uncompressed;
        let ratio = if compressed == 0 {
            if uncompressed == 0 { 1.0 } else { uncompressed as f64 }
        } else {
            uncompressed as f64 / compressed as f64
        };
        if ratio > max_expansion_ratio {
            max_expansion_ratio = ratio;
        }
    }

    let duplicate_paths = normalized_paths.values().filter(|count| **count > 1).count();
    let archive_expansion_ratio = if total_compressed_bytes == 0 {
        if total_uncompressed_bytes == 0 {
            1.0
        } else {
            total_uncompressed_bytes as f64
        }
    } else {
        total_uncompressed_bytes as f64 / total_compressed_bytes as f64
    };
    let mut signals = Vec::new();
    let mut risk_score = 0u32;

    if traversal_entries > 0 {
        signals.push(format!("{traversal_entries} traversal entry(s)"));
        risk_score += 35;
    }
    if absolute_path_entries > 0 {
        signals.push(format!("{absolute_path_entries} absolute path entry(s)"));
        risk_score += 20;
    }
    if duplicate_paths > 0 {
        signals.push(format!("{duplicate_paths} duplicate path(s)"));
        risk_score += 10;
    }
    if executable_entries > 0 {
        signals.push(format!("{executable_entries} executable/script payload(s)"));
        risk_score += 12;
    }
    if nested_archives > 0 {
        signals.push(format!("{nested_archives} nested archive(s)"));
        risk_score += 10;
    }
    if max_expansion_ratio >= ratio_threshold {
        signals.push(format!(
            "max expansion ratio {:.1}x crossed threshold {:.1}x",
            max_expansion_ratio, ratio_threshold
        ));
        risk_score += 18;
    }

    if archive_expansion_ratio >= ratio_threshold * 0.85 {
        signals.push(format!(
            "archive-wide expansion ratio {:.1}x",
            archive_expansion_ratio
        ));
        risk_score += 8;
    }

    let total_size_threshold_bytes = (total_size_threshold_mb * 1024.0 * 1024.0) as u64;
    if total_uncompressed_bytes >= total_size_threshold_bytes {
        signals.push(format!(
            "total uncompressed size {:.1} MB crossed threshold {:.1} MB",
            bytes_to_mb(total_uncompressed_bytes),
            total_size_threshold_mb
        ));
        risk_score += 12;
    }

    if signals.is_empty() {
        signals.push("no obvious extraction hazards detected".to_string());
    }

    Ok(ArchiveFinding {
        archive_path: path.display().to_string(),
        risk_score: risk_score.min(100),
        entry_count: normalized_paths.len(),
        duplicate_paths,
        traversal_entries,
        absolute_path_entries,
        executable_entries,
        nested_archives,
        max_expansion_ratio: (max_expansion_ratio * 10.0).round() / 10.0,
        archive_expansion_ratio: (archive_expansion_ratio * 10.0).round() / 10.0,
        total_uncompressed_bytes,
        total_compressed_bytes,
        signals,
    })
}

fn normalize_archive_path(path: &str) -> String {
    let mut pieces = Vec::new();
    for piece in path.split('/') {
        if piece.is_empty() || piece == "." {
            continue;
        }
        pieces.push(piece);
    }
    pieces.join("/")
}

fn is_traversal_entry(path: &str) -> bool {
    path.split('/').any(|piece| piece == "..")
}

fn is_absolute_entry(path: &str) -> bool {
    path.starts_with('/') || path.starts_with('\\') || has_windows_drive_prefix(path)
}

fn has_windows_drive_prefix(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 3 && bytes[1] == b':' && (bytes[2] == b'/' || bytes[2] == b'\\')
}

fn is_executable_like(path: &str) -> bool {
    matches!(
        extension(path).as_deref(),
        Some("exe" | "dll" | "bat" | "cmd" | "ps1" | "js" | "vbs" | "scr" | "msi" | "com")
    )
}

fn is_nested_archive(path: &str) -> bool {
    matches!(
        extension(path).as_deref(),
        Some("zip" | "jar" | "war" | "ear" | "7z" | "gz" | "tar")
    )
}

fn extension(path: &str) -> Option<String> {
    Path::new(path)
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.to_ascii_lowercase())
}

fn print_console(report: &AuditReport, top: usize) {
    println!("Zip Risk Auditor");
    println!("================");
    println!("Generated:          {}", report.generated_at);
    println!("Archives scanned:   {}", report.archives_scanned);
    println!("Flagged archives:   {}", report.flagged_archives);
    println!("Ratio threshold:    {:.1}x", report.ratio_threshold);
    println!("Size threshold:     {:.1} MB", report.total_size_threshold_mb);
    println!();

    if report.rows.is_empty() {
        println!("No archives were scanned.");
        return;
    }

    println!("{:<4} {:<4} {:<6} {:<6} Archive", "Risk", "Trav", "Dup", "Exec");
    println!("{}", "-".repeat(88));
    for row in report.rows.iter().take(top) {
        println!(
            "{:<4} {:<4} {:<6} {:<6} {}",
            row.risk_score,
            row.traversal_entries,
            row.duplicate_paths,
            row.executable_entries,
            row.archive_path
        );
        println!("  signals: {}", row.signals.join("; "));
    }
}

fn render_markdown(report: &AuditReport) -> String {
    let mut output = String::new();
    output.push_str("# Zip Risk Brief\n\n");
    output.push_str(&format!("- Generated: `{}`\n", report.generated_at));
    output.push_str(&format!("- Archives scanned: `{}`\n", report.archives_scanned));
    output.push_str(&format!("- Flagged archives: `{}`\n", report.flagged_archives));
    output.push_str(&format!("- Ratio threshold: `{:.1}x`\n", report.ratio_threshold));
    output.push_str(&format!(
        "- Total size threshold: `{:.1} MB`\n\n",
        report.total_size_threshold_mb
    ));
    output.push_str("| Archive | Risk | Traversal | Duplicate paths | Executables | Max ratio | Archive ratio |\n");
    output.push_str("| --- | ---: | ---: | ---: | ---: | ---: | ---: |\n");
    for row in &report.rows {
        output.push_str(&format!(
            "| {} | {} | {} | {} | {} | {:.1}x | {:.1}x |\n",
            escape_pipes(&row.archive_path),
            row.risk_score,
            row.traversal_entries,
            row.duplicate_paths,
            row.executable_entries,
            row.max_expansion_ratio,
            row.archive_expansion_ratio
        ));
    }
    output.push_str("\n## Findings\n\n");
    for row in &report.rows {
        output.push_str(&format!("### {}\n\n", row.archive_path));
        output.push_str(&format!("- Risk score: `{}`\n", row.risk_score));
        output.push_str(&format!("- Signals: {}\n", row.signals.join("; ")));
        output.push_str(&format!(
            "- Counts: traversal `{}`, absolute `{}`, executable/script `{}`, nested archive `{}`\n",
            row.traversal_entries,
            row.absolute_path_entries,
            row.executable_entries,
            row.nested_archives
        ));
        output.push_str(&format!(
            "- Size profile: compressed `{}` bytes, uncompressed `{}` bytes, max entry ratio `{:.1}x`, archive ratio `{:.1}x`\n\n",
            row.total_compressed_bytes,
            row.total_uncompressed_bytes,
            row.max_expansion_ratio,
            row.archive_expansion_ratio
        ));
    }
    output
}

fn escape_pipes(value: &str) -> String {
    value.replace('|', "\\|")
}

fn write_parent_dir(path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    Ok(())
}

fn iso_timestamp() -> String {
    match std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", "(Get-Date).ToString('o')"])
        .output()
    {
        Ok(output) if output.status.success() => String::from_utf8_lossy(&output.stdout).trim().to_string(),
        _ => "unknown".to_string(),
    }
}

fn bytes_to_mb(bytes: u64) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;
    use zip::CompressionMethod;
    use zip::ZipWriter;
    use zip::write::FileOptions;

    #[test]
    fn normalize_archive_path_removes_dot_segments() {
        assert_eq!(normalize_archive_path("./docs//report.txt"), "docs/report.txt");
    }

    #[test]
    fn traversal_and_absolute_entries_are_detected() {
        assert!(is_traversal_entry("../AppData/startup.bat"));
        assert!(is_absolute_entry("/Windows/System32/calc.exe"));
        assert!(is_absolute_entry("C:/Windows/System32/cmd.exe"));
    }

    #[test]
    fn executable_and_nested_archive_detection_handles_common_extensions() {
        assert!(is_executable_like("payload/run.ps1"));
        assert!(is_nested_archive("drop/vendor.jar"));
        assert!(!is_nested_archive("notes/readme.md"));
    }

    #[test]
    fn analyze_archive_flags_size_and_payload_risks() {
        let temp = tempdir().unwrap();
        let archive_path = temp.path().join("sample.zip");
        let file = File::create(&archive_path).unwrap();
        let mut writer = ZipWriter::new(file);
        let options = FileOptions::default().compression_method(CompressionMethod::Stored);

        writer.start_file("../startup.bat", options).unwrap();
        writer.write_all(&vec![b'A'; 2048]).unwrap();
        writer.start_file("nested/tool.zip", options).unwrap();
        writer.write_all(b"fake nested zip").unwrap();
        writer.finish().unwrap();

        let finding = analyze_archive(&archive_path, 2.0, 0.001).unwrap();
        assert!(finding.risk_score > 0);
        assert_eq!(finding.traversal_entries, 1);
        assert_eq!(finding.executable_entries, 1);
        assert_eq!(finding.nested_archives, 1);
        assert!(finding
            .signals
            .iter()
            .any(|signal| signal.contains("total uncompressed size")));
    }
}
