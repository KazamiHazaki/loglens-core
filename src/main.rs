// loglens-core/src/main.rs
// LogLens CLI - Single binary log analysis tool powered by loglens-core engine

use clap::{Parser, Subcommand, ValueEnum};
use colored::*;
use flate2::read::GzDecoder;
use loglens_core::parsers::parse_log_line;
use loglens_core::query::evaluate;
use loglens_core::LogEntry;
use rayon::prelude::*;
use serde_json::Value;
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

// ────────────────────────────────────────────────────────────
// CLI Definition
// ────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "loglens",
    version = "0.1.2",
    about = "🔍 LogLens - Blazing fast structured log analysis CLI",
    long_about = "A lightning-fast command-line tool for log analysis.\n\
                  Search, query, and analyze structured logs (JSON, Nginx, Logfmt)\n\
                  at scale. Built in Rust for maximum performance."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Search log files using text or structured queries
    Search {
        /// Search query (text or structured: `level == "error" && latency > 500`)
        query: String,
        /// Files or directories to search
        #[arg(required = true)]
        files: Vec<PathBuf>,
        /// Show N lines of context after each match
        #[arg(short = 'A', long, default_value_t = 0)]
        after: usize,
        /// Show N lines of context before each match
        #[arg(short = 'B', long, default_value_t = 0)]
        before: usize,
        /// Show N lines of context before and after each match
        #[arg(short = 'C', long, default_value_t = 0)]
        context: usize,
        /// Maximum number of results per file
        #[arg(short = 'n', long)]
        max_results: Option<usize>,
        /// Time filter: show only entries since (e.g., "1h", "30m", "2d ago")
        #[arg(long)]
        since: Option<String>,
        /// Output format
        #[arg(short = 'o', long, default_value = "text")]
        output: OutputFormat,
        /// Search recursively in directories
        #[arg(short = 'r', long)]
        recursive: bool,
        /// Case-insensitive search
        #[arg(short = 'i', long)]
        ignore_case: bool,
        /// Show statistics after results
        #[arg(long)]
        stats: bool,
        /// Suppress file headers (one match per line)
        #[arg(long)]
        compact: bool,
        /// Exclude files matching pattern
        #[arg(long)]
        exclude: Vec<String>,
    },
    /// Run a structured query against log files
    Query {
        /// Structured query expression
        query: String,
        /// Files or directories to query
        #[arg(required = true)]
        files: Vec<PathBuf>,
        /// Time filter
        #[arg(long)]
        since: Option<String>,
        /// Maximum results per file
        #[arg(short = 'n', long)]
        max_results: Option<usize>,
        /// Search recursively
        #[arg(short = 'r', long)]
        recursive: bool,
        /// Output format
        #[arg(short = 'o', long, default_value = "text")]
        output: OutputFormat,
        /// Show statistics
        #[arg(long)]
        stats: bool,
    },
    /// Watch log files in real-time with filtering
    Watch {
        /// Files to watch
        #[arg(required = true)]
        files: Vec<PathBuf>,
        /// Filter query (text or structured)
        #[arg(short = 'q', long)]
        query: Option<String>,
        /// Highlight matching terms
        #[arg(long)]
        highlight: bool,
        /// Show N context lines before match
        #[arg(short = 'B', long, default_value_t = 0)]
        before: usize,
    },
    /// Discover fields/schema in log files
    Fields {
        /// Log file to analyze
        file: PathBuf,
        /// Number of lines to sample (0 = all)
        #[arg(short = 'n', long, default_value_t = 1000)]
        sample: usize,
    },
    /// Count matches in log files
    Count {
        /// Search query
        query: String,
        /// Files or directories to search
        #[arg(required = true)]
        files: Vec<PathBuf>,
        /// Search recursively
        #[arg(short = 'r', long)]
        recursive: bool,
        /// Time filter
        #[arg(long)]
        since: Option<String>,
    },
    /// Compress log files using gzip
    Compress {
        /// Files to compress
        #[arg(required = true)]
        files: Vec<PathBuf>,
        /// Remove original file after compression
        #[arg(long)]
        remove_original: bool,
    },
}

#[derive(Clone, ValueEnum)]
enum OutputFormat {
    /// Human-readable colored text
    Text,
    /// JSON output (one object per match)
    Json,
    /// Raw line output (no formatting)
    Raw,
}

// ────────────────────────────────────────────────────────────
// File Discovery
// ────────────────────────────────────────────────────────────

fn discover_files(paths: &[PathBuf], recursive: bool, excludes: &[String]) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for path in paths {
        if path.is_file() {
            files.push(path.clone());
        } else if path.is_dir() {
            if recursive {
                collect_files_recursive(path, &mut files);
            } else {
                if let Ok(entries) = std::fs::read_dir(path) {
                    for entry in entries.flatten() {
                        let p = entry.path();
                        if p.is_file() && is_log_file(&p) {
                            files.push(p);
                        }
                    }
                }
            }
        } else if let Some(pattern) = path.to_str() {
            // Try glob pattern
            if let Ok(entries) = glob::glob(pattern) {
                for entry in entries.flatten() {
                    if entry.is_file() {
                        files.push(entry);
                    }
                }
            }
        }
    }

    // Apply exclusions
    if !excludes.is_empty() {
        files.retain(|f| {
            let fname = f.to_string_lossy().to_lowercase();
            !excludes.iter().any(|ex| fname.contains(&ex.to_lowercase()))
        });
    }

    files.sort();
    files
}

fn collect_files_recursive(dir: &PathBuf, files: &mut Vec<PathBuf>) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        let mut sorted_entries: Vec<_> = entries.flatten().collect();
        sorted_entries.sort_by_key(|e| e.path());
        for entry in sorted_entries {
            let p = entry.path();
            if p.is_dir() {
                collect_files_recursive(&p, files);
            } else if p.is_file() {
                files.push(p);
            }
        }
    }
}

fn is_log_file(path: &PathBuf) -> bool {
    let name = path.to_string_lossy().to_lowercase();
    name.ends_with(".log")
        || name.ends_with(".json")
        || name.ends_with(".ndjson")
        || name.ends_with(".jsonl")
        || name.ends_with(".log.gz")
        || name.ends_with(".gz")
        || name.ends_with(".txt")
        || name.ends_with(".out")
        || name.ends_with(".err")
}

// ────────────────────────────────────────────────────────────
// File Reading
// ────────────────────────────────────────────────────────────

fn open_log_reader(path: &PathBuf) -> io::Result<Box<dyn BufRead>> {
    let file = File::open(path)?;
    let name = path.to_string_lossy();
    if name.ends_with(".gz") {
        let decoder = GzDecoder::new(file);
        Ok(Box::new(BufReader::new(decoder)))
    } else {
        Ok(Box::new(BufReader::new(file)))
    }
}

// ────────────────────────────────────────────────────────────
// Search Engine
// ────────────────────────────────────────────────────────────

struct SearchResult {
    file: PathBuf,
    line_num: usize,
    raw_line: String,
    parsed: Option<Value>,
    is_match: bool,
    is_context: bool,
}

struct FileStats {
    total_lines: usize,
    matched_lines: usize,
    level_counts: HashMap<String, usize>,
}

fn search_file(
    path: &PathBuf,
    query: &str,
    before: usize,
    after: usize,
    max_results: Option<usize>,
    since_filter: Option<&str>,
) -> (Vec<SearchResult>, FileStats) {
    let mut results = Vec::new();
    let mut stats = FileStats {
        total_lines: 0,
        matched_lines: 0,
        level_counts: HashMap::new(),
    };

    let reader = match open_log_reader(path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!(
                "{} {}: {}",
                "⚠ Error:".yellow().bold(),
                path.display(),
                e
            );
            return (results, stats);
        }
    };

    let mut line_buffer: Vec<(usize, String, Option<Value>, bool)> = Vec::new();
    let mut after_count: usize = 0;
    let mut match_count: usize = 0;

    for (line_idx, line_result) in reader.lines().enumerate() {
        let line_num = line_idx + 1;
        stats.total_lines += 1;

        let raw_line = match line_result {
            Ok(l) => l,
            Err(_) => continue,
        };

        // Parse the line
        let (parsed_value, raw_for_eval) = match parse_log_line(&raw_line) {
            LogEntry::Structured(v) => (Some(v.clone()), Some(v)),
            LogEntry::Unstructured(_s) => (None, None),
        };

        // Track log levels for stats
        if let Some(ref val) = parsed_value {
            if let Some(level) = val.get("level").and_then(|v| v.as_str()) {
                *stats.level_counts.entry(level.to_string()).or_insert(0) += 1;
            } else if let Some(level) = val.get("severity").and_then(|v| v.as_str()) {
                *stats.level_counts.entry(level.to_string()).or_insert(0) += 1;
            }
        }

        // Check if we're in after-context mode
        if after_count > 0 {
            after_count -= 1;
            results.push(SearchResult {
                file: path.clone(),
                line_num,
                raw_line: raw_line.clone(),
                parsed: parsed_value.clone(),
                is_match: false,
                is_context: true,
            });
            line_buffer.push((line_num, raw_line, parsed_value.clone(), true));
            if line_buffer.len() > before {
                line_buffer.remove(0);
            }
            continue;
        }

        // Evaluate query
        let matches = if let Some(ref val) = raw_for_eval {
            match evaluate(val, &raw_line, query) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("{} {}", "⚠ Query error:".yellow(), e);
                    false
                }
            }
        } else {
            // Fallback: text search on raw line
            let q_lower = query.to_lowercase();
            raw_line.to_lowercase().contains(&q_lower)
        };

        // Apply since filter
        let time_matches = if let Some(since_str) = since_filter {
            if let Some(ref val) = raw_for_eval {
                if let Ok(since_time) =
                    loglens_core::time::parse_time_string(since_str)
                {
                    if let Some(log_time) =
                        loglens_core::time::extract_and_parse_timestamp(val)
                    {
                        log_time >= since_time
                    } else {
                        true // No timestamp = include
                    }
                } else {
                    true
                }
            } else {
                true
            }
        } else {
            true
        };

        let final_match = matches && time_matches;

        if final_match {
            match_count += 1;
            stats.matched_lines += 1;

            // Add before-context
            if before > 0 {
                for (ctx_num, ctx_line, ctx_parsed, _) in &line_buffer {
                    results.push(SearchResult {
                        file: path.clone(),
                        line_num: *ctx_num,
                        raw_line: ctx_line.clone(),
                        parsed: ctx_parsed.clone(),
                        is_match: false,
                        is_context: true,
                    });
                }
            }

            // Add the match
            results.push(SearchResult {
                file: path.clone(),
                line_num,
                raw_line: raw_line.clone(),
                parsed: parsed_value.clone(),
                is_match: true,
                is_context: false,
            });

            // Start after-context
            after_count = after;

            if let Some(max) = max_results {
                if match_count >= max {
                    break;
                }
            }
        }

        // Update before-context buffer
        line_buffer.push((line_num, raw_line, parsed_value, false));
        if line_buffer.len() > before {
            line_buffer.remove(0);
        }
    }

    (results, stats)
}

// ────────────────────────────────────────────────────────────
// Output Formatting
// ────────────────────────────────────────────────────────────

fn format_result_text(result: &SearchResult, show_file: bool) -> String {
    let mut parts = Vec::new();

    if result.is_context {
        let prefix = format!("{}", "─".dimmed());
        if show_file {
            parts.push(format!(
                "{}{}",
                prefix,
                result.file.display().to_string().dimmed()
            ));
        }
        parts.push(format!(
            "{}{:>6}{}",
            prefix,
            format!("{}", result.line_num).dimmed(),
            format!(" {}", result.raw_line).dimmed()
        ));
        return parts.join("\n");
    }

    if show_file {
        parts.push(format!(
            "{}:{}",
            result.file.display().to_string().cyan(),
            format!("{}", result.line_num).yellow()
        ));
    }

    // Colorize based on log level
    let line = &result.raw_line;
    let colored = if let Some(ref val) = result.parsed {
        let level = val
            .get("level")
            .or_else(|| val.get("severity"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_lowercase();

        match level.as_str() {
            "fatal" | "critical" | "emerg" | "emergency" => {
                format!("{}", line.on_red().white().bold())
            }
            "error" | "err" => format!("{}", line.red()),
            "warn" | "warning" => format!("{}", line.yellow()),
            "info" => format!("{}", line.green()),
            "debug" | "trace" => format!("{}", line.dimmed()),
            _ => line.clone(),
        }
    } else {
        // Unstructured: try to detect level in raw text
        let upper = line.to_uppercase();
        if upper.contains("FATAL") || upper.contains("CRITICAL") || upper.contains("EMERGENCY") {
            format!("{}", line.on_red().white().bold())
        } else if upper.contains("ERROR") {
            format!("{}", line.red())
        } else if upper.contains("WARN") {
            format!("{}", line.yellow())
        } else if upper.contains("INFO") {
            format!("{}", line.green())
        } else if upper.contains("DEBUG") || upper.contains("TRACE") {
            format!("{}", line.dimmed())
        } else {
            line.clone()
        }
    };

    if show_file {
        format!("{}:{}", parts.join(" "), colored)
    } else {
        format!("{}: {}", format!("{}", result.line_num).yellow(), colored)
    }
}

fn format_result_json(result: &SearchResult) -> String {
    if let Some(ref val) = result.parsed {
        serde_json::to_string(val).unwrap_or_else(|_| result.raw_line.clone())
    } else {
        // Wrap unstructured in JSON
        let wrapper = serde_json::json!({
            "file": result.file.display().to_string(),
            "line": result.line_num,
            "text": result.raw_line,
        });
        serde_json::to_string(&wrapper).unwrap_or_else(|_| result.raw_line.clone())
    }
}

fn print_results(
    results: &[SearchResult],
    format: &OutputFormat,
    compact: bool,
    show_file: bool,
) {
    let stdout = io::stdout();
    let mut out = stdout.lock();

    let mut last_file: Option<&PathBuf> = None;

    for result in results {
        if !compact && show_file {
            if last_file.map_or(true, |f| f != &result.file) {
                if last_file.is_some() {
                    let _ = writeln!(out);
                }
                let _ = writeln!(
                    out,
                    "{}",
                    format!("══ {} ══", result.file.display())
                        .blue()
                        .bold()
                );
                last_file = Some(&result.file);
            }
        }

        match format {
            OutputFormat::Text => {
                let _ = writeln!(out, "{}", format_result_text(result, show_file && !compact));
            }
            OutputFormat::Json => {
                let _ = writeln!(out, "{}", format_result_json(result));
            }
            OutputFormat::Raw => {
                let _ = writeln!(out, "{}", result.raw_line);
            }
        }
    }
}

// ────────────────────────────────────────────────────────────
// Statistics
// ────────────────────────────────────────────────────────────

fn print_stats(
    file_stats: &[(PathBuf, FileStats)],
    elapsed: std::time::Duration,
    total_matches: usize,
) {
    let total_files = file_stats.len();
    let total_lines: usize = file_stats.iter().map(|(_, s)| s.total_lines).sum();

    eprintln!();
    eprintln!("{}", "─".repeat(55).dimmed());
    eprintln!("{}", "📊 Search Statistics".bold());
    eprintln!("  {} {}", "Files:".dimmed(), total_files);
    eprintln!("  {} {}", "Lines scanned:".dimmed(), total_lines);
    eprintln!(
        "  {} {}",
        "Matches:".dimmed(),
        format!("{}", total_matches).bold()
    );
    eprintln!(
        "  {} {:.3}s",
        "Elapsed:".dimmed(),
        elapsed.as_secs_f64()
    );

    if total_lines > 0 {
        let throughput = total_lines as f64 / elapsed.as_secs_f64();
        eprintln!(
            "  {} {:.0} lines/sec",
            "Speed:".dimmed(),
            throughput
        );
    }

    // Aggregate level counts
    let mut all_levels: HashMap<String, usize> = HashMap::new();
    for (_, stats) in file_stats {
        for (level, count) in &stats.level_counts {
            *all_levels.entry(level.clone()).or_insert(0) += count;
        }
    }

    if !all_levels.is_empty() {
        eprintln!();
        eprintln!("  {}", "Log Level Distribution:".bold());
        let mut levels: Vec<_> = all_levels.into_iter().collect();
        levels.sort_by(|a, b| b.1.cmp(&a.1));
        for (level, count) in levels {
            let colored = match level.to_lowercase().as_str() {
                "fatal" | "critical" => format!("{}", format!(" {:<10} {}", level, count).on_red().white()),
                "error" => format!("{}", format!(" {:<10} {}", level, count).red()),
                "warn" | "warning" => format!("{}", format!(" {:<10} {}", level, count).yellow()),
                "info" => format!("{}", format!(" {:<10} {}", level, count).green()),
                "debug" | "trace" => format!("{}", format!(" {:<10} {}", level, count).dimmed()),
                _ => format!(" {:<10} {}", level, count),
            };
            eprintln!("  {}", colored);
        }
    }

    // Top files by match count
    let mut by_matches: Vec<_> = file_stats.iter().collect();
    by_matches.sort_by(|a, b| b.1.matched_lines.cmp(&a.1.matched_lines));
    let top_files: Vec<_> = by_matches.iter().take(5).filter(|(_, s)| s.matched_lines > 0).collect();

    if !top_files.is_empty() {
        eprintln!();
        eprintln!("  {}", "Top Files:".bold());
        for (path, stats) in top_files {
            eprintln!(
                "    {}: {}",
                path.file_name().unwrap_or_default().to_string_lossy(),
                stats.matched_lines
            );
        }
    }

    eprintln!("{}", "─".repeat(55).dimmed());
}

// ────────────────────────────────────────────────────────────
// Watch / Tail
// ────────────────────────────────────────────────────────────

fn watch_files(files: &[PathBuf], query: Option<&str>, before: usize) {
    eprintln!(
        "{}",
        format!(
            "👁 Watching {} file(s)... Press Ctrl+C to stop.",
            files.len()
        )
        .green()
        .bold()
    );

    let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .ok();

    let stdout = io::stdout();
    let mut out = stdout.lock();

    // Track file positions
    let mut positions: HashMap<PathBuf, u64> = HashMap::new();
    let mut buffers: HashMap<PathBuf, Vec<String>> = HashMap::new();

    // Initialize: seek to end of each file
    for file in files {
        if let Ok(metadata) = std::fs::metadata(file) {
            positions.insert(file.clone(), metadata.len());
        } else {
            positions.insert(file.clone(), 0);
        }
        buffers.insert(file.clone(), Vec::new());
    }

    while running.load(Ordering::SeqCst) {
        for file in files {
            let pos = positions.get(file).copied().unwrap_or(0);
            if let Ok(f) = File::open(file) {
                if let Ok(metadata) = f.metadata() {
                    let current_len = metadata.len();
                    if current_len > pos {
                        use std::io::Seek;
                        let mut seekable = BufReader::new(File::open(file).unwrap());
                        seekable.seek(io::SeekFrom::Start(pos)).ok();

                        let mut line = String::new();
                        while seekable.read_line(&mut line).unwrap_or(0) > 0 {
                            let trimmed = line.trim_end();
                            if !trimmed.is_empty() {
                                let matches = if let Some(q) = query {
                                    match parse_log_line(trimmed) {
                                        LogEntry::Structured(val) => {
                                            evaluate(&val, trimmed, q).unwrap_or(false)
                                        }
                                        LogEntry::Unstructured(_) => {
                                            trimmed.to_lowercase().contains(&q.to_lowercase())
                                        }
                                    }
                                } else {
                                    true
                                };

                                let buf = buffers.get_mut(file).unwrap();
                                if matches {
                                    // Print context before
                                    let ctx_start = buf.len().saturating_sub(before);
                                    for ctx_line in &buf[ctx_start..] {
                                        let _ = writeln!(
                                            out,
                                            "{} {} {}",
                                            format!("[{}]", file.display()).cyan().dimmed(),
                                            "│".dimmed(),
                                            ctx_line.dimmed()
                                        );
                                    }
                                    // Print match
                                    let _ = writeln!(
                                        out,
                                        "{} {} {}",
                                        format!("[{}]", file.display()).cyan(),
                                        "▶".green(),
                                        trimmed
                                    );
                                    let _ = out.flush();
                                }

                                buf.push(trimmed.to_string());
                                if buf.len() > 100 {
                                    buf.remove(0);
                                }
                            }
                            line.clear();
                        }
                        positions.insert(file.clone(), current_len);
                    }
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    eprintln!("\n{}", "Stopped.".yellow());
}

// ────────────────────────────────────────────────────────────
// Fields Discovery
// ────────────────────────────────────────────────────────────

fn discover_fields(file: &PathBuf, sample_size: usize) {
    let reader = match open_log_reader(file) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{} {}", "Error:".red().bold(), e);
            return;
        }
    };

    let mut field_types: HashMap<String, HashMap<String, usize>> = HashMap::new();
    let mut total_parsed = 0usize;
    let mut total_lines = 0usize;

    eprintln!(
        "{}",
        format!("🔬 Analyzing fields in {}...", file.display()).dimmed()
    );

    for line_result in reader.lines() {
        total_lines += 1;
        if sample_size > 0 && total_lines > sample_size {
            break;
        }

        let line = match line_result {
            Ok(l) => l,
            Err(_) => continue,
        };

        if let LogEntry::Structured(val) = parse_log_line(&line) {
            total_parsed += 1;
            if let Some(obj) = val.as_object() {
                for (key, value) in obj {
                    let type_name = match value {
                        Value::String(_) => "string",
                        Value::Number(_) => "number",
                        Value::Bool(_) => "boolean",
                        Value::Array(_) => "array",
                        Value::Object(_) => "object",
                        Value::Null => "null",
                    };
                    field_types
                        .entry(key.clone())
                        .or_default()
                        .entry(type_name.to_string())
                        .and_modify(|c| *c += 1)
                        .or_insert(1);
                }
            }
        }
    }

    eprintln!();
    eprintln!(
        "{} {} lines read, {} structured entries parsed",
        "📊".bold(),
        total_lines,
        total_parsed
    );
    eprintln!();

    if field_types.is_empty() {
        eprintln!("{}", "No structured fields found.".yellow());
        return;
    }

    // Sort fields by frequency
    let mut fields: Vec<_> = field_types.into_iter().collect();
    fields.sort_by(|a, b| {
        let a_total: usize = a.1.values().sum();
        let b_total: usize = b.1.values().sum();
        b_total.cmp(&a_total)
    });

    eprintln!("{}", "  Field                    Type(s)                        Count".bold());
    eprintln!("{}", "  ────────────────────────────────────────────────────────────────".dimmed());

    for (field, types) in &fields {
        let total: usize = types.values().sum();
        let type_str: Vec<String> = types
            .iter()
            .map(|(t, c)| {
                if *c == total {
                    t.clone()
                } else {
                    format!("{}({})", t, c)
                }
            })
            .collect();

        let coverage = if total_parsed > 0 {
            (total as f64 / total_parsed as f64 * 100.0) as usize
        } else {
            0
        };

        eprintln!(
            "  {:<26} {:<30} {} ({}%)",
            field.cyan(),
            type_str.join(", "),
            total,
            coverage
        );
    }
}

// ────────────────────────────────────────────────────────────
// Compress
// ────────────────────────────────────────────────────────────

fn compress_files(files: &[PathBuf], remove_original: bool) {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Read;

    for file in files {
        let output_path = PathBuf::from(format!("{}.gz", file.display()));
        eprint!("  Compressing {} -> {} ... ", file.display(), output_path.display());

        match File::open(file) {
            Ok(mut input) => {
                let output = match File::create(&output_path) {
                    Ok(f) => f,
                    Err(e) => {
                        eprintln!("{}", format!("ERROR: {}", e).red());
                        continue;
                    }
                };

                let mut encoder = GzEncoder::new(output, Compression::best());
                match io::copy(&mut input, &mut encoder) {
                    Ok(_) => {
                        encoder.finish().ok();
                        if remove_original {
                            std::fs::remove_file(file).ok();
                        }
                        eprintln!("{}", "✓".green());
                    }
                    Err(e) => eprintln!("{}", format!("ERROR: {}", e).red()),
                }
            }
            Err(e) => eprintln!("{}", format!("ERROR: {}", e).red()),
        }
    }
}

// ────────────────────────────────────────────────────────────
// Main
// ────────────────────────────────────────────────────────────

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Search {
            query,
            files,
            after,
            before,
            context,
            max_results,
            since,
            output,
            recursive,
            ignore_case: _,
            stats,
            compact,
            exclude,
        } => {
            let before = if context > 0 { context } else { before };
            let after = if context > 0 { context } else { after };

            let discovered = discover_files(&files, recursive, &exclude);
            if discovered.is_empty() {
                eprintln!("{}", "No files found.".yellow());
                std::process::exit(1);
            }

            eprintln!(
                "{}",
                format!("🔍 Searching {} file(s)...", discovered.len()).dimmed()
            );

            let start = Instant::now();
            let since_ref = since.as_deref();

            // Parallel search
            let all_results: Vec<(PathBuf, Vec<SearchResult>, FileStats)> = discovered
                .par_iter()
                .map(|file| {
                    let (results, file_stats) = search_file(
                        file,
                        &query,
                        before,
                        after,
                        max_results,
                        since_ref,
                    );
                    (file.clone(), results, file_stats)
                })
                .collect();

            let elapsed = start.elapsed();

            // Flatten results
            let mut flat_results: Vec<SearchResult> = Vec::new();
            let mut file_stats_vec: Vec<(PathBuf, FileStats)> = Vec::new();
            let mut total_matches = 0usize;

            for (path, results, fstats) in all_results {
                total_matches += fstats.matched_lines;
                file_stats_vec.push((path, fstats));
                flat_results.extend(results);
            }

            // Print
            print_results(&flat_results, &output, compact, file_stats_vec.len() > 1);

            if stats {
                print_stats(&file_stats_vec, elapsed, total_matches);
            }

            if total_matches == 0 {
                std::process::exit(1);
            }
        }

        Commands::Query {
            query,
            files,
            since,
            max_results,
            recursive,
            output,
            stats,
        } => {
            let discovered = discover_files(&files, recursive, &[]);
            if discovered.is_empty() {
                eprintln!("{}", "No files found.".yellow());
                std::process::exit(1);
            }

            eprintln!(
                "{}",
                format!(
                    "🔍 Querying {} file(s) with: {}",
                    discovered.len(),
                    query.cyan()
                )
                .dimmed()
            );

            let start = Instant::now();
            let since_ref = since.as_deref();

            let all_results: Vec<(PathBuf, Vec<SearchResult>, FileStats)> = discovered
                .par_iter()
                .map(|file| {
                    let (results, file_stats) =
                        search_file(file, &query, 0, 0, max_results, since_ref);
                    (file.clone(), results, file_stats)
                })
                .collect();

            let elapsed = start.elapsed();

            let mut flat_results: Vec<SearchResult> = Vec::new();
            let mut file_stats_vec: Vec<(PathBuf, FileStats)> = Vec::new();
            let mut total_matches = 0usize;

            for (path, results, fstats) in all_results {
                total_matches += fstats.matched_lines;
                file_stats_vec.push((path, fstats));
                flat_results.extend(results);
            }

            print_results(&flat_results, &output, false, file_stats_vec.len() > 1);

            if stats {
                print_stats(&file_stats_vec, elapsed, total_matches);
            }

            if total_matches == 0 {
                std::process::exit(1);
            }
        }

        Commands::Watch {
            files,
            query,
            highlight: _,
            before,
        } => {
            watch_files(&files, query.as_deref(), before);
        }

        Commands::Fields { file, sample } => {
            discover_fields(&file, sample);
        }

        Commands::Count {
            query,
            files,
            recursive,
            since,
        } => {
            let discovered = discover_files(&files, recursive, &[]);
            if discovered.is_empty() {
                eprintln!("{}", "No files found.".yellow());
                std::process::exit(1);
            }

            let since_ref = since.as_deref();
            let total = AtomicUsize::new(0);

            let per_file: Vec<(PathBuf, usize)> = discovered
                .par_iter()
                .map(|file| {
                    let (results, _fstats) = search_file(file, &query, 0, 0, None, since_ref);
                    let count = results.iter().filter(|r| r.is_match).count();
                    total.fetch_add(count, Ordering::Relaxed);
                    (file.clone(), count)
                })
                .collect();

            for (path, count) in &per_file {
                if *count > 0 {
                    println!("{}: {}", path.display(), count);
                }
            }

            eprintln!();
            eprintln!(
                "{} {} matches across {} files",
                "Total:".bold(),
                total.load(Ordering::Relaxed),
                discovered.len()
            );
        }

        Commands::Compress {
            files,
            remove_original,
        } => {
            compress_files(&files, remove_original);
        }
    }
}
