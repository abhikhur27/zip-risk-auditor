# Zip Risk Auditor

Rust CLI that scans `.zip` archives for extraction hazards and suspicious contents before you open them on a Windows workstation or drop them into a project.

## Why it exists

Archive files are easy to trust too quickly. A quick download folder cleanup or vendor handoff can hide:

- path traversal entries like `..\..\AppData\...`
- unusually high expansion ratios that hint at zip-bomb behavior
- duplicate file paths inside the same archive
- executable/script payloads mixed into what looks like a normal document drop
- nested archives that deserve a second look

This tool turns that first-pass inspection into one repeatable command.

## What it does

- Scans one or more `.zip` files or walks directories recursively for zip archives
- Flags path traversal and absolute-path extraction entries
- Measures per-entry and per-archive expansion ratios
- Counts executable/script payloads and nested archives
- Detects duplicate normalized entry paths inside each archive
- Exports JSON and Markdown briefs for handoff or cleanup notes

## Usage

```bash
cargo run -- --input . --markdown-out reports/brief.md --json-out reports/brief.json
```

Tighten the zip-bomb threshold and show more archives in the console:

```bash
cargo run -- --input C:\Users\abhim\Downloads --ratio-threshold 12 --top 8
```

## Output

- Console summary with the riskiest archives first
- JSON report for scripting
- Markdown brief for notes or a PR

## Portfolio Positioning

- Project type: Rust CLI utility
- Role: archive safety and extraction triage
- Direction fit: practical installable workflow utility, not another browser demo
