# tcpwatch

Parse `tcpdump` pcap files and live streams with configurable delimiter-style (e.g., `|`, `;`, tab) data patterns. Supports both an interactive GUI and a stream-friendly CLI.

---

## Features

- **Standard Library Only**: Built with pure Python (3.8+). No third-party dependencies (`tkinter` required only for GUI mode).
- **Full File & Live Follow**: Parses the entire pcap file from beginning to end, then continues following newly appended packets in real time (disable with `--no-follow`).
- **Dual Mode (GUI & CLI)**: Interactive GUI with high-DPI support, live search/filtering, and pattern editor; falls back automatically to CLI if no display or `tkinter` is detected.
- **Flexible Pattern Profiles**: Split payloads into structured columns using delimiters or regex. Store configurations in `patterns.json` or override on the fly via CLI flags.
- **Multiple Output Formats**: Export records to `table`, `csv`, `tsv`, or `json` (newline-delimited JSON).
- **Live Stream / Stdin Support**: Pipe directly from `tcpdump` into `tcpwatch` using `-`.
- **Packet Filtering**: Filter by protocol (`tcp`/`udp`), port, regex pattern, and text grep.

---

## Requirements & Compatibility

- **Python**: 3.8 or higher.
- **GUI**: Requires `tkinter` (included by default on Windows/macOS; on Debian/Ubuntu install via `sudo apt-get install python3-tk`).
- **PCAP Format**: Supports standard/classic pcap format (`tcpdump -w` default). *Note: `pcapng` format is not supported.*

---

## Quick Start

### 1. Try with Simulated Feed
Generate fake live traffic with pipe-delimited payloads and inspect it in real time:

```bash
# Terminal 1: Start sample feed generator
python sample_feed.py live.pcap

# Terminal 2: Launch tcpwatch
python main.py live.pcap
```

### 2. Live Capture with `tcpdump`
When capturing with `tcpdump`, pass the `-U` flag to flush packet buffers immediately:

```bash
# Capture packets to a live file
tcpdump -i eth0 -U -w live.pcap

# In another terminal, follow live packets in GUI mode
python main.py live.pcap
```

Or stream directly through stdin without writing to disk:

```bash
tcpdump -i any -U -w - | python main.py --cli -
```

---

## Usage Examples

### GUI Mode
```bash
# Launch GUI (auto-falls back to CLI if no display is available)
python main.py live.pcap

# Force GUI mode
python main.py --gui live.pcap

# Configure maximum retained rows in GUI (default: 500000, 0 = unlimited)
python main.py live.pcap --max-rows 100000
```

### CLI Mode
```bash
# Pretty-printed table in terminal
python main.py --cli live.pcap

# Process finished pcap without following, output to CSV file
python main.py --cli live.pcap --no-follow -f csv -o out.csv

# Custom delimiter, custom field names, and grep filter
python main.py --cli live.pcap -d ';' -F id,user,action --grep login -n 100

# JSON output without packet metadata, piped to jq
python main.py --cli live.pcap -f json --no-meta -q | jq .

# Select a stored pattern profile
python main.py --list-profiles
python main.py --cli -p myprofile live.pcap
```

---

## Patterns & Profiles

Profiles define how packet payloads are extracted and split into columns.

- **GUI Configuration**: Use the **"Edit patterns..."** dialog in the GUI to adjust profiles visually.
- **Configuration File**: Saved in `patterns.json` (or custom path via `-c / --config`).
- **CLI Overrides**: Any profile setting can be overridden for a single run using command-line arguments:
  - `-d, --delimiter`: Field separator (e.g. `|`, `;`, `\t`).
  - `-F, --fields`: Comma-separated column headers.
  - `-r, --regex`: Regex pattern to capture records (Group 1 = record).
  - `--proto`: Filter by protocol (`any`, `tcp`, `udp`).
  - `--port`: Filter by specific source or destination port.
  - `--min-fields`: Minimum number of split fields required for a record to count.

---

## Command-Line Reference

```text
usage: main.py [-h] [--cli] [--gui] [--no-follow] [-c CONFIG] [-p PROFILE]
               [--list-profiles] [-d DELIMITER] [-F FIELDS] [-r REGEX]
               [--proto {any,tcp,udp}] [--port PORT] [--min-fields MIN_FIELDS]
               [-f {table,csv,tsv,json}] [-o OUTPUT] [-n COUNT] [--grep GREP]
               [--unparsed] [--no-meta] [--no-header] [-q] [--max-rows MAX_ROWS]
               [pcap]
```

### Positional Arguments
| Argument | Description |
|---|---|
| `pcap` | Path to pcap file (live or finished), or `-` to read from stdin. |

### Mode Options
| Option | Description |
|---|---|
| `--cli` | Run in terminal mode (no GUI). |
| `--gui` | Force GUI mode. |
| `--no-follow` | Exit when reaching EOF instead of waiting for newly appended packets. |

### Pattern Options
| Option | Description |
|---|---|
| `-c`, `--config` | Path to patterns config file (default: `patterns.json` next to `main.py`). |
| `-p`, `--profile` | Profile name to use. |
| `--list-profiles` | List available profiles and exit. |
| `-d`, `--delimiter` | Delimiter string (e.g. `'|'`, `';'`, `'\t'`). |
| `-F`, `--fields` | Comma-separated list of field names. |
| `-r`, `--regex` | Regex pattern where group 1 defines the record. |
| `--proto` | Match protocol: `any`, `tcp`, or `udp`. |
| `--port` | Match source or destination port. |
| `--min-fields` | Minimum field count required to consider a record valid. |

### CLI Output Options
| Option | Description |
|---|---|
| `-f`, `--format` | Output format: `table` (default), `csv`, `tsv`, `json`. |
| `-o`, `--output` | Write output to a file instead of stdout. |
| `-n`, `--count` | Stop after outputting `N` records. |
| `--grep` | Filter output rows containing this text (case-insensitive). |
| `--unparsed` | Output packets even if payload could not be parsed. |
| `--no-meta` | Emit only parsed fields without packet metadata (`#`, time, src, dst, proto, len). |
| `--no-header` | Suppress the header line. |
| `-q`, `--quiet` | Suppress summary stats on stderr upon exit. |

### GUI Options
| Option | Description |
|---|---|
| `--max-rows` | Maximum rows retained in GUI table (default: `500000`, `0` = unlimited). |
