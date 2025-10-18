# Aerospike tcpdump Analyzer

A powerful command-line tool for analyzing Aerospike database traffic from tcpdump/pcap captures. Decode the Aerospike wire protocol to inspect transactions, identify hot keys, and troubleshoot performance issues.

## Features

- **Transaction Analysis**: Decode and display detailed information about Aerospike operations
  - Transaction types: READ, WRITE, DELETE, BATCH, SCAN, QUERY
  - Record metadata: generation, TTL, result codes
  - Record identity: namespace, set, digest, primary key
  
- **Hot Key Detection**: Identify frequently accessed records that may cause performance bottlenecks
  - Configurable threshold for hot key detection
  - Columnar output for easy analysis
  - Export reports to text or CSV format

- **Advanced Filtering**: Focus on specific transaction types
  - Filter by READ, WRITE, DELETE, BATCH, SCAN, or QUERY
  - Combine multiple filters
  - Limit output for quick analysis

- **Primary Key Visibility**: See when SEND_KEY flag is used
  - Display keys in multiple formats (string, integer, hex)
  - Track which operations include the primary key

## Installation

### Requirements

- Python 3.6 or higher
- Scapy library for packet parsing

### Install Dependencies

```bash
pip install scapy
```

Or if you prefer using pip3:

```bash
pip3 install scapy
```

### Download the Tool

Save the script as `aerospike_analyzer.py` and make it executable:

```bash
chmod +x aerospike_analyzer.py
```

## Quick Start

### 1. Capture Aerospike Traffic

Use tcpdump to capture traffic on the Aerospike port (default: 3000):

```bash
# Capture to file
sudo tcpdump -i any -s 65535 -w aerospike.pcap port 3000

# Capture for 60 seconds
sudo tcpdump -i any -s 65535 -w aerospike.pcap -G 60 -W 1 port 3000
```

### 2. Analyze the Capture

```bash
# Basic analysis
python3 aerospike_analyzer.py aerospike.pcap

# Hot key detection
python3 aerospike_analyzer.py aerospike.pcap --hotkey 10

# Filter by transaction type
python3 aerospike_analyzer.py aerospike.pcap --type WRITE
```

## Command-Line Options

```
Usage: python aerospike_analyzer.py <pcap_file> [options]

Options:
  --port N         : Aerospike port (default: 3000)
  --type TYPE      : Filter by transaction type (can specify multiple)
                     Types: READ, WRITE, DELETE, BATCH, SCAN, QUERY
  --hotkey N       : Enable hot key detection mode (threshold: N+ accesses)
                     Shows simplified columnar output
  --output FILE    : Save hot key report to file
  --csv            : Save report in CSV format (use with --output)
  --verbose        : Show debug information
  --limit N        : Limit output to first N matching packets
```

## Usage Examples

### Detailed Packet Analysis

**Analyze all traffic:**
```bash
python3 aerospike_analyzer.py capture.pcap
```

**Filter by transaction type:**
```bash
# Only WRITE operations
python3 aerospike_analyzer.py capture.pcap --type WRITE

# Only READ operations
python3 aerospike_analyzer.py capture.pcap --type READ

# Multiple types (WRITE or DELETE)
python3 aerospike_analyzer.py capture.pcap --type WRITE --type DELETE
```

**Limit output for quick inspection:**
```bash
# Show first 10 WRITE operations
python3 aerospike_analyzer.py capture.pcap --type WRITE --limit 10
```

**Custom port:**
```bash
python3 aerospike_analyzer.py capture.pcap --port 3001
```

### Hot Key Detection

**Basic hot key detection:**
```bash
# Flag records accessed 10+ times
python3 aerospike_analyzer.py capture.pcap --hotkey 10
```

**Adjust sensitivity:**
```bash
# More sensitive - flag keys accessed 5+ times
python3 aerospike_analyzer.py capture.pcap --hotkey 5

# Less sensitive - only very hot keys (20+ accesses)
python3 aerospike_analyzer.py capture.pcap --hotkey 20
```

**Filter hot keys by transaction type:**
```bash
# Hot keys for WRITE operations only
python3 aerospike_analyzer.py capture.pcap --type WRITE --hotkey 5

# Hot keys for READ operations
python3 aerospike_analyzer.py capture.pcap --type READ --hotkey 10
```

### Saving Reports

**Save hot key report as text:**
```bash
python3 aerospike_analyzer.py capture.pcap --hotkey 10 --output hotkeys.txt
```

**Save as CSV for Excel/analysis:**
```bash
python3 aerospike_analyzer.py capture.pcap --hotkey 10 --output hotkeys.csv --csv
```

**Filter and save:**
```bash
# Save WRITE hot keys to CSV
python3 aerospike_analyzer.py capture.pcap --type WRITE --hotkey 5 --output write_hotkeys.csv --csv
```

### Troubleshooting

**Verbose mode to see what's being parsed:**
```bash
python3 aerospike_analyzer.py capture.pcap --verbose --limit 5
```

**Check if traffic exists:**
```bash
python3 aerospike_analyzer.py capture.pcap --verbose
```

## Output Format

### Detailed Packet Output

```
================================================================================
Packet #42 [CLIENT->SERVER] - 1634567890.123456
================================================================================
Transaction Type: WRITE
Result Code: OK (0)

--- RECORD IDENTITY ---
Namespace: test
Set: users
Record Digest: a1b2c3d4e5f6789012345678901234567890abcd

SEND_KEY: TRUE
Primary Key:
  String: user12345
  Hex: 75736572313233343

--- METADATA ---
Generation: 5
Record TTL: 2592000 seconds
Transaction TTL: 1000 milliseconds

--- FLAGS ---
WRITE, CHECK_GENERATION, COMMIT_MASTER

--- OPERATIONS (2) ---
  WRITE: username
  WRITE: email
```

### Hot Key Report (Text Format)

```
====================================================================================================
HOT KEY DETECTION - 12 hot keys found (threshold: 10+ accesses)
====================================================================================================
DIGEST                                   NAMESPACE.SET             TX TYPES           COUNT
---------------------------------------- ------------------------- ------------------ --------
a1b2c3d4e5f6789012345678901234567890ab   test.users                READ,WRITE           127
f1e2d3c4b5a6789012345678901234567890ab   test.sessions             READ                  89
c4d5e6f7a8b9012345678901234567890abcd   prod.inventory            WRITE                 67
====================================================================================================
```

### Hot Key Report (CSV Format)

```csv
DIGEST,NAMESPACE,SET,TX_TYPES,COUNT
a1b2c3d4e5f6789012345678901234567890abcd,test,users,READ;WRITE,127
f1e2d3c4b5a6789012345678901234567890abcd,test,sessions,READ,89
c4d5e6f7a8b9012345678901234567890abcdef,prod,inventory,WRITE,67
```

## Common Use Cases

### 1. Identify Write Hot Keys

Find records being written to frequently:

```bash
python3 aerospike_analyzer.py capture.pcap --type WRITE --hotkey 5 --output write_hotkeys.csv --csv
```

### 2. Debug Key Visibility Issues

Check if SEND_KEY flag is being used:

```bash
python3 aerospike_analyzer.py capture.pcap --type WRITE --limit 20
```

Look for "SEND_KEY: TRUE" or "SEND_KEY: FALSE" in the output.

### 3. Monitor Read vs Write Patterns

Analyze read and write traffic separately:

```bash
# Analyze reads
python3 aerospike_analyzer.py capture.pcap --type READ --hotkey 10 --output reads.txt

# Analyze writes
python3 aerospike_analyzer.py capture.pcap --type WRITE --hotkey 10 --output writes.txt
```

### 4. Investigate Performance Issues

Capture traffic during a performance issue and identify hot keys:

```bash
# During the issue
sudo tcpdump -i any -s 65535 -w issue.pcap -G 300 -W 1 port 3000

# Analyze
python3 aerospike_analyzer.py issue.pcap --hotkey 5 --output issue_hotkeys.txt
```

### 5. Verify Record Digests

See the actual digest values being used:

```bash
python3 aerospike_analyzer.py capture.pcap --type WRITE --limit 10
```

## Tips and Best Practices

### Capturing Traffic

1. **Use adequate snapshot length**: `-s 65535` captures full packets
2. **Capture on all interfaces**: `-i any` ensures you don't miss traffic
3. **Time-limited captures**: Use `-G` and `-W` flags to limit capture duration
4. **Production considerations**: Be mindful of disk space and network overhead

### Analyzing Large Captures

1. **Use filters**: `--type` and `--limit` to reduce output
2. **Hot key mode**: Use `--hotkey` for performance analysis without verbose output
3. **Save to file**: Use `--output` to save results for later review
4. **CSV export**: Use `--csv` for importing into spreadsheets or databases

### Hot Key Detection

1. **Start with default threshold**: `--hotkey 10` is a good starting point
2. **Adjust based on traffic**: Lower threshold for low-traffic systems
3. **Filter by operation**: Use `--type` to focus on specific transaction types
4. **Monitor over time**: Capture and analyze traffic at different times

## Troubleshooting

### No Aerospike Traffic Found

**Check the port:**
```bash
python3 aerospike_analyzer.py capture.pcap --port 3001 --verbose
```

**Verify capture has data:**
```bash
tcpdump -r capture.pcap -c 10
```

### Digests Not Showing

Run with `--verbose` to see if digest fields are present:
```bash
python3 aerospike_analyzer.py capture.pcap --verbose --limit 5
```

### Script Hangs or Runs Slowly

This is normal for large pcap files. The tool streams packets for memory efficiency, but large files take time. Use `--limit` for quick testing:
```bash
python3 aerospike_analyzer.py large_capture.pcap --limit 100
```

## Understanding the Output

### Transaction Types

- **READ**: Simple read operation (get)
- **WRITE**: Write/put operation
- **DELETE**: Delete operation
- **BATCH**: Batch read operation
- **SCAN**: Full namespace/set scan
- **QUERY**: Secondary index query

### Common Flags

- **SEND_KEY**: Primary key is sent with the request
- **CHECK_GENERATION**: Generation number must match
- **COMMIT_MASTER**: Commit level requires master node
- **DURABLE_DELETE**: Tombstone will be written for delete

### Result Codes

- **0 (OK)**: Operation successful
- **2 (KEY_NOT_FOUND)**: Record doesn't exist
- **5 (KEY_EXISTS)**: Record already exists (CREATE_ONLY failed)
- **9 (TIMEOUT)**: Operation timed out

## Performance Considerations

- The tool streams packets from pcap files, so memory usage is minimal
- Large pcap files will take time to process
- Use `--limit` for quick analysis of large files
- Hot key mode (`--hotkey`) is faster as it suppresses detailed output

## Contributing

Found a bug or want to add a feature? Contributions are welcome!

## License

This tool is provided as-is for analyzing Aerospike traffic.

## Support

For issues related to:
- **This tool**: Check verbose output and verify pcap file integrity
- **Aerospike protocol**: Refer to Aerospike documentation
- **Packet capture**: Check tcpdump/libpcap documentation
