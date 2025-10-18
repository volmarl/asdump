#!/usr/bin/env python3
"""
Aerospike tcpdump Analyzer
Analyzes tcpdump captures of Aerospike traffic and displays protocol details
"""

import struct
import sys
from collections import defaultdict

try:
    from scapy.all import PcapReader, TCP, IP
except ImportError:
    print("Error: scapy is required. Install with: pip install scapy")
    sys.exit(1)

# Aerospike Protocol Constants
AS_PROTO_VERSION = 2
AS_PROTO_TYPE_INFO = 1
AS_PROTO_TYPE_MESSAGE = 3
AS_PROTO_TYPE_COMPRESSED = 4

# Message types
MSG_TYPE_INFO = 1
MSG_TYPE_MESSAGE = 3

# Transaction result codes
RESULT_CODES = {
    0: "OK",
    1: "UNKNOWN",
    2: "KEY_NOT_FOUND",
    3: "GENERATION_ERROR",
    4: "PARAMETER_ERROR",
    5: "KEY_EXISTS",
    6: "BIN_EXISTS",
    7: "CLUSTER_KEY_MISMATCH",
    8: "PARTITION_OUT_OF_SPACE",
    9: "TIMEOUT",
    10: "NO_XDR",
    11: "SERVER_UNAVAILABLE",
    12: "INCOMPATIBLE_TYPE",
    13: "RECORD_TOO_BIG",
    14: "KEY_BUSY",
    15: "SCAN_ABORT",
    16: "UNSUPPORTED_FEATURE",
    17: "BIN_NOT_FOUND",
    18: "DEVICE_OVERLOAD",
    19: "KEY_MISMATCH",
    20: "NAMESPACE_NOT_FOUND",
    21: "BIN_NAME_TOO_LONG",
    22: "FAIL_FORBIDDEN",
    23: "FAIL_ELEMENT_NOT_FOUND",
    24: "FAIL_ELEMENT_EXISTS",
    25: "ENTERPRISE_ONLY",
    26: "OP_NOT_APPLICABLE",
    27: "FILTERED_OUT",
    28: "LOST_CONFLICT",
    29: "QUERY_END",
    30: "SECURITY_NOT_SUPPORTED",
    31: "SECURITY_NOT_ENABLED",
    32: "SECURITY_SCHEME_NOT_SUPPORTED",
    33: "INVALID_COMMAND",
    34: "INVALID_FIELD",
    35: "ILLEGAL_STATE",
    36: "INVALID_USER",
    37: "USER_ALREADY_EXISTS",
    38: "INVALID_PASSWORD",
    39: "EXPIRED_PASSWORD",
    40: "FORBIDDEN_PASSWORD",
    41: "INVALID_CREDENTIAL",
    42: "INVALID_ROLE",
    43: "ROLE_ALREADY_EXISTS",
    44: "INVALID_PRIVILEGE",
    45: "NOT_AUTHENTICATED",
    46: "ROLE_VIOLATION",
}

# Message info flags
INFO1_READ = 0x01
INFO1_GET_ALL = 0x02
INFO1_BATCH_INDEX = 0x04
INFO1_XDR = 0x08
INFO1_GET_NOBINDATA = 0x10
INFO1_READ_MODE_AP_ALL = 0x20
INFO1_COMPRESS_RESPONSE = 0x40

INFO2_WRITE = 0x01
INFO2_DELETE = 0x02
INFO2_GENERATION = 0x04
INFO2_GENERATION_GT = 0x08
INFO2_DURABLE_DELETE = 0x10
INFO2_CREATE_ONLY = 0x20
INFO2_RELAX_AP_LONG_QUERY = 0x40
INFO2_RESPOND_ALL_OPS = 0x80

INFO3_LAST = 0x01
INFO3_COMMIT_MASTER = 0x02
INFO3_UPDATE_ONLY = 0x08
INFO3_CREATE_OR_REPLACE = 0x10
INFO3_REPLACE_ONLY = 0x20
INFO3_SC_READ_TYPE = 0x40
INFO3_SC_READ_RELAX = 0x80

# Field types
FIELD_TYPE_NAMESPACE = 0
FIELD_TYPE_SET = 1
FIELD_TYPE_KEY = 2
FIELD_TYPE_DIGEST = 4
FIELD_TYPE_DIGEST_ARRAY = 6
FIELD_TYPE_TRID = 7
FIELD_TYPE_SCAN_OPTIONS = 8
FIELD_TYPE_INDEX_NAME = 21
FIELD_TYPE_INDEX_RANGE = 22
FIELD_TYPE_INDEX_FILTER = 23
FIELD_TYPE_INDEX_LIMIT = 24
FIELD_TYPE_INDEX_ORDER = 25
FIELD_TYPE_UDF_PACKAGE_NAME = 30
FIELD_TYPE_UDF_FUNCTION = 31
FIELD_TYPE_UDF_ARGLIST = 32
FIELD_TYPE_UDF_OP = 33
FIELD_TYPE_QUERY_BINLIST = 40
FIELD_TYPE_BATCH_INDEX = 41
FIELD_TYPE_BATCH_INDEX_WITH_SET = 42
FIELD_TYPE_PID_ARRAY = 43
FIELD_TYPE_DIGEST_ARRAY_OPAQUE = 44

FIELD_NAMES = {
    0: "NAMESPACE",
    1: "SET",
    2: "KEY",
    4: "DIGEST",
    6: "DIGEST_ARRAY",
    7: "TRID",
    8: "SCAN_OPTIONS",
    21: "INDEX_NAME",
    22: "INDEX_RANGE",
    23: "INDEX_FILTER",
    24: "INDEX_LIMIT",
    25: "INDEX_ORDER",
    30: "UDF_PACKAGE_NAME",
    31: "UDF_FUNCTION",
    32: "UDF_ARGLIST",
    33: "UDF_OP",
    40: "QUERY_BINLIST",
    41: "BATCH_INDEX",
    42: "BATCH_INDEX_WITH_SET",
    43: "PID_ARRAY",
    44: "DIGEST_ARRAY_OPAQUE",
}

# Operation types
OP_READ = 1
OP_WRITE = 2
OP_CDT_READ = 3
OP_CDT_MODIFY = 4
OP_INCR = 5
OP_APPEND = 9
OP_PREPEND = 10
OP_TOUCH = 11
OP_DELETE = 12

OP_NAMES = {
    1: "READ",
    2: "WRITE",
    3: "CDT_READ",
    4: "CDT_MODIFY",
    5: "INCREMENT",
    9: "APPEND",
    10: "PREPEND",
    11: "TOUCH",
    12: "DELETE",
}


class AerospikeProtocolParser:
    def __init__(self, verbose=False, filter_types=None, hotkey_threshold=10, hotkey_mode=False):
        self.conversations = defaultdict(list)
        self.verbose = verbose
        self.filter_types = [t.upper() for t in filter_types] if filter_types else None
        self.hotkey_threshold = hotkey_threshold
        self.hotkey_mode = hotkey_mode  # Simplified output for hot key analysis
        self.digest_counts = defaultdict(lambda: {'count': 0, 'namespace': None, 'set': None, 'tx_types': set()})
        self.digest_first_seen = {}  # Track when we first see each digest
    
    def parse_proto_header(self, data):
        """Parse the protocol header (8 bytes)"""
        if len(data) < 8:
            return None
        
        version = data[0]
        msg_type = data[1]
        sz = struct.unpack(">Q", data[:8])[0]
        sz = sz & 0xFFFFFFFFFFFF  # Lower 6 bytes
        
        return {
            'version': version,
            'type': msg_type,
            'size': sz
        }
    
    def parse_message_header(self, data):
        """Parse message header"""
        if len(data) < 22:
            return None
        
        header_sz = data[0]
        info1 = data[1]
        info2 = data[2]
        info3 = data[3]
        unused = data[4]
        result_code = data[5]
        generation = struct.unpack(">I", data[6:10])[0]
        record_ttl = struct.unpack(">I", data[10:14])[0]
        transaction_ttl = struct.unpack(">I", data[14:18])[0]
        n_fields = struct.unpack(">H", data[18:20])[0]
        n_ops = struct.unpack(">H", data[20:22])[0]
        
        return {
            'header_size': header_sz,
            'info1': info1,
            'info2': info2,
            'info3': info3,
            'result_code': result_code,
            'generation': generation,
            'record_ttl': record_ttl,
            'transaction_ttl': transaction_ttl,
            'n_fields': n_fields,
            'n_ops': n_ops
        }
    
    def parse_fields(self, data, n_fields):
        """Parse message fields"""
        fields = []
        offset = 0
        
        for _ in range(n_fields):
            if offset + 5 > len(data):  # Need at least 4 bytes size + 1 byte type
                break
            
            # Field size is the size of type (1 byte) + data (N bytes), NOT including the 4-byte size field itself
            field_size = struct.unpack(">I", data[offset:offset+4])[0]
            
            # Check if we have enough data for the entire field
            if offset + 4 + field_size > len(data):
                break
                
            field_type = data[offset+4]
            # field_data starts at offset+5 (after 4-byte size and 1-byte type)
            # and goes for (field_size - 1) bytes (subtracting the type byte from field_size)
            field_data = data[offset+5:offset+4+field_size]
            
            fields.append({
                'type': field_type,
                'type_name': FIELD_NAMES.get(field_type, f"UNKNOWN({field_type})"),
                'data': field_data
            })
            
            # Move offset past the entire field: 4 bytes (size) + field_size (type + data)
            offset += 4 + field_size
        
        return fields, offset
    
    def parse_operations(self, data, n_ops):
        """Parse operations"""
        operations = []
        offset = 0
        
        for _ in range(n_ops):
            if offset + 8 > len(data):
                break
            
            # Operation size includes everything after the 4-byte size field
            op_size = struct.unpack(">I", data[offset:offset+4])[0]
            
            # Check if we have enough data
            if offset + 4 + op_size > len(data):
                break
                
            op_type = data[offset+4]
            bin_name_len = data[offset+7]
            
            if offset + 8 + bin_name_len > len(data):
                break
                
            bin_name = data[offset+8:offset+8+bin_name_len].decode('utf-8', errors='ignore')
            
            operations.append({
                'type': op_type,
                'type_name': OP_NAMES.get(op_type, f"UNKNOWN({op_type})"),
                'bin_name': bin_name,
                'size': op_size
            })
            
            # Move offset past the entire operation: 4 bytes (size) + op_size (operation data)
            offset += 4 + op_size
        
        return operations
    
    def decode_info_flags(self, info1, info2, info3):
        """Decode info flags"""
        flags = []
        
        if info1 & INFO1_READ:
            flags.append("READ")
        if info1 & INFO1_GET_ALL:
            flags.append("GET_ALL")
        if info1 & INFO1_BATCH_INDEX:
            flags.append("BATCH")
        if info1 & INFO1_GET_NOBINDATA:
            flags.append("NO_BIN_DATA")
        if info1 & INFO1_COMPRESS_RESPONSE:
            flags.append("COMPRESS_RESPONSE")
        
        if info2 & INFO2_WRITE:
            flags.append("WRITE")
        if info2 & INFO2_DELETE:
            flags.append("DELETE")
        if info2 & INFO2_GENERATION:
            flags.append("CHECK_GENERATION")
        if info2 & INFO2_GENERATION_GT:
            flags.append("GENERATION_GT")
        if info2 & INFO2_DURABLE_DELETE:
            flags.append("DURABLE_DELETE")
        if info2 & INFO2_CREATE_ONLY:
            flags.append("CREATE_ONLY")
        if info2 & INFO2_RESPOND_ALL_OPS:
            flags.append("RESPOND_ALL_OPS")
        
        if info3 & INFO3_LAST:
            flags.append("LAST")
        if info3 & INFO3_COMMIT_MASTER:
            flags.append("COMMIT_MASTER")
        if info3 & INFO3_UPDATE_ONLY:
            flags.append("UPDATE_ONLY")
        if info3 & INFO3_CREATE_OR_REPLACE:
            flags.append("CREATE_OR_REPLACE")
        if info3 & INFO3_REPLACE_ONLY:
            flags.append("REPLACE_ONLY")
        
        return flags
    
    def determine_transaction_type(self, info1, info2, info3, fields):
        """Determine transaction type"""
        if info1 & INFO1_BATCH_INDEX:
            return "BATCH"
        elif info2 & INFO2_WRITE:
            if info2 & INFO2_DELETE:
                return "DELETE"
            return "WRITE"
        elif info1 & INFO1_READ:
            return "READ"
        
        # Check for scan/query based on fields
        for field in fields:
            if field['type'] == FIELD_TYPE_SCAN_OPTIONS:
                return "SCAN"
            elif field['type'] in [FIELD_TYPE_INDEX_NAME, FIELD_TYPE_INDEX_RANGE]:
                return "QUERY"
        
        return "UNKNOWN"
    
    def format_digest(self, digest_bytes):
        """Format digest as hex string"""
        return digest_bytes.hex()
    
    def has_sendkey(self, fields):
        """Check if SEND_KEY flag is present (key field exists)"""
        for field in fields:
            if field['type'] == FIELD_TYPE_KEY:
                return True


    def get_hotkey_summary(self):
        """Get summary of hot keys"""
        hotkeys = []
        for digest, info in self.digest_counts.items():
            if info['count'] >= self.hotkey_threshold:
                hotkeys.append({
                    'digest': digest,
                    'count': info['count'],
                    'namespace': info['namespace'],
                    'set': info['set'],
                    'tx_types': info['tx_types']
                })
        
        # Sort by count descending
        hotkeys.sort(key=lambda x: x['count'], reverse=True)
        return hotkeys
    
    def print_hotkey_table(self, hotkeys, output_file=None, csv_format=False):
        """Print hot keys in columnar format and optionally save to file"""
        if not hotkeys:
            print("No hot keys detected.")
            return
        
        # Prepare output lines
        lines = []
        
        if csv_format:
            # CSV format
            lines.append("DIGEST,NAMESPACE,SET,TX_TYPES,COUNT")
            for hk in hotkeys:
                namespace = hk['namespace'] if hk['namespace'] else ""
                set_name = hk['set'] if hk['set'] else ""
                tx_types_str = ';'.join(sorted(hk['tx_types']))
                lines.append(f"{hk['digest']},{namespace},{set_name},{tx_types_str},{hk['count']}")
        else:
            # Text format
            lines.append(f"{'='*100}")
            lines.append(f"HOT KEY DETECTION - {len(hotkeys)} hot keys found (threshold: {self.hotkey_threshold}+ accesses)")
            lines.append(f"{'='*100}")
            lines.append(f"{'DIGEST':<42} {'NAMESPACE.SET':<25} {'TX TYPES':<18} {'COUNT':>8}")
            lines.append(f"{'-'*42} {'-'*25} {'-'*18} {'-'*8}")
            
            for hk in hotkeys:
                digest_short = hk['digest'][:40]
                location = f"{hk['namespace']}" if hk['namespace'] else "N/A"
                if hk['set']:
                    location += f".{hk['set']}"
                location = location[:25]
                
                tx_types_str = ','.join(sorted(hk['tx_types']))[:18]
                
                lines.append(f"{digest_short:<42} {location:<25} {tx_types_str:<18} {hk['count']:>8}")
            
            lines.append(f"{'='*100}")
        
        # Print to console
        if not csv_format:
            print()
        for line in lines:
            print(line)
        
        # Save to file if specified
        if output_file:
            try:
                with open(output_file, 'w') as f:
                    f.write('\n'.join(lines) + '\n')
                print(f"\nHot key report saved to: {output_file}")
            except Exception as e:
                print(f"\nError saving report to file: {e}")
        return False
    
    def format_key(self, key_bytes):
        """Format key in multiple representations"""
        result = {
            'hex': key_bytes.hex(),
            'string': None,
            'integer': None
        }
        
        # Try to decode as string
        try:
            key_str = key_bytes.decode('utf-8', errors='strict')
            if key_str.isprintable():
                result['string'] = key_str
        except:
            pass
        
        # Try to decode as integer (for numeric keys)
        if len(key_bytes) == 8:
            try:
                result['integer'] = struct.unpack(">Q", key_bytes)[0]
            except:
                pass
        elif len(key_bytes) == 4:
            try:
                result['integer'] = struct.unpack(">I", key_bytes)[0]
            except:
                pass
        
        return result
    
    def analyze_packet(self, packet_num, direction, data, timestamp):
        """Analyze a single Aerospike packet"""
        if len(data) < 8:
            if self.verbose:
                print(f"Packet #{packet_num}: Too small ({len(data)} bytes)")
            return False
        
        proto_header = self.parse_proto_header(data)
        if not proto_header:
            if self.verbose:
                print(f"Packet #{packet_num}: Failed to parse protocol header")
            return False
        
        if proto_header['type'] != AS_PROTO_TYPE_MESSAGE:
            if self.verbose:
                print(f"Packet #{packet_num}: Not a message type (type={proto_header['type']})")
            return False
        
        msg_data = data[8:]
        if len(msg_data) < 22:
            if self.verbose:
                print(f"Packet #{packet_num}: Message data too small")
            return False
            
        msg_header = self.parse_message_header(msg_data)
        if not msg_header:
            if self.verbose:
                print(f"Packet #{packet_num}: Failed to parse message header")
            return False
        
        # Parse fields and operations
        field_data = msg_data[msg_header['header_size']:]
        fields, field_offset = self.parse_fields(field_data, msg_header['n_fields'])
        
        op_data = field_data[field_offset:]
        operations = self.parse_operations(op_data, msg_header['n_ops'])
        
        # Extract key information
        namespace = None
        set_name = None
        key = None
        digest = None
        
        # Debug: print all field types found
        if self.verbose:
            print(f"DEBUG: Found {len(fields)} fields:")
            for i, field in enumerate(fields):
                print(f"  Field {i}: type={field['type']} ({field['type_name']}), data_len={len(field['data'])}, data_hex={field['data'][:20].hex()}...")
        
        for field in fields:
            if field['type'] == FIELD_TYPE_NAMESPACE:
                namespace = field['data'].decode('utf-8', errors='ignore')
            elif field['type'] == FIELD_TYPE_SET:
                set_name = field['data'].decode('utf-8', errors='ignore')
            elif field['type'] == FIELD_TYPE_KEY:
                key = field['data']
            elif field['type'] == FIELD_TYPE_DIGEST:
                digest = self.format_digest(field['data'])
                if self.verbose:
                    print(f"DEBUG: Found digest field, length={len(field['data'])}, digest={digest}")
        
        # Determine transaction type
        tx_type = self.determine_transaction_type(
            msg_header['info1'], 
            msg_header['info2'], 
            msg_header['info3'],
            fields
        )
        
        # Apply filter if specified
        if self.filter_types:
            if tx_type not in self.filter_types:
                if self.verbose:
                    print(f"Packet #{packet_num}: Filtered out (type={tx_type})")
                return False
        
        flags = self.decode_info_flags(
            msg_header['info1'],
            msg_header['info2'],
            msg_header['info3']
        )
        
        has_key = self.has_sendkey(fields)
        formatted_key = self.format_key(key) if key else None
        
        # Track digest for hot key detection
        is_hotkey = False
        if digest:
            self.digest_counts[digest]['count'] += 1
            self.digest_counts[digest]['namespace'] = namespace
            self.digest_counts[digest]['set'] = set_name
            self.digest_counts[digest]['tx_types'].add(tx_type)
            
            if digest not in self.digest_first_seen:
                self.digest_first_seen[digest] = packet_num
            
            # Check if this is a hot key
            if self.digest_counts[digest]['count'] >= self.hotkey_threshold:
                is_hotkey = True
        
        # If in hotkey mode, skip detailed output and just track
        if self.hotkey_mode:
            return True
        
        # Print analysis
        print(f"\n{'='*80}")
        print(f"Packet #{packet_num} [{direction}] - {timestamp}")
        print(f"{'='*80}")
        print(f"Transaction Type: {tx_type}")
        print(f"Result Code: {RESULT_CODES.get(msg_header['result_code'], 'UNKNOWN')} ({msg_header['result_code']})")
        
        # Highlight key record identifiers
        print(f"\n--- RECORD IDENTITY ---")
        if namespace:
            print(f"Namespace: {namespace}")
        if set_name:
            print(f"Set: {set_name}")
        
        if digest:
            access_count = self.digest_counts[digest]['count']
            if is_hotkey:
                print(f"Record Digest: {digest} *** HOT KEY *** (accessed {access_count} times)")
            else:
                print(f"Record Digest: {digest} (accessed {access_count} times)")
        else:
            print(f"Record Digest: NOT PRESENT")
        
        # Highlight Primary Key and SEND_KEY status
        if has_key and formatted_key:
            print(f"\nSEND_KEY: TRUE")
            print(f"Primary Key:")
            if formatted_key['string']:
                print(f"  String: {formatted_key['string']}")
            if formatted_key['integer'] is not None:
                print(f"  Integer: {formatted_key['integer']}")
            print(f"  Hex: {formatted_key['hex']}")
        else:
            print(f"\nSEND_KEY: FALSE (Primary key not sent)")
        
        print(f"\n--- METADATA ---")
        print(f"Generation: {msg_header['generation']}")
        print(f"Record TTL: {msg_header['record_ttl']} seconds")
        print(f"Transaction TTL: {msg_header['transaction_ttl']} milliseconds")
        
        if flags:
            print(f"\n--- FLAGS ---")
            print(f"{', '.join(flags)}")
        
        if operations:
            print(f"\n--- OPERATIONS ({len(operations)}) ---")
            for op in operations:
                print(f"  {op['type_name']}: {op['bin_name']}")
        
        if msg_header['n_fields'] > 0 and self.verbose:
            print(f"\n--- ALL FIELDS ({msg_header['n_fields']}) ---")
            for field in fields:
                print(f"  {field['type_name']}")
        
        return True


def main():
    if len(sys.argv) < 2:
        print("Usage: python aerospike_analyzer.py <pcap_file> [options]")
        print("\nOptions:")
        print("  --port N         : Aerospike port (default: 3000)")
        print("  --type TYPE      : Filter by transaction type (can specify multiple)")
        print("                     Types: READ, WRITE, DELETE, BATCH, SCAN, QUERY")
        print("  --hotkey N       : Enable hot key detection mode (threshold: N+ accesses)")
        print("                     Shows simplified columnar output with digest, tx type, and count")
        print("  --output FILE    : Save hot key report to file")
        print("  --csv            : Save report in CSV format (use with --output)")
        print("  --verbose        : Show debug information")
        print("  --limit N        : Limit output to first N matching packets")
        print("\nExamples:")
        print("  # Detailed packet analysis")
        print("  python aerospike_analyzer.py capture.pcap --type WRITE")
        print("")
        print("  # Hot key detection mode")
        print("  python aerospike_analyzer.py capture.pcap --hotkey 10")
        print("  python aerospike_analyzer.py capture.pcap --type WRITE --hotkey 5")
        print("")
        print("  # Save hot key report to file")
        print("  python aerospike_analyzer.py capture.pcap --hotkey 10 --output hotkeys.txt")
        print("  python aerospike_analyzer.py capture.pcap --hotkey 5 --output hotkeys.csv --csv")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    as_port = 3000
    verbose = False
    limit = None
    filter_types = []
    hotkey_threshold = None
    output_file = None
    csv_format = False
    
    # Parse arguments
    i = 2
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg == '--verbose':
            verbose = True
        elif arg == '--csv':
            csv_format = True
        elif arg == '--limit':
            if i + 1 < len(sys.argv):
                limit = int(sys.argv[i + 1])
                i += 1
        elif arg == '--port':
            if i + 1 < len(sys.argv):
                as_port = int(sys.argv[i + 1])
                i += 1
        elif arg == '--type':
            if i + 1 < len(sys.argv):
                filter_types.append(sys.argv[i + 1])
                i += 1
        elif arg == '--hotkey':
            if i + 1 < len(sys.argv):
                hotkey_threshold = int(sys.argv[i + 1])
                i += 1
        elif arg == '--output':
            if i + 1 < len(sys.argv):
                output_file = sys.argv[i + 1]
                i += 1
        i += 1
    
    # Enable hotkey mode if threshold is specified
    hotkey_mode = hotkey_threshold is not None
    if hotkey_threshold is None:
        hotkey_threshold = 10  # Default threshold even if not in hotkey mode
    
    print(f"Analyzing Aerospike traffic on port {as_port} from {pcap_file}")
    if filter_types:
        print(f"Filtering by transaction type(s): {', '.join(filter_types)}")
    if hotkey_mode:
        print(f"Hot key detection mode: ENABLED (threshold: {hotkey_threshold} accesses)")
        print(f"Simplified output - detailed packet info suppressed")
    if output_file:
        print(f"Report will be saved to: {output_file} ({'CSV' if csv_format else 'TEXT'} format)")
    if limit:
        print(f"Output limited to first {limit} matching packets")
    if verbose:
        print("Verbose mode: ON")
    print(f"{'='*80}\n")
    
    parser = AerospikeProtocolParser(verbose=verbose, filter_types=filter_types, 
                                      hotkey_threshold=hotkey_threshold, hotkey_mode=hotkey_mode)
    packet_count = 0
    as_packet_count = 0
    filtered_count = 0
    total_packets = 0
    
    try:
        if not hotkey_mode:
            print("Opening pcap file (streaming mode)...")
        reader = PcapReader(pcap_file)
        
        for pkt in reader:
            total_packets += 1
            
            # Progress indicator every 10000 packets
            if total_packets % 10000 == 0:
                status = f"Processed {total_packets} packets"
                if hotkey_mode:
                    status += f", tracking {len(parser.digest_counts)} unique digests..."
                else:
                    status += f", found {filtered_count} matching Aerospike packets..."
                print(status, end='\r')
            
            if TCP in pkt and (pkt[TCP].sport == as_port or pkt[TCP].dport == as_port):
                if len(pkt[TCP].payload) > 0:
                    packet_count += 1
                    direction = "CLIENT->SERVER" if pkt[TCP].dport == as_port else "SERVER->CLIENT"
                    timestamp = pkt.time if hasattr(pkt, 'time') else 'N/A'
                    
                    try:
                        if parser.analyze_packet(packet_count, direction, bytes(pkt[TCP].payload), timestamp):
                            as_packet_count += 1
                            filtered_count += 1
                            
                            # Check limit
                            if limit and filtered_count >= limit:
                                print(f"\nReached limit of {limit} matching packets. Stopping.")
                                break
                    except Exception as e:
                        if verbose:
                            print(f"\nError parsing packet #{packet_count}: {e}")
                            import traceback
                            traceback.print_exc()
        
        reader.close()
        
    except FileNotFoundError:
        print(f"Error: File '{pcap_file}' not found")
        sys.exit(1)
    except Exception as e:
        print(f"\nError reading pcap file: {e}")
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)
    
    print(f"\n{'='*80}")
    print(f"Analysis complete.")
    print(f"Total packets processed: {total_packets}")
    print(f"TCP packets on port {as_port}: {packet_count}")
    print(f"Aerospike messages decoded: {as_packet_count}")
    print(f"Unique digests seen: {len(parser.digest_counts)}")
    
    if filter_types:
        print(f"Matching filtered packets: {filtered_count}")
    print(f"{'='*80}")
    
    # Display hot key summary
    hotkeys = parser.get_hotkey_summary()
    if hotkey_mode or hotkeys:
        parser.print_hotkey_table(hotkeys, output_file=output_file, csv_format=csv_format)
    
    if as_packet_count == 0:
        print(f"\nNo Aerospike traffic found on port {as_port}.")
        print(f"Try running with --verbose to see what's being skipped.")
        print(f"Or check if Aerospike is using a different port.")
    elif filter_types and filtered_count == 0:
        print(f"\nNo packets matched filter: {', '.join(filter_types)}")


if __name__ == "__main__":
    main()
