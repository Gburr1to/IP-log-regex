# IP-log-regex

Regex to document IP attacks in log files.

## About the Project

This project contains regular expressions (regex) and C++ code for identifying and documenting IP addresses associated with attacks in log files.

## Language

- **C++** - Primary programming language

## Usage

The program analyzes log files for suspicious IP addresses and failed login attempts. It uses regular expressions to identify:
- IP addresses with "Connection from" entries
- Failed or invalid user login attempts
- IP addresses within a specific subnet

### Command Line Arguments

The program requires three command-line arguments:

```bash
./program_name <log_file> <reference_ip> <subnet_mask>
```

**Arguments:**
- `<log_file>` - Path to the log file to analyze (e.g., `log2.txt`)
- `<reference_ip>` - A reference IP address in the format `XXX.XXX.XXX.XXX` (e.g., `192.168.1.100`)
- `<subnet_mask>` - Network subnet mask in the format `XXX.XXX.XXX.XXX` (e.g., `255.255.255.0`)

**Example:**
```bash
./ip-log-regex log2.txt 192.168.1.100 255.255.255.0
```

### Output

The program produces three main outputs:
1. **IP addresses** - All detected IP addresses with connection counts
2. **Hackers** - Failed/invalid login attempts with dates and usernames
3. **IP subaddresses** - IP addresses that belong to the specified subnet


## License

This project does not currently have a selected license.

---

Created: March 9, 2026
