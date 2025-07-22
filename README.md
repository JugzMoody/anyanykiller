# AnyAnyKiller

A Python tool for analyzing AWS security groups with "any:any" rules and evaluating their actual usage through VPC Flow Logs.

## Overview

AnyAnyKiller helps AWS administrators identify overly permissive security group rules (0.0.0.0/0 to 0.0.0.0/0) and determine if they can be safely removed or restricted based on actual traffic patterns.

## Features

- Identifies security groups with "any:any" rules
- Analyzes VPC Flow Logs to determine actual traffic patterns
- Supports flexible time periods (from minutes to days)
- Provides recommendations on rule modifications
- Handles CloudWatch Logs query limits with intelligent chunking

## Requirements

- Python 3.6+
- boto3
- AWS credentials with permissions for:
  - EC2 (describe security groups, network interfaces)
  - CloudWatch Logs (describe flow logs, query logs)

## Installation

```bash
# Clone the repository or download the script
# Install dependencies
pip install boto3
```

## Usage

```bash
python anyanykiller.py --sg-id sg-12345678 --hours 24 --verbose
```

### Parameters

- `--sg-id`: Security Group ID to analyze
- `--hours`: Time period to analyze (default: 24, supports float values for sub-hour periods)
- `--verbose`: Enable detailed output
- `--max-flows`: Maximum number of flow log entries to retrieve (default: 10000)

## How It Works

1. Retrieves the specified security group configuration
2. Identifies any "any:any" rules (0.0.0.0/0 to 0.0.0.0/0)
3. Finds network interfaces associated with the security group
4. Retrieves VPC Flow Logs for those interfaces
5. Analyzes actual traffic patterns
6. Provides recommendations on rule modifications

## Time Period Handling

The tool intelligently adjusts time chunking based on the specified period:
- 10 minutes or less: 2 chunks
- 30 minutes or less: 3 chunks
- 1 hour or less: 4 chunks
- 6 hours or less: 12 chunks
- Longer periods: 30-minute chunks

This approach helps avoid CloudWatch Logs query limits while providing comprehensive coverage.

## Limitations

- Does not currently analyze security group references
- CloudWatch Logs has query limits that may affect results for busy interfaces
- Requires active flow logging for the VPC, subnet, or network interface

## License

[MIT License](LICENSE)