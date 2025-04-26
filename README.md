# Ecole42Paris_ft_ping

A custom implementation of the `ping` command for Ecole 42 Paris, based on inetutils-2.0-ping.

## Overview

This project is a recreation of the classic network utility `ping` that tests the reachability of a host on an Internet Protocol (IP) network. The implementation uses raw sockets to send ICMP echo request packets to target hosts and processes the ICMP echo reply messages.

## Features

- Sends ICMP echo requests to specified hosts
- Calculates and displays round-trip time statistics
- Supports customizable TTL, timeout, and packet count
- Displays detailed packet information in verbose mode
- Handles time exceeded ICMP messages
- Properly calculates packet loss percentage
- Provides min/avg/max/stddev round-trip time metrics

## Supported Options

| Option | Long Option | Description |
|--------|-------------|-------------|
| `-?` | `--help` | Display help information |
| | `--usage` | Display usage information |
| `-v` | `--verbose` | Verbose output, display detailed packet information |
| | `--ttl` | Set the IP Time To Live field |
| `-w` | `--timeout` | Set the maximum time to wait for a response |
| `-W` | `--linger` | Set the time to wait for each response |
| `-c` | `--count` | Stop after sending and receiving count packets |
| `-q` | `--quiet` | Quiet output, only display summary |

## Usage

```sh
make
sudo ./ft_ping [-vcwWq --ttl] <hostname>
```
## Implementation Details

- Uses raw sockets with ICMP protocol
- Implements RFC 1071 checksum calculation
- Uses getaddrinfo() for DNS resolution
- Handles various ICMP message types
- Uses the Welford algorithm for incremental calculation of mean and variance
- Properly formats output similar to the original ping utility

## Requirements

- GCC or Clang compiler
- Linux environment (requires root privileges to create raw sockets)

## Notes

- This program requires root privileges to create raw sockets
- Based on inetutils-2.0-ping implementation
- Created as part of the Ecole 42 Paris curriculum
