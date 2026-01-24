# TCP Port Scanner

This project is a multithreaded TCP port scanner built using Python. It scans a target host to identify open, closed, and filtered ports.

## Features
- Scans a single host
- Supports custom port ranges
- Uses multithreading for faster scanning
- Detects open, closed, and timeout ports
- Logs scan results to a file
- Handles network exceptions safely

## Concepts Learned
- Python Socket Programming
- TCP Connections
- Multithreading using `threading`
- Task management using `Queue`
- Logging scan results
- Exception handling in network programs

## How It Works
The scanner attempts to establish a TCP connection with each port on the target machine.  
If the connection succeeds → the port is **open**.  
If it fails → the port is **closed** or **filtered**.

## Usage

```bash
python portscan.py <host> <start_port> <end_port>
