#!/bin/bash
# This script runs the reconsan.py script with the specified parameters.
# Usage: ./run.sh <IP_ADDRESS> <START_PORT> <END_PORT> <TIMEOUT> <VERBOSE>
# Example: ./run.sh
python Recon.py 192.168.1.10 -s 20 -e 1000 -t 200 -v