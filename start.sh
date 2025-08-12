#!/bin/bash
cd "$(dirname "$0")"   # Change directory to where the script is
while true; do
    echo "Starting node..."
    node index.js
    echo "Node crashed with exit code $? - restarting in 5 seconds..."
    sleep 2
done
