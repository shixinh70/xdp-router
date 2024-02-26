#!/bin/bash



if [ "$#" -eq 0 ]; then
    echo "Usage: $0 <interface>"
    exit 1
fi

interface=$1

tc filter show dev "$interface" egress
