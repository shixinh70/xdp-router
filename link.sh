#!/bin/bash

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <interface> <enable/disable>"
    exit 1
fi

interface="$1"
action="$2"


if [ "$action" != "0" ] && [ "$action" != "1" ]; then
    echo "Invalid action. Use '0' to disable or '1' to enable."
    exit 1
fi


if [ "$action" -eq 1 ]; then
    eval "ip link set $interface xdpgeneric object ./router.o"
elif [ "$action" -eq 0 ]; then
    eval "ip link set $interface xdpgeneric off"
fi
