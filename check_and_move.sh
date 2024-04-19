#!/bin/bash

if [ "$(ls -A ./processed_packets)" ]; then
    mv ./processed_packets/* packets
fi
