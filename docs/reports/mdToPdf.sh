#!/bin/bash

if [ $# -ne 2 ]; then
    echo "Usage: $0 input_file output_file"
    exit 1
fi

pandoc -H conf.tex "$1" -o "$2" --filter=mermaid-filter

