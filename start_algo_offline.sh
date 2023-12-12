#!/bin/bash

conda=$1
file=$2

PYTHON="${conda}/envs/mini-ipd/bin/python3"

tools/extract_ingresslink.sh $conda
$PYTHON tools/extract_router_lookup_table.py

zcat $file | $PYTHON algo_mini-ipd.py \
    -q=0.7 \
    -c4=1 \
    -c6=12 \
    -cidrmax4=28 \
    -cidrmax6=48 \
    -e=120 \
    -t=30 \
    -b=30 \
    -decay=Default
