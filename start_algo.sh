#!/bin/bash

PYTHON="/home/max/WORK/masterthesis/miniconda3/envs/mini/bin/python3"

tools/extract_ingresslink.sh
$PYTHON tools/extract_router_lookup_table.py

$PYTHON tools/netflow_collector.py | $PYTHON algo_debug.py \
    -q=0.7 \
    -c4=1 \
    -c6=12 \
    -cidrmax4=28 \
    -cidrmax6=48 \
    -e=120 \
    -t=30 \
    -b=30 \
    -decay=Default

$PYTHON tools/connect_netflow.py
