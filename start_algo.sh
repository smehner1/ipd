#!/bin/bash

# tools/extract_ingresslink.sh
# /home/max/WORK/masterthesis/miniconda3/envs/mini/bin/python3 /home/max/WORK/ipd-implementation/tools/extract_router_lookup_table.py

# tools/collect_netflow.sh | /home/max/WORK/masterthesis/miniconda3/envs/mini/bin/python3 algo.py -q=0.5 -c4=0.00025 -c6=0.00025 -cidrmax4=8 -cidrmax6=8 -e=120 -t=60 -loglevel=10
# tools/collect_netflow_local.sh | /home/max/WORK/masterthesis/miniconda3/envs/mini/bin/python3 algo.py -q=0.5 -c4=0.00025 -c6=0.00025 -cidrmax4=8 -cidrmax6=8 -e=150 -t=60
tools/collect_netflow_local.sh -o 4 | /home/max/WORK/masterthesis/miniconda3/envs/mini/bin/python3 algo_debug.py -q=0.5 -c4=0.00025 -c6=0.00025 -cidrmax4=8 -cidrmax6=8 -e=150 -t=60
