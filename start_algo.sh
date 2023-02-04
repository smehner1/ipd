#!/bin/bash

tools/extract_ingresslink.sh
/home/max/WORK/masterthesis/miniconda3/envs/mini/bin/python3 /home/max/WORK/ipd-implementation/tools/extract_router_lookup_table.py

tools/collect_netflow.sh | /home/max/WORK/masterthesis/miniconda3/envs/mini/bin/python3 algo.py -q 0.51 -c4 1 -c6 1 -cidrmax4 24 -cidrmax6 48 -e 500 -t 60
