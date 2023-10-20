#!/bin/bash

q=$1
c4=$2
c6=$3
cidr4=$4
cidr6=$5

file=$6


PYTHON="/home/max/WORK/masterthesis/miniconda3/envs/mini/bin/python3"

zcat $file | /home/max/WORK/masterthesis/miniconda3/envs/mini/bin/python3 /home/max/WORK/ipd-implementation/algo_debug.py \
    -q=$q \
    -c4=$c4 \
    -c6=$c6 \
    -cidrmax4=$cidr4 \
    -cidrmax6=$cidr6 \
    -e=120 \
    -t=30 \
    -b=30 \
    -decay=default
