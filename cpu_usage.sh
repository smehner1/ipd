#!/bin/bash

DIR=$1

processes=$(ps ax | grep "sudo bash ./start_algo.sh")
ext=( $processes )
pid=${ext[0]}

output=( $(pmap $pid) )
PROCESSRAM=${output[${#output[@]} - 1]}

## CPU usage

CPU=$(mpstat -P ALL 1 1 | awk '/Durchschnitt:/ && $2 ~ /\[0-9\]/ {print $3}')
CPU=$(mpstat -P ALL 1 1 | awk '/Average:/ && $2 {print $3}')

### RAM usage

RAMALL=$(free --human | grep  "Mem:" | awk '{print $3}')

DATE=$(date +%Y-%m-%d\_%H-%M-%S)

# echo "$DATE $RAMALL" $PROCESSRAM $CPU
echo "$DATE $RAMALL" $PROCESSRAM $CPU >> ${DIR}/systemusage.log
