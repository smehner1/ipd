#!/bin/bash

conda=$1

PYTHON="${conda}/envs/mini-ipd/bin/python3"
MINIDIR="../mini-internet/"  # directory that includes the mini internet
IPDDIR=$(pwd)  

# read possible flags, otherwise use default values
while getopts "p:m" OPTION; do
    case "$OPTION" in
        p)
            pvalue="$OPTARG"
            PYTHON=$pvalue
            ;;
        m)
            mvalue="$OPTARG"
            MINIDIR=$mvalue
            ;;
        i)
            ivalue="$OPTARG"
            INGRESSDIR=$ivalue
            ;;
        ?)
            echo "script usage: $(basename \$0) [-p python executable] [-m mini internet directory] [-i ipd directory]" >&2
            exit 1
            ;;
    esac
done
shift "$(($OPTIND -1))"

FILE_PATH="$(dirname -- "${BASH_SOURCE[0]}")"            # relative
FILE_PATH="$(cd -- "$FILE_PATH" && pwd)"    # absolute and normalized
if [[ -z "$FILE_PATH" ]] ; then
  exit 1  # fail
fi

$PYTHON $FILE_PATH/extract_ingresslink.py --minidir $MINIDIR --ipddir $IPDDIR
gzip -f $IPDDIR/ingresslink/mini-internet
