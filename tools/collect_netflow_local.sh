#!/bin/bash

# echo "##### STARTING NETFLOW COLLECTION #####"

# the time (in sec) between each lookup for new netflow (should be the same like the nfdump interval)
# INTERVAL=60  # given in seconds
INTERVAL=300  # given in seconds
# the AS from which the netflow should be collected
AS=1

# flag to detemine if debug output should be shown
TEST=0
VERBOSE=0

# read possible flags, otherwise use default values
while getopts "o:i:a:tv" OPTION; do
    case "$OPTION" in
        o)
            ivalue="$OPTARG"
            FIRST=$ivalue
            ;;
        i)
            ivalue="$OPTARG"
            INTERVAL=$ivalue
            ;;
        a)
            avalue="$OPTARG"
            AS=$avalue
            ;;
        t)
            TEST=1
            ;;
        v)
            VERBOSE=1
            ;;
        ?)
            echo "script usage: $(basename \$0) [-i intervaltime] [-a asnumber] [-t] [-v]" >&2
            exit 1
            ;;
    esac
done
shift "$(($OPTIND -1))"

# the file that includes a table with the AS, the ingress routers and their interfaces
IPD="/home/max/WORK/ipd-implementation/ingresslink/mini-internet.txt"
# path to where the collected netflow should be saved
# COLLECTOR_LOCATION="/home/max/WORK/masterthesis/ipd/test_netflow"
COLLECTOR_LOCATION="/home/max/WORK/ipd-implementation/netflow/mini"

function collect_netflow {
    # ------------------------------------------------------------------------------------------------------------------
    #     read the router/interface/as     -----------------------------------------------------------------------------
    # ------------------------------------------------------------------------------------------------------------------
    lines=()

    readarray -t moini < "${IPD}"

    # extract the lines
    for m in "${moini[@]}"
    do
        row=($m)
        peer="${row[0]:12}"
        inface="${row[1]:9}"
        as="${row[2]:2}"
        src=($as, $peer, $inface)
        if [ $TEST == 1 ]; then
            echo "------------ INFO ------------"
            echo "| ACCESS AT ROUTER: " $peer
            echo "| USED INTERFACE:   " $inface
            echo "| IN AS:            " $as
            echo "------------ ENDE ------------"
            echo
            echo "Go into Folder of Router $peer from AS $as and get netflow for port $inface"
            echo "${src[@]}"
            echo
        fi

        lines+=(${src[@]})
    done

    num_lines="${#lines[@]}"

    # check if array length is a multiple of 3 --> TODO: why?
    if [ $((num_lines % 3)) != 0 ]; then
        echo " !!!!! WARNING: wrong number of elements in array !!!!! "
    fi

    # ------------------------------------------------------------------------------------------------------------------
    #     extract time information     ---------------------------------------------------------------------------------
    # ------------------------------------------------------------------------------------------------------------------

    # extract the current day, month and year
    DAY=$(date +%D)
    DAY=${DAY//"/"/" "}
    DAY_ARR=($DAY)

    MONTH=${DAY_ARR[0]}
    DAY=${DAY_ARR[1]}
    DAY=$(sed 's/^0*//'<<< $DAY)  # remove leading zero
    YEAR="20"${DAY_ARR[2]}

    # extract current hour and minute
    TIME=$(date +"%-H:%-M:%S")
    TIME=${TIME//":"/" "}
    TIME_ARR=($TIME)

    if [ $VERBOSE == 1 ]; then
        echo "| ${TIME_ARR[@]}"
    fi

    HOUR=${TIME_ARR[0]}
    # HOUR=14
    MIN=${TIME_ARR[1]}
    MIN=$((MIN))

    if [ $MIN -lt 10 ]; then
        MIN=0${MIN}
    fi

    # MIN="15"
    # echo ${HOUR}:${MIN}

    # bring minute to wanted interval minute (e.g. 2 and 7 for interval of 5 min)
    LAST_NUM=${MIN:1:1}
    LAST_NUM=$((LAST_NUM))
    # echo $LAST_NUM
    if [ $LAST_NUM == 0 ]; then
        LAST_NUM=1$LAST_NUM
    fi

    # FIRST=2
    LAST=$((FIRST+5))  # =7

    # echo $LAST_NUM
    if [ $LAST_NUM != $FIRST ] || [ $LAST_NUM != $LAST ]; then
        offset=$((LAST_NUM-FIRST))
        if [ $offset -lt 0 ]; then
            offset=$((offset+5))
        else
            offset=$((offset%5))
        fi
    else
        offset=0
    fi

    # echo $offset
    # echo $MIN
    MIN=$(sed 's/^0*//'<<< $MIN)  # remove leading zero
    MIN=$((MIN-offset))
    # echo $MIN

    # set MIN 5 minutes back
    MIN=$((MIN-5))
    # echo $MIN

    if [ ${MIN} -lt 0 ]; then
        MIN=$((MIN+60))
        HOUR=$((HOUR-1))
    fi

    if [ ${HOUR} -lt 0 ]; then
        HOUR=$((HOUR+24))
        DAY=$((DAY-1))
    fi

    if [ $TEST == 1 ]; then
        echo
        echo $HOUR
        echo $MIN
        echo
        echo $DAY
        echo $MONTH
        echo $YEAR
        echo
    fi

    # ------------------------------------------------------------------------------------------------------------------
    #     get the files from containers     ----------------------------------------------------------------------------
    # ------------------------------------------------------------------------------------------------------------------

    if [ ${DAY} -lt 10 ]; then
        DAY=0${DAY}
    fi

    if [ ${MIN} -lt 10 ]; then
        if [ ${HOUR} -lt 10 ]; then
            SRC_FILE=${YEAR}${MONTH}${DAY}0${HOUR}0${MIN}
        else
            SRC_FILE=${YEAR}${MONTH}${DAY}${HOUR}0${MIN}
        fi
    else
        if [ ${HOUR} -lt 10 ]; then
            SRC_FILE=${YEAR}${MONTH}${DAY}0${HOUR}${MIN}
        else
            SRC_FILE=${YEAR}${MONTH}${DAY}${HOUR}${MIN}
        fi
    fi

    if [ $VERBOSE == 1 ]; then
        echo "|" $SRC_FILE
    fi

    LOCAL_PATH=${COLLECTOR_LOCATION}/${SRC_FILE}/

    # number of interfaces to scrape
    inters=$((num_lines / 3))

    mkdir -p ${LOCAL_PATH}

    # for each interface receive the netflow
    for (( c=0; c<$inters; c++ ))
    do
        lookup=("${lines[@]:$((3*c)):3}")
        if [ $TEST == 1 ]; then
            echo "${lookup[@]}"
            echo "${lookup[0]:0:1}"
            echo "${lookup[1]:0:4}"
            echo "${lookup[2]}"
            echo
        fi

        as="${lookup[0]:0:1}"
        router="${lookup[1]:0:4}"
        inface="${lookup[2]}"

        if [ ${MIN} -lt 10 ]; then
            if [ ${HOUR} -lt 10 ]; then
                DST_FILE=${as}_${router}_${inface}_${YEAR}${MONTH}${DAY}0${HOUR}0${MIN}
            else
                DST_FILE=${as}_${router}_${inface}_${YEAR}${MONTH}${DAY}${HOUR}0${MIN}
            fi
        else
            if [ ${HOUR} -lt 10 ]; then
                DST_FILE=${as}_${router}_${inface}_${YEAR}${MONTH}${DAY}0${HOUR}${MIN}
            else
                DST_FILE=${as}_${router}_${inface}_${YEAR}${MONTH}${DAY}${HOUR}${MIN}
            fi
        fi

        CONTAINER="${as}"_"${router}"router
        # SRC_PATH=/home/netflow/port-${inface}/${YEAR}/${MONTH}/${DAY}
        SRC_PATH=/home/max/WORK/netflow_mini-internet/AS_${as}/${as}_${router}router/port-${inface}/${YEAR}/${MONTH}/${DAY}
        
        if [ $TEST == 1 ]; then
            echo
            echo "----- SCRAPING -----"
            echo $SRC_FILE
            echo $CONTAINER
            echo $SRC_PATH
            echo "${COLLECTOR_LOCATION}"/
            echo "----- FINISHED -----"
            echo
        fi

        LOCAL_FILE=${COLLECTOR_LOCATION}/${SRC_FILE}/nfcapd.${DST_FILE}

        if [ $VERBOSE == 1 ]; then
            echo "|" $LOCAL_FILE
        fi

        # cp ${SRC_PATH}/nfcapd.${SRC_FILE} ${LOCAL_FILE}
        mv ${SRC_PATH}/nfcapd.${SRC_FILE} ${LOCAL_FILE}
        echo ${SRC_PATH}/nfcapd.${SRC_FILE} >> tmp.txt
        # docker cp ${CONTAINER}:${SRC_PATH}/nfcapd.${SRC_FILE}  ${LOCAL_FILE}

        # use nfdump and convert netflow files to .csv.gz to use later in preprocessing
        nfdump -r ${LOCAL_FILE} -o csv | gzip -9 > ${LOCAL_FILE}.csv.gz &
    done

    chmod ugo+rw -R ${COLLECTOR_LOCATION}

    # ----------------------------------------------------------------------------------------------------------------------
    #     preprocess all extracted files     -------------------------------------------------------------------------------
    # ----------------------------------------------------------------------------------------------------------------------

    sleep 10  # TODO: check if this helps solving the error with ENDOFFILE and no such file
    if [ $VERBOSE == 1 ]; then
        echo "|" -- preprocess collected netflow
    fi
    /home/max/WORK/masterthesis/miniconda3/envs/mini/bin/python3 /home/max/WORK/ipd-implementation/tools/preprocess_netflow_local.py -nf ${LOCAL_PATH} -outname ${COLLECTOR_LOCATION}/preprocessed_${SRC_FILE}
    exit_status=$?
    if [ $VERBOSE == 1 ]; then
        echo "|" -- finished preprocessing
    fi

    rm -rf ${LOCAL_PATH}
    # > tmp.txt

    # if we are in the usage case output the resulting preprocessed netflow
    if [ $VERBOSE == 0 ]; then
        # echo "${exit_status}"
        # if [ "${exit_status}" == 1 ]; then
        zcat ${COLLECTOR_LOCATION}/preprocessed_${SRC_FILE}.csv.gz
        # fi
    fi

    # TODO: after printing the data connect it to the already collected data
    # /home/max/WORK/masterthesis/miniconda3/envs/mini/bin/python3 /home/max/WORK/ipd-implementation/tools/connect_netflow.py 0
    # delete the added single netflow file
    # rm ${COLLECTOR_LOCATION}/preprocessed_${SRC_FILE}.csv.gz
}

# infinitly collect every $INTERVAL seconds the netflow
while :
do
    if [ $VERBOSE == 1 ]; then
        echo -------------------------------
        echo "|" Collecting Netflow
    fi
    start=`date +%s`
    collect_netflow
    end=`date +%s`
    exec_time=$((end-start))
    wait=$((INTERVAL-exec_time))

    if [ $wait -lt 0 ]; then
        wait=0
    fi

    if [ $VERBOSE == 1 ]; then
        echo "|" Collected!
        echo "|" sleeping ${wait} seconds!
        echo -------------------------------
        echo
    fi

    sleep "${wait}"
done