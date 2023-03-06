#!/usr/bin/python3

import os
import sys
import csv
import time
import gzip
import datetime
import argparse
import pandas as pd
from datetime import datetime as dt


def init_Parser() -> argparse.ArgumentParser:
    '''initializes the parser of this script with the needed arguments and returns the parser'''
    parser: argparse.ArgumentParser = argparse.ArgumentParser()

    # FYI: Change the default Values for your system
    parser.add_argument(
        '-nf',
        default='/home/max/WORK/netflow_collection/netflows_test/',
        type=str,
        help='directory path where the collected netflow is stored',
    )
    parser.add_argument(
        '-ilf',
        default='/home/max/WORK/ipd-implementation/ingresslink/mini-internet.gz',
        type=str,
        help='the path to the ingresslink_file in which the ingress links will be saved',
    )
    parser.add_argument(
        '-rimf',
        default='/home/max/WORK/ipd-implementation/router_lookup_tables/mini-internet.txt',
        type=str,
        help='path to the touter_lookup_table',
    )
    parser.add_argument(
        '-outname',
        default='preprocessed_netflow.csv.gz',
        type=str,
        help='the name of the final output without .csv.gz',
    )

    return parser


def preprocess_netflow(file: str) -> pd.DataFrame:
    '''
    selects and renames only the needed columns, converts the dates to Unix Timestamps and applies the peer_src_ip
    '''

    try:
        with gzip.open(file, 'rb') as f:
            df: pd.DataFrame = pd.read_csv(f)
            # select only needed columns
            df: pd.DataFrame = df[[
                'smk',
                'dmk',
                'sp',
                'dp',
                'sa',
                'da',
                'sp',
                'dp',
                'pr',
                'flg',
                'td',
                'ts',
                'te',
                'ipkt',
                'ibyt'
            ]]
            # rename the columns corresponding to the needed names of algo.py
            df.columns: list = [
                'tag',
                'peer_src_ip',
                'in_iface',
                'out_iface',
                'src_ip',
                'dst_net',
                'src_port',
                'dst_port',
                'proto',
                '__',
                '_',
                'ts_start',
                'ts_end',
                'pkts',
                'bytes'
            ]
            # remove summarization
            df: pd.DataFrame = df[:-3]

            # convert all dates into unix timestamps
            dates1: pd.Series = df['ts_start']
            dates2: pd.Series = df['ts_end']

            conv_dates_1: list = []
            conv_dates_2: list = []

            # TODO: check ob hier alles richtig läuft
            for date in dates1:
                date: int = int(datetime.datetime.strptime(date, '%Y-%m-%d %H:%M:%S').timestamp())
                conv_dates_1.append(int(str(date)))

            for date in dates2:
                date: int = int(datetime.datetime.strptime(date, '%Y-%m-%d %H:%M:%S').timestamp())
                conv_dates_2.append(int(str(date)))

            df['ts_start'] = conv_dates_1
            df['ts_end'] = conv_dates_2

            # detemine the ingress router, from which the netflow was collected by splitting the file name
            peer: str = file.split('/')[-1].split('_')[1]
            df['peer_src_ip'] = peer
            df['in_iface'] = (f"{file.split('/')[-1].split('_')[2]}_{file.split('/')[-1].split('_')[3]}_"
                              f"{file.split('/')[-1].split('_')[4]}")
        return df
    except ValueError as e:
        print('The Data could not be read. Maybe there was no netflow collected!')
        return pd.DataFrame()


def preprocess_netflows(args: argparse.Namespace) -> pd.DataFrame:
    '''
    reads all netflow files existing in a folder and runs the preprocessing on them. Finally concatenates them
    to one big dataframe
    '''

    frames: list = []  # list that will include the netflow frames

    netflows: list = os.listdir(args.nf)
    netflows: list = list(filter(lambda file: 'gz' in file, netflows))

    for net in netflows:
        frame: pd.DataFrame = preprocess_netflow(args.nf + net)
        frames.append(frame)

    if len(netflows) == 0:
        concat: pd.DataFrame = pd.DataFrame()
    else:
        concat: pd.DataFrame = pd.concat(frames, axis=0)

    return concat


if __name__ == '__main__':
    try:
        parser: argparse.ArgumentParser = init_Parser()
        args: argparse.Namespace = parser.parse_args()

        netflows: pd.DataFrame = preprocess_netflows(args)
        if not netflows.empty:
            netflows.sort_values(by=['ts_start'], inplace=True)
            outname: str = args.outname.replace('.csv.gz', '')  # be save to have no existing file ending with .csv.gz
            netflows.to_csv(
                outname + '.csv.gz',
                index=False,
                compression={'method': 'gzip', 'compresslevel': 1, 'mtime': 1}
            )
            sys.exit(0)
        else:
            outname: str = args.outname.replace('.csv.gz', '')  # be save to have no existing file ending with .csv.gz
            netflows.to_csv(
                outname + '.csv.gz',
                index=False,
                compression={'method': 'gzip', 'compresslevel': 1, 'mtime': 1}
            )
            sys.exit(1)
    except KeyboardInterrupt:  # catch a possible Keyboard Interrupt to finish the IPD Algorithm correctly
        exit
