#!/usr/bin/python3

import os
import sys
import csv
import time
import gzip
import datetime
import argparse
import pandas as pd


def init_Parser():
    '''initializes the parser of this script with the needed arguments and returns the parser'''
    parser = argparse.ArgumentParser()

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


def preprocess_netflow(file, ingresslink_dict):
    '''
    selects and renames only the needed columns, converts the dates to Unix Timestamps and applies the peer_src_ip
    '''

    try:
        with gzip.open(file, 'rb') as f:
            df = pd.read_csv(f)
            # print(df.columns)
            # select only needed columns
            df = df[[
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
            df.columns = [
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
            df = df[:-3]

            # convert all dates into unix timestamps
            dates1 = df['ts_start']
            dates2 = df['ts_end']

            conv_dates_1 = []
            conv_dates_2 = []

            for date in dates1:
                date = time.mktime(datetime.datetime.strptime(date, "%Y-%m-%d %H:%M:%S").timetuple())
                conv_dates_1.append(int(str(date).strip(".0")))

            for date in dates2:
                date = time.mktime(datetime.datetime.strptime(date, "%Y-%m-%d %H:%M:%S").timetuple())
                conv_dates_2.append(int(str(date).strip(".0")))

            df['ts_start'] = conv_dates_1
            df['ts_end'] = conv_dates_2

            # detemine the ingress router, from which the netflow was collected by splitting the file name
            peer = file.split('/')[-1].split('_')[1]
            df['peer_src_ip'] = peer
            df['in_iface'] = (f"{file.split('/')[-1].split('_')[2]}_{file.split('/')[-1].split('_')[3]}_"
                              f"{file.split('/')[-1].split('_')[4]}")
        return df
    except ValueError as e:
        print('The Data could not be read. Maybe there was no netflow collected!')
        return pd.DataFrame()


def preprocess_netflows(args, ingresslink_dict):
    '''
    reads all netflow files existing in a folder and runs the preprocessing on them. Finally concatenates them
    to one big dataframe
    '''

    frames = []

    netflows = os.listdir(args.nf)
    netflows = list(filter(lambda file: 'gz' in file, netflows))

    for net in netflows:
        frame = preprocess_netflow(args.nf + net, ingresslink_dict)
        frames.append(frame)

    if len(netflows) == 0:
        concat = pd.DataFrame()
    else:
        concat = pd.concat(frames, axis=0)

    return concat


def create_ingresslink_file(netflow, args, router_ip_lookup_dict):
    '''scraps all occurrences of peer_src_ip, in_iface tuples from netflow and saves in ingress link file'''

    # clean up the ingress link file
    with gzip.open(args.ilf, 'wb') as file:
        file.write("".encode())

    # search through all ips in the collected netflow and note all occurrences of interfaces in ingress link file
    for ip in netflow['peer_src_ip']:
        peer_src_ip = router_ip_lookup_dict[ip]
        ip_df = netflow.query(f'peer_src_ip == "{ip}"')
        ports = ip_df['in_iface'].unique()
        for port in ports:
            with gzip.open(args.ilf, 'ab') as file:
                file.write(f"PEER_SRC_IP={peer_src_ip},IN_IFACE={port},&=1234\n".encode())


if __name__ == '__main__':
    try:
        parser = init_Parser()
        args = parser.parse_args()

        # convert the router mapping to a dict for better handling
        # with open(args.rimf, 'r') as csv_file:
        #     router_ip_mapping_csv = csv.reader(csv_file, delimiter=' ')
        #     router_ip_lookup_dict = {rows[0]: rows[1] for rows in router_ip_mapping_csv}

        ingresslink_dict = {}
        with gzip.open(args.ilf, 'rb') as f:
            for line in f:
                line = line.decode('utf-8').split(",")
                router = line[0].replace("PEER_SRC_IP=", "")
                in_iface = line[1].replace("IN_IFACE=", "")

                ingresslink_dict[f"{router}"] = f"{in_iface}"

        netflows: pd.DataFrame = preprocess_netflows(args, ingresslink_dict)
        if not netflows.empty:
            netflows.sort_values(by=['ts_start'], inplace=True)
            outname = args.outname.replace('.csv.gz', '')  # be save to have no existing file ending with .csv.gz
            netflows.to_csv(
                outname + '.csv.gz',
                index=False,
                compression={'method': 'gzip', 'compresslevel': 1, 'mtime': 1}
            )
            sys.exit(0)
        else:
            sys.exit(1)
    except KeyboardInterrupt:  # catch a possible Keyboard Interrupt to finish the IPD Algorithm correctly
        exit
