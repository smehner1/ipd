#!/usr/bin/python3

import os
import sys
import datetime
import argparse
import pandas as pd


def init_parser() -> argparse.ArgumentParser:
    '''initializes the parser of this script with the needed arguments and returns the parser'''
    parser: argparse.ArgumentParser = argparse.ArgumentParser()

    parser.add_argument('-nf',
                        type=str,
                        help='directory path where the collected netflow is stored',
                        )
    parser.add_argument('-outname',
                        default='preprocessed_netflow',
                        type=str,
                        help='the name of the final output without .csv.gz',
                        )

    return parser


def preprocess_netflow(file: str) -> pd.DataFrame:
    '''
    selects and renames only the needed columns, converts the dates to Unix Timestamps and applies the peer_src_ip

    Arguments
    ---------
    file (str): path to netflow file to preprocess

    Returns
    -------
    df (DataFrame): preprocessed netflow for one file
    '''
    try:
        df: pd.DataFrame = pd.read_csv(
            file,
            compression='gzip',
            dtype=object)

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

        # remove all rows with a src_ip from 179.0....
        df.drop(df[df['src_ip'].str.contains('179.')].index, inplace=True)
        # remove all rows with port 768 (ICMP port unreachable)
        df.drop(df.query('out_iface == "768"').index, inplace=True)

        return df
    except ValueError:
        # print('The Data could not be read. Maybe there was no netflow collected!')
        return pd.DataFrame()


def preprocess_netflows(netflow_dir: str) -> pd.DataFrame:
    '''
    reads all netflow files existing in a folder and runs the preprocessing on them. Finally concatenates them
    to one big dataframe

    Arguments
    ---------
    netflow_dir (str): path to directory that includes the netflow files

    Returns
    -------
    concat (DataFrame): Frame with preprocessed netflow from all routers
    '''
    frames: list = []  # list that will include the netflow frames

    netflows: list = os.listdir(netflow_dir)
    netflows: list = list(filter(lambda file: 'gz' in file, netflows))

    for net in netflows:
        frame: pd.DataFrame = preprocess_netflow(netflow_dir + net)
        frames.append(frame)

    if len(netflows) == 0:
        concat: pd.DataFrame = pd.DataFrame()
    else:
        concat: pd.DataFrame = pd.concat(frames, axis=0)

    return concat


def main() -> None:
    try:
        parser: argparse.ArgumentParser = init_parser()
        args: argparse.Namespace = parser.parse_args()

        netflows: pd.DataFrame = preprocess_netflows(args.nf)
        if not netflows.empty:
            netflows.sort_values(by=['ts_end'], inplace=True)
            outname: str = args.outname.replace('.csv.gz', '')  # be save to have no existing file ending with .csv.gz
            netflows.to_csv(
                outname + '.csv.gz',
                index=False,
                header=None,
                compression={'method': 'gzip', 'compresslevel': 1, 'mtime': 1}
            )
            # print(len(netflows))
            sys.exit(0)
        else:
            outname: str = args.outname.replace('.csv.gz', '')  # be save to have no existing file ending with .csv.gz
            netflows.to_csv(
                outname + '.csv.gz',
                index=False,
                header=None,
                compression={'method': 'gzip', 'compresslevel': 1, 'mtime': 1}
            )
            # print(len(netflows))
            sys.exit(1)
    except KeyboardInterrupt:  # catch a possible Keyboard Interrupt to finish the IPD Algorithm correctly
        exit


if __name__ == '__main__':
    main()
