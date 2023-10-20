import os
import glob
import argparse

import pandas as pd


def init_parser() -> argparse.ArgumentParser:
    '''initializes a parser for the CLI'''
    parser = argparse.ArgumentParser()
    parser.add_argument('--netdir',
                        help='path to directory with single netflow files',
                        type=str,
                        default='/home/max/WORK/ipd-implementation/netflow/mini/',
                        )

    return parser


def main() -> None:
    parser: argparse.ArgumentParser = init_parser()
    args: argparse.Namespace = parser.parse_args()

    # read all collected netflow files and sort them
    netflow_files: list = glob.glob(f'{args.netdir}/*')
    netflow_files.sort()

    # convert all csv files to dataframes
    frames: list = []
    for file in netflow_files:
        print(file)
        try:
            try:
                frames.append(pd.read_csv(file, compression='gzip', header=None))
            except pd.errors.EmptyDataError as e:
                continue
        except IsADirectoryError as e:
            continue

    # connect them all together
    connected: pd.DataFrame = pd.concat(frames, ignore_index=True)

    # save with start and end date of collection range
    start: str = netflow_files[0].split('/')[-1].split('.')[0].split('_')[-1]
    end: str = netflow_files[-1].split('/')[-1].split('.')[0].split('_')[-1]
    connected.to_csv(
        f'{args.netdir}/../netflow-{start}_{end}.csv.gz',
        header=None,
        index=False,
        compression='gzip'
    )

    for file in netflow_files:
        os.popen(f'rm -f {file}')


if __name__ == '__main__':
    main()
