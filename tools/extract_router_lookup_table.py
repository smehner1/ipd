import os
import argparse
import pandas as pd


def init_parser() -> argparse.ArgumentParser:
    '''initializes a parser for the CLI'''
    parser = argparse.ArgumentParser()
    parser.add_argument('--ipddir',
                        help='path to directory of IPD',
                        type=str,
                        default=os.getcwd(),
                        )
    parser.add_argument('--minidir',
                        help='path to directory of mini internet',
                        type=str,
                        default='/home/max/WORK/mini-internet/',
                        )

    return parser


def main() -> None:
    parser: argparse.ArgumentParser = init_parser()
    args: argparse.Namespace = parser.parse_args()

    links_file = f'{args.minidir}/platform/config/external_links_config.txt'

    frame: pd.DataFrame = pd.read_csv(links_file, delim_whitespace=True, header=None)
    frame.columns = [
        'src_as',
        'src_router',
        'connection',
        'dst_as',
        'dst_router',
        'connection2',
        'b1',
        'b2',
        'prefix'
    ]

    router_lookup_table: pd.DataFrame = pd.DataFrame(columns=['ip', 'name'])

    for i in range(frame.shape[0]):
        row: pd.Series = frame.iloc[i]
        prefix: str = row['prefix']
        prefix: str = prefix.split('/')[0]

        src: str = row['src_router']
        dst: str = row['dst_router']

        router_lookup_table: pd.DataFrame = pd.concat(
            [
                router_lookup_table,
                pd.DataFrame({'ip': [prefix], 'name': [src]})
            ],
            ignore_index=True)

    router_lookup_table.to_csv(f'{args.ipddir}/router_lookup_tables/mini-internet.txt', sep=' ', index=False)


if __name__ == '__main__':
    main()
