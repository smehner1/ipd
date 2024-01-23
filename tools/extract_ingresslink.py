import os
import argparse
import pandas as pd

EGRESS_LINKS: list = [('BERL', 'NEWY', 2), ('NEWY', 'NEWY', 3), ('SANF', 'SANF', 4), ('SAOP', 'SANF', 5)]
CENTER_AS: int = 1


def init_parser() -> argparse.ArgumentParser:
    '''initializes a parser for the CLI'''
    parser = argparse.ArgumentParser()
    parser.add_argument('--ipddir',
                        help='path to directory of mini internet',
                        type=str,
                        default=os.getcwd(),
                        )
    parser.add_argument('--minidir',
                        help='path to directory of mini internet',
                        type=str,
                        default='../mini-internet',
                        )

    return parser


def extract_ingresslinks() -> None:
    '''extracts based on Mini Internet config the ingresslink file needed for the IPD and as txt'''
    parser: argparse.ArgumentParser = init_parser()
    args: argparse.Namespace = parser.parse_args()

    links_file = f'{args.minidir}/platform/config/external_links_config.txt'
    links: pd.DataFrame = pd.read_csv(links_file, delim_whitespace=True, header=None)
    links.columns = [
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

    links.query(f'src_as == {CENTER_AS}', inplace=True)

    ingress: str = f'{args.ipddir}/ingresslink/mini-internet'
    ingress_netflow_collector: str = f'{args.ipddir}/ingresslink/mini-internet.txt'

    file = open(ingress, 'w')
    file = open(ingress, 'a')

    file2 = open(ingress_netflow_collector, 'w')
    file2 = open(ingress_netflow_collector, 'a')

    for i in range(links.shape[0]):
        row = links.iloc[i]
        src_router: str = row['src_router']
        dst_router: str = row['dst_router']
        dst_as: int = row['dst_as']

        if (src_router, dst_router, dst_as) not in EGRESS_LINKS:
            line: str = f'PEER_SRC_IP={src_router},IN_IFACE=ext_{dst_as}_{dst_router},&={dst_as}\n'
            file.write(line)

            line: str = f'PEER_SRC_IP={src_router}    IN_IFACE=ext_{dst_as}_{dst_router}    &=1\n'
            file2.write(line)


if __name__ == '__main__':
    extract_ingresslinks()
