import pandas as pd

# extracts the router_lookup_table from the external_links_config from mini-internet 

links_file = '/home/max/WORK/mini-internet/platform/config/external_links_config.txt'

frame = pd.read_csv(links_file, delim_whitespace=True, header=None)
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

ingress = '/home/max/WORK/ipd-implementation/ingresslink/mini-internet'
ingress_netflow_collector = '/home/max/WORK/ipd-implementation/ingresslink/mini-internet-test.txt'

file = open(ingress, 'w')
file = open(ingress, 'a')

file2 = open(ingress_netflow_collector, 'w')
file2 = open(ingress_netflow_collector, 'a')

for i in range(frame.shape[0]):
    row = frame.iloc[i]
    src_router = row['src_router']
    dst_router = row['dst_router']
    dst_as = row['dst_as']

    line = f'PEER_SRC_IP={src_router},IN_IFACE=ext_{dst_as}_{dst_router},&={dst_as}\n'
    file.write(line)
    line = f'PEER_SRC_IP={src_router}    IN_IFACE=ext_{dst_as}_{dst_router}    &=1\n'
    file2.write(line)
