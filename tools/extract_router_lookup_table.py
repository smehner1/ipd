import pandas as pd

# extracts the router_lookup_table from the external_links_config from mini-internet

links_file = '~/WORK/mini-internet/platform/config/external_links_config.txt'

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

router_lookup_table = pd.DataFrame(columns=['ip', 'name'])

for i in range(frame.shape[0]):
    row = frame.iloc[i]
    prefix = row['prefix']
    prefix = prefix.split('/')[0]
    prefix = prefix[:-1]

    src = row['src_router']
    dst = row['dst_router']

    router_lookup_table = pd.concat(
        [
            router_lookup_table,
            pd.DataFrame({'ip': [prefix + str(row['src_as'])], 'name': [src]})
        ],
        ignore_index=True)
    router_lookup_table = pd.concat(
        [
            router_lookup_table,
            pd.DataFrame({'ip': [prefix + '2'], 'name': [dst]})
        ],
        ignore_index=True)

router_lookup_table.to_csv('~/WORK/ipd-implementation/router_lookup_tables/mini-internet.txt', sep=' ', index=False)
