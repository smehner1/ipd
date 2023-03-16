import pandas as pd 
import csv
import gzip
from netaddr import *
from collections import defaultdict
from multiprocessing import Pool
import os

PROCS = 50
chunksize=10000
cols=['tag', 'peer_src_ip', 'in_iface', 'out_iface', 'src_ip', 'dst_net', 'src_port', 'dst_port', 'proto', '__', '_', 'ts_start', 'ts_end', 'pkts', 'bytes']

# netflow_path="/data/slow/mehner/netflow/dummy_netflow.gz"
ingresslink_file = "/data/slow/mehner/ipd/ingresslink/1605571200.gz"                # if we get more netflow, we should adjust the file 
router_ip_mapping_file="/data/slow/mehner/ipd/router_lookup_tables/1605571200.txt"

###################################################
########### ROUTER NAME <--> IP MAPPING ###########
###################################################
with open(router_ip_mapping_file, 'r') as csv_file:
    router_ip_mapping_csv = csv.reader(csv_file, delimiter=' ')
    router_ip_lookup_dict = {rows[0]:rows[1] for rows in router_ip_mapping_csv}

###################################################
###########     INGRESS LINK FILE       ###########
###################################################

print("> load ingresslink file")

ingresslink_dict= {}
with gzip.open("{}".format(ingresslink_file), 'rb') as f:
    for line in f:
        line = line.decode('utf-8').split(",")
        router= line[0].replace("PEER_SRC_IP=", "")
        in_iface= line[1].replace("IN_IFACE=", "")
        
        # ingresslink_list.append("{}.{}".format(router, in_iface))
        ingresslink_dict["{}.{}".format(router, in_iface)] = True
print("  ...done\n")


def dump_netflow_to_pandas(netflow_file):
    nf_ps=netflow_file.split("/")[-3]
    nf_ts=netflow_file.split("/")[-1].replace(".gz","").replace("@00000000000000","")

    os.makedirs("/data/slow/mehner/ipd/netflow_preprocessed", exist_ok=True)
    filename = f"/data/slow/mehner/ipd/netflow_preprocessed/{nf_ps}_{nf_ts}"

    if os.path.exists(filename) and os.path.getsize(filename) > 0:
        print(f"file {filename} already exists - skip")
        return False

    print(f"--> {filename}")
    # TAG     PEER_SRC_IP  IN IFACE OUT_IFACE SRC_IP          DST_NET        SRC_PORT DST_PORT PROTO  _       _       TS_START        TS_END    PKTS    BYTES
    # 0       194.25.7.141    13      1571    91.127.69.122   31.13.84.4      40730   443     tcp     0       i       1605639641      1605639641 1       121
    #netflow_df = pd.read_csv(netflow_file, compression='gzip', header=None, sep=',', quotechar='"', on_bad_lines='skip', names=cols, usecols = ['peer_src_ip', 'in_iface', 'src_ip', 'ts_end'], chunksize=100000)

    netflow_df = pd.DataFrame()
    for i, chunk in enumerate(pd.read_csv(netflow_file, compression='gzip', header=None, sep=',', quotechar='"', names=cols, usecols = ['peer_src_ip', 'in_iface', 'src_ip', 'ts_end'], chunksize=chunksize, low_memory=False)):
        netflow_df = pd.concat([netflow_df, chunk])




    print("read: ", len(netflow_df))

    ## pandas pipe  -> https://towardsdatascience.com/25-pandas-functions-you-didnt-know-existed-p-guarantee-0-8-1a05dcaad5d0
    netflow_df['ingress_router'] = netflow_df.peer_src_ip.apply(lambda x: router_ip_lookup_dict.get(x))
    netflow_df['ingress'] = netflow_df['ingress_router'] + "." + netflow_df.in_iface.astype(str)
    netflow_df.drop(columns=['ingress_router', 'peer_src_ip', 'in_iface'], inplace=True)

    netflow_df.drop(netflow_df.index[netflow_df['ts_end'] == 'TIMESTAMP_END'], inplace=True)

    netflow_df['is_ingresslink'] = netflow_df.ingress.apply(lambda x: ingresslink_dict.get(x,False))
    netflow_df = netflow_df.loc[netflow_df.is_ingresslink]
    
    netflow_df.drop(columns=['is_ingresslink'], inplace=True)
    print("ingress only: ", len(netflow_df))

    # netflow_df['ts_end'] = netflow_df.ts_end.apply(lambda x: int(int(x) #/ t) * t) 
    #netflow_df.sort_values(by = 'ts_end', inplace=True)  

    # mask to cidr max
    #netflow_df['src_ip'] = netflow_df.src_ip.apply(lambda x: str(ipaddress.ip_network("{}/{}".format(x, cidr_max), strict=False)).split("/")[0])

    netflow_df = netflow_df.convert_dtypes()
    
    # TODO bin to time; mask ip not done in this step


    
    print(netflow_df.head())
    netflow_df.to_csv(f"{filename}.csv", index=False, header=False)
    try:
        netflow_df.to_parquet(f"{filename}.parquet")
    except:
         print("ERROR: dump netflow to paquet not possible")
    # #netflow_df.to_parquet(filename, compression='gzip')

    print(f"<-- {filename}")
    return True


###################################################
###########             MAIN            ###########
###################################################
if __name__ == "__main__":
    netflow_files=[]
    for i in range(0,26):
        # netflow_files.append("/data/slow/mehner/netflow_preprocessed/parser_{:02d}/archived/@000000000000001605639660.gz".format(i))
        # netflow_files.append("/data/slow/mehner/netflow_preprocessed/parser_{:02d}/archived/@000000000000001605643260.gz".format(i))
        netflow_files.append("/data/slow/mehner/ipd/netflow_recording/parser_{:02d}/archived/@000000000000001605556860.gz".format(i))
        netflow_files.append("/data/slow/mehner/ipd/netflow_recording/parser_{:02d}/archived/@000000000000001605560460.gz".format(i))
        netflow_files.append("/data/slow/mehner/ipd/netflow_recording/parser_{:02d}/archived/@000000000000001605564060.gz".format(i))
        netflow_files.append("/data/slow/mehner/ipd/netflow_recording/parser_{:02d}/archived/@000000000000001605567660.gz".format(i))
        netflow_files.append("/data/slow/mehner/ipd/netflow_recording/parser_{:02d}/archived/@000000000000001605571260.gz".format(i))
        netflow_files.append("/data/slow/mehner/ipd/netflow_recording/parser_{:02d}/archived/@000000000000001605574860.gz".format(i))
        netflow_files.append("/data/slow/mehner/ipd/netflow_recording/parser_{:02d}/archived/@000000000000001605578460.gz".format(i))
        netflow_files.append("/data/slow/mehner/ipd/netflow_recording/parser_{:02d}/archived/@000000000000001605582060.gz".format(i))
        netflow_files.append("/data/slow/mehner/ipd/netflow_recording/parser_{:02d}/archived/@000000000000001605585660.gz".format(i))
        netflow_files.append("/data/slow/mehner/ipd/netflow_recording/parser_{:02d}/archived/@000000000000001605589260.gz".format(i))
        netflow_files.append("/data/slow/mehner/ipd/netflow_recording/parser_{:02d}/archived/@000000000000001605592860.gz".format(i))
        netflow_files.append("/data/slow/mehner/ipd/netflow_recording/parser_{:02d}/archived/@000000000000001605596460.gz".format(i))
        netflow_files.append("/data/slow/mehner/ipd/netflow_recording/parser_{:02d}/archived/@000000000000001605600060.gz".format(i))
        netflow_files.append("/data/slow/mehner/ipd/netflow_recording/parser_{:02d}/archived/@000000000000001605603660.gz".format(i))
        netflow_files.append("/data/slow/mehner/ipd/netflow_recording/parser_{:02d}/archived/@000000000000001605607260.gz".format(i))
        netflow_files.append("/data/slow/mehner/ipd/netflow_recording/parser_{:02d}/archived/@000000000000001605610860.gz".format(i))
        netflow_files.append("/data/slow/mehner/ipd/netflow_recording/parser_{:02d}/archived/@000000000000001605614460.gz".format(i))
        netflow_files.append("/data/slow/mehner/ipd/netflow_recording/parser_{:02d}/archived/@000000000000001605618060.gz".format(i))
        netflow_files.append("/data/slow/mehner/ipd/netflow_recording/parser_{:02d}/archived/@000000000000001605621660.gz".format(i))
        netflow_files.append("/data/slow/mehner/ipd/netflow_recording/parser_{:02d}/archived/@000000000000001605625260.gz".format(i))
        netflow_files.append("/data/slow/mehner/ipd/netflow_recording/parser_{:02d}/archived/@000000000000001605628860.gz".format(i))
        netflow_files.append("/data/slow/mehner/ipd/netflow_recording/parser_{:02d}/archived/@000000000000001605632460.gz".format(i))
        netflow_files.append("/data/slow/mehner/ipd/netflow_recording/parser_{:02d}/archived/@000000000000001605636060.gz".format(i))
        netflow_files.append("/data/slow/mehner/ipd/netflow_recording/parser_{:02d}/archived/@000000000000001605639660.gz".format(i))
        netflow_files.append("/data/slow/mehner/ipd/netflow_recording/parser_{:02d}/archived/@000000000000001605643260.gz".format(i))

    pool = Pool(processes=PROCS)

    print("> run netflow in multi threads...")
    res= pool.imap(dump_netflow_to_pandas, netflow_files)

    for netflow_parser_result in res:
        print (netflow_parser_result)
        
    pool.close()
    pool.join()
 