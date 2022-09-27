import pgzip
import gzip
import csv
import sys

ingresslink_file = "/data/slow/mehner/ipd/ingresslink/1605571200.gz"                # if we get more netflow, we should adjust the file 
router_ip_mapping_file="/data/slow/mehner/ipd/router_lookup_tables/1605571200.txt"

t=60

TEST=True
input_path="/data/fast/mehner/ipd/netflow_merged_sorted"
gzfiles=["@000000000000001605556860.gz", "@000000000000001605560460.gz", "@000000000000001605564060.gz", 
         "@000000000000001605567660.gz", "@000000000000001605571260.gz", "@000000000000001605574860.gz", 
         "@000000000000001605578460.gz", "@000000000000001605582060.gz", "@000000000000001605585660.gz", 
         "@000000000000001605589260.gz", "@000000000000001605592860.gz", "@000000000000001605596460.gz", 
         "@000000000000001605600060.gz", "@000000000000001605603660.gz", "@000000000000001605607260.gz", 
         "@000000000000001605610860.gz", "@000000000000001605614460.gz", "@000000000000001605618060.gz", 
         "@000000000000001605621660.gz", "@000000000000001605625260.gz", "@000000000000001605628860.gz", 
         "@000000000000001605632460.gz", "@000000000000001605636060.gz", "@000000000000001605639660.gz", 
         "@000000000000001605643260.gz"]
if TEST: gzfiles=["nf_test.gz"]#10000000

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
with pgzip.open("{}".format(ingresslink_file), 'rb') as f:
    for line in f:
        line = line.decode('utf-8').split(",")
        router= line[0].replace("PEER_SRC_IP=", "")
        in_iface= line[1].replace("IN_IFACE=", "")
        
        # ingresslink_list.append("{}.{}".format(router, in_iface))
        ingresslink_dict["{}.{}".format(router, in_iface)] = True
print("  ...done\n")

print(len(ingresslink_dict))

def read_netflow():

    #for gzfile in gzfiles:
    #    with gzip.open(f"{input_path}/{gzfile}", 'rt') as f:
        #with gzip.open(f"{input_path}/{gzfile}", 'rb') as f:
            #for line in f:
            for line in sys.stdin:
                #line = line.decode('utf-8').split(",")
                line = line.rstrip().split(",")

                router_name = router_ip_lookup_dict.get(line[1])
                
                in_iface = line[2]
                
                if len(line) < 15: continue
                
                if line[-3] == "TIMESTAMP_END": continue
                if not ingresslink_dict.get("{}.{}".format(router_name,in_iface), False): continue
                src_ip = line[4]    
                cur_ts = int(int(line[-3]) / t) * t
                #added_counter +=1


                #(cur_ts, "{}.{}".format(router_name,in_iface), src_ip)

if __name__ == '__main__':
    # xx = read_netflow()

    # for i in xx:
    #     pass

    for line in sys.stdin:
    #line = line.decode('utf-8').split(",")
        line = line.rstrip().split(",")

        router_name = router_ip_lookup_dict.get(line[1])
        
        in_iface = line[2]
        
        if len(line) < 15: continue
        
        if line[-3] == "TIMESTAMP_END": continue
        if not ingresslink_dict.get("{}.{}".format(router_name,in_iface), False): continue
        src_ip = line[4]    
        cur_ts = int(int(line[-3]) / t) * t
        #added_counter +=1


    #(cur_ts, "{}.{}".format(router_name,in_iface), src_ip)