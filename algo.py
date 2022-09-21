import csv
import gzip
import pytricia
from netaddr import *
from collections import defaultdict, namedtuple
import math
import io
import os
import argparse
import logging
import threading
import queue
import time
import json

TEST=False
IPv4_ONLY = False
DUMP_TREE=False

RESULT_PREFIX="_path_string"

IPD_IDLE_BEFORE_START=3
PROCS = 90
DEBUG_FLOW_OUTPUT = 100000
decay_ingmar_bucket_expire_keep_fraction=0.9
linear_decay = 1000

bundle_indicator=".b_"

t=60
bucket_output = t *5
b= 0.05         # allowed delta between bundle load

input_path="/data/fast/mehner/ipd/netflow_merged_sorted"
gzfiles=["@000000000000001605556860.gz", "@000000000000001605560460.gz", "@000000000000001605564060.gz", "@000000000000001605567660.gz", "@000000000000001605571260.gz", "@000000000000001605574860.gz", "@000000000000001605578460.gz", "@000000000000001605582060.gz", "@000000000000001605585660.gz", "@000000000000001605589260.gz", "@000000000000001605592860.gz", "@000000000000001605596460.gz", "@000000000000001605600060.gz", "@000000000000001605603660.gz", "@000000000000001605607260.gz", "@000000000000001605610860.gz", "@000000000000001605614460.gz", "@000000000000001605618060.gz", "@000000000000001605621660.gz", "@000000000000001605625260.gz", "@000000000000001605628860.gz", "@000000000000001605632460.gz", "@000000000000001605636060.gz", "@000000000000001605639660.gz", "@000000000000001605643260.gz"]
if TEST: gzfiles=["nf_test.gz"]#10000000


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

print(len(ingresslink_dict))


class IPD:    
    
    def __subnet_atts(self):
        return {'last_seen': 0,  'ingress' : defaultdict(int), "total" : 0}

    def __multi_dict(self, K, type):
        if K == 1:
            return defaultdict(type)
        else:
            return defaultdict(lambda: self.__multi_dict(K-1, type))

    def __init__(self, params):
        self.read_data_finisehd=False

        print("--- parametrization ---")
        print(f"d {params.d}")
        print(f"c4 {params.c4}")
        print(f"c6 {params.c6}")
        print(f"t {params.t}")
        print(f"b {params.b}")
        print(f"e {params.e}")
        print(f"q {params.q}")
        print(f"cidrmax4 {params.cidrmax4}")
        print(f"cidrmax6 {params.cidrmax6}")
        print(f"decay {params.decay}")
        print(f"loglevel {params.loglevel}")
        print("------------------------")

        # initialization
        self.range_lookup_dict = self.__multi_dict(1, pytricia.PyTricia) #defaultdict(lambda: pytricia.PyTricia())
        self.range_lookup_dict[4].insert("0.0.0.0/0", "0.0.0.0/0")
        self.range_lookup_dict[6].insert("::/0", "::/0")

        self.debug_flow_output_counter = 0
        self.netflow_data_queue= queue.Queue()
        self.min_sample_cache=self.__multi_dict(2, int)
        
        self.subnet_dict= self.__multi_dict(4, self.__subnet_atts)
        self.ipd_cache= self.__multi_dict(4, dict)

        self.bundle_dict={}
        self.d = params.d
        self.t = params.t #60 
        self.e=  params.e #120
        self.q = params.q # 0.80
        self.decay_method=params.decay


        self.cidr_max = {
            4: params.cidrmax4,
            6: params.cidrmax6
        }
        self.c = {
            4: params.c4,
            6: params.c6
        }

        self.output_folder=f"results{RESULT_PREFIX}/q{self.q}_c{self.c[4]}-{self.c[6]}_cidr_max{self.cidr_max[4]}-{self.cidr_max[6]}_t{self.t}_e{self.e}_decay{self.decay_method}"
        self.tree_output_folder=f"/data/slow/mehner/dump/{RESULT_PREFIX}/q{self.q}_c{self.c[4]}-{self.c[6]}_cidr_max{self.cidr_max[4]}-{self.cidr_max[6]}_t{self.t}_e{self.e}_decay{self.decay_method}"
        if TEST: 
            self.output_folder +="_TEST"
            if DUMP_TREE:
                self.tree_output_folder += "_TEST"

        os.makedirs(self.output_folder, exist_ok=True)
        if DUMP_TREE:
            os.makedirs(self.tree_output_folder, exist_ok=True)

        ############################################
        ########### LOGGER CONFIGURATION ###########
        ############################################

        ll = params.loglevel
        #if TEST: ll=logging.DEBUG
        os.makedirs(f"log{RESULT_PREFIX}", exist_ok=True)
        logfile=f"log{RESULT_PREFIX}/q{self.q}_c{self.c[4]}-{self.c[6]}_cidr_max{self.cidr_max[4]}-{self.cidr_max[6]}_t{self.t}_e{self.e}_decay{self.decay_method}"
        if TEST: logfile += "_TEST"
        logfile+=".log"
        logging.basicConfig(filename=logfile,
                        format='%(asctime)s %(levelname)s %(funcName)s %(message)s',
                        # datefmt='%y-%m-%d %H:%M:%S',
                        filemode='w',
                        level=ll)

        # Creating an object
        self.logger = logging.getLogger()



    




    ## lookup in pytricia tree and return corresponding range
    # input: IP str "192.168.0.2"
    # output: range str. "0.0.0.0/0"
    def get_corresponding_range(self, ip):
        ip_version = 4 if not ":" in ip else 6
        
        if ip == "::": return "::/0"

        try:
            res =self.range_lookup_dict[ip_version][ip]
        except:
            self.logger.warning(f"key error: {ip}")
            #self.logger.debug("  current ranges: {}".format(list(self.range_lookup_dict[ip_version])))
            pass

            res="0.0.0.0/0" if ip_version == 4 else "::/0"
        if self.debug_flow_output_counter > DEBUG_FLOW_OUTPUT: 
            self.logger.debug("check corresponding range;  ip: {} ; range: {}".format(ip, res))
            pass
        return res

    # input: IP str "192.168.0.2"
    # output: IP str. "192.168.0.0/28"
    def mask_ip(self, ip_address):
        ip_version = 6 if ":" in ip_address else 4
        return str(IPNetwork(f"{ip_address}/{self.cidr_max[ip_version]}").network)


    def __get_min_samples(self, ip_version, mask, decrement=False):

        if decrement:
            cc= self.c[ip_version] * 0.001 # take 0.1% of min_samples as decrement baseline
        else:            
            cc = self.c[ip_version]

        ipv_max = 32
        if ip_version == 6:
            ipv_max = 64

        min_samples= self.min_sample_cache[ip_version].get(mask, -1)
        if min_samples < 0:
            min_samples=int(cc * math.sqrt( math.pow(2, (ipv_max - mask))))
            self.min_sample_cache[ip_version][mask] = min_samples

        # self.logger.info(f"min samples: {min_samples}")
        return min_samples


    def __split_ip_and_mask(self, prefix):
        # prefix should be in this format 123.123.123.123/12 or 2001:db8:abcd:0012::0/64
        ip, mask = prefix.split("/")

        return str(ip), int(mask)

    def __convert_range_string_to_tuple(self, range_string):
        try:
            ip_version = 4 if not ":" in range_string else 6
        except:
            self.logger.warning(f"cannot obtain ipversion -> {range_string}")
        prange, mask = range_string.split("/")

        return (ip_version,mask,prange)
        

    def __convert_range_path_to_single_elems(self, path):
        x = path.split("/")
        ip_version= int(x[0])
        mask = int(x[1])
        prange = str(x[2])
        return ip_version, mask, prange

    def __sort_dict(self, dict_to_sort):
        return {k: dict_to_sort[k] for k in sorted(dict_to_sort, key=dict_to_sort.__getitem__, reverse=True)}


    def get_sample_count(self, ip_version, mask, prange):
        count=0

        # already classified
        try:
            count = self.subnet_dict.get(int(ip_version),{}).get(int(mask),{}).get(prange, {}).get('total', -1)
        except ValueError:
            self.logger.critical(self.output_folder)
            self.logger.critical(f"mask: {mask}, ip_version: {ip_version}, prange: {prange}")
            exit(1)


        if type(count) != int:
            self.logger.warning(f"type(count): {type(count)}  {count}")

        # if no prevalent ingress exists, try to get cache data 
        if count < 0:
            try:
                count = sum(self.ipd_cache.get(int(ip_version),{}).get(int(mask),{}).get(prange, {}).get('cache', -1).values())
            except:
                # otherwise: count all items
                count=0

                for masked_ip in self.subnet_dict[ip_version][mask][prange]:
                    count+= self.subnet_dict.get(ip_version, {}).get(mask, {}).get(prange, {}).get(masked_ip, {}).get('total', 0)
                
                # TODO opt: add count to prange
                if count <=0 or count == {}:
                    self.logger.warning(f" key {ip_version} {mask} {prange} does not exist")
                    self.logger.debug(self.subnet_dict[ip_version][mask])
                    return -1

        return count

    def check_if_enough_samples_have_been_collected(self, ip_version, mask, prange):
        
        sample_count = self.get_sample_count(ip_version, mask, prange)
        if sample_count < 0: # if -1 -> key error
            self.logger.warning(f"key not found {ip_version} {mask} {prange}")
            return None

        min_samples= self.__get_min_samples(ip_version, mask)

        self.logger.info(f"  > Check if enough samples have been collected (s_ipcount >= n_cidr ) {ip_version} {mask} {prange}  s_ipcount={sample_count} min_samples={min_samples}")
        if sample_count >= min_samples:
            return True
        else:
            return False

    # if raw=True: return not prevalent ingress, but dict with counters for all found routers
    def get_prevalent_ingress(self, ip_version, mask, prange, raw=False):
        

        cur_prevalent=None
        ratio= -1
        #sample_count= self.get_sample_count(path)


        # input: counter dict
        # output: prevalent ingress or None
        def __get_prev_ing(counter_dict):
            prevalent_ingress = None
            prevalent_ratio = -1.00

            total = sum(counter_dict.values())


            # single ingresses are handled here
            for ingress in counter_dict.keys():
                ratio = counter_dict[ingress]/total

                if  ratio >= self.q:
                    prevalent_ingress = ingress
                    prevalent_ratio = ratio

                    # self.ipd_cache[ip_version][mask][prange]['cache_prevalent_ingress']  = ingress
                    # self.ipd_cache[ip_version][mask][prange]['cache_prevalent_ratio'] = ratio

            if prevalent_ingress == None: # still no prevalent ingress? -> check for bundles

                self.logger.debug("CHECK FOR BUNDLES NOW")
                bundle_candidates=set()
                last_value=None
                last_ingress=None
                result_dict = __get_shares(counter_dict)
                self.logger.debug(result_dict)
                
                for ingress in result_dict.keys():
                    value = result_dict.get(ingress)
                    if value < 0.1: break # since it is sorted; otherwise we should use continue here

                    # first iteration
                    if last_value == None:
                        last_value = value
                        last_ingress = ingress
                        continue

                    # 2nd ... nth iteration
                    if value + b >= last_value:
                        # check if there is the same router
                        if ingress.split(".")[0] == last_ingress.split(".")[0]:
                            bundle_candidates.add(last_ingress)
                            bundle_candidates.add(ingress)

                    last_value = value
                    last_ingress = ingress

                if len(bundle_candidates) > 0:
                    self.logger.debug(f"bundle candidates: {bundle_candidates}")
                    cum_ratio=0
                    for i in bundle_candidates: cum_ratio += result_dict.get(i)

                    if cum_ratio >= self.q:
                        # if cum_ratio exceeds q, this will be a bundle
                        prevalent_ingress=list(bundle_candidates)
                        ratio = cum_ratio


                if prevalent_ingress == None: ratio = -1,00
                # self.ipd_cache[ip_version][mask][prange]['cache_prevalent_ingress']  = prevalent_ingress
                # self.ipd_cache[ip_version][mask][prange]['cache_prevalent_ratio'] = ratio

            self.logger.info(f"        prevalent for {ip_version} {mask} {prange}: {prevalent_ingress} ({prevalent_ratio:.2f})")
            return prevalent_ingress
            
        def __get_shares(counter_dict):
            total = sum(counter_dict.values())
            tmp_dict={}
            for ingress in counter_dict.keys():
                ratio = counter_dict.get(ingress) / total
                tmp_dict[ingress] = round(ratio,3)

            return self.__sort_dict(tmp_dict)
            # there was no prevalent

        # something like this:
        # defaultdict(int,
        # {'VIE-SB5.1507': 5,
        # 'VIE-SB5.1530': 6,
        # 'VIE-SB5.10': 1,
        # 'VIE-SB5.12': 1,
        # 'VIE-SB5.26': 1})
        counter_dict = self.ipd_cache[ip_version][mask][prange].get('cache', defaultdict(int))

        # use cached data
        if len(counter_dict) >0:
            # if > 0 then we have data
            if raw: return counter_dict
            self.logger.info(f" current shares: {list(__get_shares(counter_dict).items())[:5]}")
            return (__get_prev_ing(counter_dict))
            
        else: # calculate everything from new

            result_dict={}
            
            p_ingress = self.subnet_dict[ip_version][mask][prange].get('prevalent', None)
            p_total   = self.subnet_dict[ip_version][mask][prange].get('total', None)
            p_miss    = self.subnet_dict[ip_version][mask][prange].get('miss', None)


            # already classified
            if p_ingress != None and p_total != None: # there is a prevalent ingress yet
                if p_total < 1: 
                    pr = self.subnet_dict[ip_version][mask].pop(prange)
                    self.logger.warning(f"p_total < 1: {ip_version} {mask} {prange} ingress:{p_ingress} total:{p_total} miss:{p_miss} - pop: {pr}")
                    
                    return None

                if bundle_indicator in p_ingress:
                    
                    pass
                

                ratio = 1- (p_miss / p_total)

                counter_dict={p_ingress : (p_total-p_miss), 'miss' : p_miss}

                res = __get_prev_ing(counter_dict)
                if res == None:
                    self.logger.warning(f"        prevalent ingress {p_ingress} for {ip_version} {mask} {prange} below threshold ({ratio}) (will be popped in another step)")
                    # TODO remove path if it is not prevalent anymore -> will be popped in prevalent_color_still_valid
                    #self.subnet_dict[ip_version][mask].pop(prange)
            
            # not classified yet
            else:
                # create counter_dict
                
                # get all masked ips for current range
                #self.logger.warning(f"{mask} {prange} {self.subnet_dict[ip_version][mask][prange].keys()}")
                masked_ips_list=list(self.subnet_dict[ip_version][mask][prange].keys())
                
                while len(masked_ips_list) > 0:
                    masked_ip = masked_ips_list.pop()

                    # iterate over all found ingresses for masked ip -> fill counter_dict
                    for ingress in list(self.subnet_dict[ip_version][mask][prange][masked_ip]['ingress'].keys()):
                        counter_dict[ingress] += self.subnet_dict[ip_version][mask][prange][masked_ip]['ingress'][ingress]

                # is single ingress prevalent?    
                cur_prevalent = __get_prev_ing(counter_dict)
                if raw: return counter_dict
        

            if cur_prevalent == None:
                ratio = -1
                self.logger.info("        no prevalent ingress found: {}".format(result_dict))
            else:
                self.logger.info(f"        prevalent for {ip_version} {mask} {prange}: {cur_prevalent} ({ratio:.2f})")
            
            # finally add cache entry
            self.ipd_cache[ip_version][mask][prange]['cache'] = counter_dict
            return cur_prevalent

    def set_prevalent_ingress(self, ip_version, mask, prange, ingress, current_ts):
        # if an ingress is prevalent we set a 'prevalent' attribute for this path
        # then we can set the counter for miss and match
        # and pop the list with all single ips
        # then we need to distinguish between
        #   already classified ranges => increment counters for misses and matches; decrement by dec_function
        #   not classified ranges = add IPs
        #

        # single ingress or bundle?

        if type(ingress) == list: # bundle
            bundle_id=len(self.bundle_dict)+1
            prevalent_name ="{}{}{}".format(ingress[0].split(".")[0], bundle_indicator, bundle_id) # name of bundle
        else: # single
            prevalent_name = ingress
            ingress = [ingress] # convert single ingress to list to iterate over all ( =1) ingresses 

        sample_count = sum(self.ipd_cache[ip_version][mask][prange]['cache'].values())
        miss = sample_count
        

        tmp_dict=defaultdict(int)   
        for single_ingress in ingress:
            miss -= self.ipd_cache[ip_version][mask][prange]['cache'][single_ingress]
            tmp_dict[single_ingress] += self.ipd_cache[ip_version][mask][prange]['cache'][single_ingress]
            
        if bundle_indicator in prevalent_name:
             self.bundle_dict[prevalent_name] = tmp_dict
             
        pr = self.subnet_dict[ip_version][mask].pop(prange)
        self.logger.info(f" remove state for {len(pr)} IPs")
        
        self.subnet_dict[ip_version][mask][prange]['prevalent'] = prevalent_name
        self.subnet_dict[ip_version][mask][prange]['total'] = sample_count
        self.subnet_dict[ip_version][mask][prange]['miss'] = miss
        self.subnet_dict[ip_version][mask][prange]['prevalent_last_seen'] = current_ts


        #if DEBUG:
        min_samples=self.__get_min_samples(ip_version, mask)
        ratio= (sample_count - miss) / sample_count
        self.logger.info(f"        set prevalent ingress: {ip_version} {mask} {prange} => {prevalent_name}: {ip_version} range {ratio:.3f} {sample_count}/{min_samples} {prange}/{mask} {prevalent_name} | miss: {miss} total: {sample_count}")
        if bundle_indicator in ingress:
            self.logger.info(self.bundle_dict.get(ingress))

            pass
        ######## OLD  END

    # iterates over all ranges that are already classified
    def is_prevalent_ingress_still_valid(self, ip_version, mask, prange, current_ts):

        self.logger.info("  > Prevalent color still valid (s_color >= q)")

        current_prevalent = self.subnet_dict[ip_version][mask][prange]['prevalent']
        new_prevalent = self.get_prevalent_ingress(ip_version, mask, prange)

        
        # if new_prevalent is list and current_prevalent is bundle string, we split current_prevalent and compare list
        if (current_prevalent == new_prevalent) or ((type(new_prevalent) == list) and (bundle_indicator in current_prevalent) and  (list(self.bundle_dict.get(current_prevalent).keys()).sort() == sorted(new_prevalent))):
            self.logger.info("     YES → join siblings ? (join(s_color ) >= q) ")

            # TODO if True -> probably join_siblings could be applied
            return True

        else:
            x = self.subnet_dict[ip_version][mask].pop(prange)
            self.logger.info(f"     NO → remove all information for {prange}: {len(x)}")
            
            return False            

    def split_range(self, ip_version, mask, prange):

        if self.cidr_max[ip_version] <= mask:
            self.logger.info("    max_cidr reached - do nothing")
            return

        nw= IPNetwork(f"{prange}/{mask}")


        # add range to pytrcia tree and remove supernet
        info_txt=f"          split {prange}/{mask} into"
        for splitted_nw in nw.subnet(mask+1):
            #self.logger.info(f"     add {splitted_nw}")
            self.range_lookup_dict[ip_version].insert(str(splitted_nw), str(splitted_nw))
            info_txt+=f" {splitted_nw} and"
        info_txt= info_txt[:-4]
        self.logger.info(info_txt)
        # self.logger.info(f"     del {nw}")

        self.range_lookup_dict[ip_version].delete(str(nw))
        masked_ip_list = list(self.subnet_dict[ip_version][mask][prange].keys())

        self.logger.debug(f"        #items {len(masked_ip_list)}")
        
        for masked_ip in masked_ip_list:
            try:
                for ingress in self.subnet_dict[ip_version][mask][prange][masked_ip].get("ingress").keys():
                    last_seen=self.subnet_dict[ip_version][mask][prange][masked_ip].get("last_seen")
                    i_count=self.subnet_dict[ip_version][mask][prange][masked_ip][("ingress")][ingress]
                    self.add_to_subnet(masked_ip= masked_ip, ingress=ingress, last_seen=last_seen, i_count=i_count)
            except:
                self.logger.warning(f"         splitting not possible: {ip_version} {mask} {prange} {masked_ip}")

        # when all ips are shifted to new range -> pop prange
        self.subnet_dict[ip_version][mask].pop(prange)
        # self.logger.info(f"range_lookup_dict: (elem count: {len(list(self.range_lookup_dict[ip_version])[:10])}) {list(self.range_lookup_dict[ip_version])[:10]}")

    # def get_siblings(self, ip_version, mask, prange):
    #     nw = IPNetwork(f"{prange}/{mask}")

    #     #what is the potential sibling?
    #     nw_supernet=nw.supernet(mask-1)[0]
    #     supernet_ip=str(nw_supernet).split("/")[0]
    #     supernet_mask=int(str(nw_supernet).split("/")[1])

    #     siblings=list(nw_supernet.subnet(mask))

    #     return siblings

    def join_siblings(self, ip_version, mask, prange, current_ts, counter_check=True):
        self.logger.info(f"        join siblings for range {ip_version} {mask} {prange}")
        ## check if join would be possible

        if mask == 0:
            self.logger.info("        join siblings not possible - we are at the root of the tree")
            return None


        nw = IPNetwork(f"{prange}/{mask}")


        #### GET SUPERNET
        nw_supernet=nw.supernet(mask-1)[0]
        supernet_ip=str(nw_supernet).split("/")[0]
        supernet_mask=int(str(nw_supernet).split("/")[1])

        #### GET SIBLINGS
        siblings=list(nw_supernet.subnet(mask))
        the_other_one=None

        for sibling in siblings:

            self.logger.debug(f"sibling: {sibling}")
            # if one of both siblings does not exist -> skip joining
            # rationale: 
            #   we can only join siblings on same level 
            #   if one sibling is more specific meanwhile, then joining is not possible:
            #       e.g.  128.0.0.0/5 and 136.0.0.0/5 to  128.0.0.0/4
            #              128.0.0.0/5 exists
            #              136.0.0.0/5 not but 136.0.0.0/6 and 140.0.0.0/6
            #           -> so skip joining here
            if self.range_lookup_dict[ip_version].get(str(sibling), None) == None: 
                self.logger.info(f"sibling does not exist: {str(sibling)} - abort joining")
                #self.logger.info(f"range_lookup_dict: (elem count: {len(list(self.range_lookup_dict[ip_version]))}) {list(self.range_lookup_dict[ip_version])[:10]}")
                return None

            if str(sibling) != f"{prange}/{mask}": the_other_one= str(sibling)

        # remove expired ips from the other one 
        self.remove_expired_ips_from_range(current_ts, f"{ip_version}/{the_other_one.split('/')[1]}/{the_other_one.split('/')[0]}")


        ####### would joining satisfy s_color >= q?
        
        # first get counter_dicts from both siblings
        s1= self.get_prevalent_ingress(self.__convert_range_string_to_tuple(str(siblings[0])), current_ts=current_ts, raw=True)
        s2= self.get_prevalent_ingress(self.__convert_range_string_to_tuple(str(siblings[1])), current_ts=current_ts, raw=True)

        # if empty -> make an empty dict instead of None
        s1 = s1 if s1 != None else {}
        s2 = s2 if s2 != None else {}
        
        
        if (len(s1) == 0 and len(s2) == 0):
            self.logger.info("both prefixes have no prevalent ingress")

        #     self.logger.warning(f"        both prefixes are empty - pop siblings and create supernet {str(nw_supernet)}")
        #     self.logger.info("lpm lookup: {}".format(list(self.range_lookup_dict[ip_version])))
            
        #     # TODO pop s1 and s2 and create supernet
        #     for sibling in siblings:
        #         try:
        #             self.range_lookup_dict[ip_version].delete(str(sibling))
        #         except:
        #             self.logger.warning(f"key {sibling} does not exist")
        #             self.logger.debug("   {}".format(self.range_lookup_dict[ip_version]))

        #     self.range_lookup_dict[ip_version].insert(str(nw_supernet), str(nw_supernet))
        #     return str(nw_supernet), None

        # TODO it can be the case that a bundle is returned here
        #   lookup that bundle

        # s1 or s2 return
        #   a dict with ingress router {"VIE-SB5.123" : matching samples, "miss" : miss samples}
        #   a dict with all routers and there counters
        #   a dict with bundle id: {"VIE-SB5.b_xxxx" : matching samples, "miss" : miss samples}
        for sibling_dict in [s1, s2]:
            # input {'VIE-SB5.b_123': 123141, 'miss': 32}
            for x in  [i for i in sibling_dict.keys() if bundle_indicator in i]:
                sibling_dict.update(self.bundle_dict.get(x))
                sibling_dict.pop(x)
            
                # now we have a dict with all ingress links separately
                # e.g. {'miss': 32, 'VIE-SB5.12': 61000, 'VIE-SB5.10': 61571}

        ###### now check if we will get a prevalent ingress in case of joining
        tmp_merged_counter_dict =  {k: s1.get(k, 0) + s2.get(k, 0) for k in set(s1) | set(s2)}
        tmp_merged_sample_count = sum(tmp_merged_counter_dict.values())

        tmp_cur_prevalent = None
        for ingress in tmp_merged_counter_dict:
                ratio = tmp_merged_counter_dict.get(ingress) / tmp_merged_sample_count
                # self.logger.info("       ratio for {}: {:.2f}".format(ingress, ratio))
                if ratio >= self.q:
                    self.logger.info(f"    join possible: join would set {ingress} as prevalent for {nw_supernet}")
                    
                    tmp_cur_prevalent = ingress
                else:
                    #self.logger.debug("    join not possible")
                    pass

        ####### check requirements
        #                     
        # if join(s_color) >= q  OR join(s_ipcount) < n_cidr-1 => let's join siblings
        min_samples= self.__get_min_samples(ip_version, supernet_mask)
        if (tmp_cur_prevalent != None) or (tmp_merged_sample_count < min_samples and counter_check):

            self.logger.info(f" begin to join {siblings[0]} and {siblings[1]} to  {nw_supernet}")
            # if both siblings exists -> delete it from self.range_lookup_dict and add supernet
            self.logger.debug("len before: {}".format(len(list(self.subnet_dict[ip_version][supernet_mask][supernet_ip].keys()))))

            # insert new range to lpm lookup tree
            self.range_lookup_dict[ip_version].insert(str(nw_supernet), str(nw_supernet))

            # remove old prefixes from self.subnet_dict and self.range_lookup_dict
            for sibling in siblings:

                # merge subnet trees to supernet
                self.logger.debug("{} -> {}".format(sibling, len(self.subnet_dict[ip_version][mask][str(sibling).split("/")[0]])))
                p= self.subnet_dict[ip_version][supernet_mask][supernet_ip].update(self.subnet_dict[ip_version][mask].pop(str(sibling).split("/")[0]))
                self.logger.debug(f" remove prefix: {p}")
                try:
                    self.range_lookup_dict[ip_version].delete(str(sibling))
                except:
                    self.logger.warning(f"key {sibling} does not exist - cannot remove from LPM lookup tree")
                    #self.logger.debug("   {}".format(self.range_lookup_dict[ip_version]))
                    pass
            self.logger.debug("len now: {}".format(len(list(self.subnet_dict[ip_version][supernet_mask][supernet_ip].keys()))))

            #     supernet add to list   sibling that can be removed
            return str(nw_supernet) , str(the_other_one)

        else:
            self.logger.info(" NO -> do nothing")
            return None


    def add_to_subnet(self, masked_ip, ingress, last_seen, i_count=1):
        # cases:
        #   1) no prevalent ingress for that range found -> add ip and last_seen timestamp
        #   2a) there is one single prevalent link:       -> increment total and increment miss if it is not the correct ingress
        #   2b) there is a prevalent bundle:              -> increment total and increment miss in self.subnet_dict AND increment matches for ingresses in bundle dict

        ip_version = 4 if not ":" in masked_ip else 6

        # masked_ip = self.mask_ip(ip)

        prange, mask = self.__split_ip_and_mask(self.get_corresponding_range(masked_ip))
        self.debug_flow_output_counter +=1
        if self.debug_flow_output_counter > DEBUG_FLOW_OUTPUT:
            self.logger.debug(f"add flow {ip}, {ingress}, {last_seen} --> {ip_version}, {mask}, {masked_ip} --> {self.get_corresponding_range(masked_ip)}")
            self.debug_flow_output_counter = 0
        
        # get current prev ingress if existing
        p_ingress=self.subnet_dict.get(ip_version, {}).get(mask,{}).get(prange,{}).get('prevalent', None)

        if p_ingress==None: # 1) no prevalent ingress found for that range
            
            self.subnet_dict[int(ip_version)][int(mask)][prange][masked_ip]['last_seen'] = int(last_seen)
            self.subnet_dict[int(ip_version)][int(mask)][prange][masked_ip]['ingress'][ingress] += i_count
            self.subnet_dict[int(ip_version)][int(mask)][prange][masked_ip]['total'] += i_count

            # print("in: ", self.subnet_dict[int(ip_version)][int(mask)][prange][masked_ip]['ingress'])
            # print("total: ", self.subnet_dict[int(ip_version)][int(mask)][prange][masked_ip]['total'])
            if self.debug_flow_output_counter > DEBUG_FLOW_OUTPUT: 
                self.logger.debug(f"  not classified yet - {self.subnet_dict[int(ip_version)][int(mask)][prange][masked_ip]}")
                pass

        else: # 2) there is already a prevalent link
            self.subnet_dict.get(ip_version, {}).get(mask,{}).get(prange,{})['total'] += i_count # increment totals
            self.subnet_dict.get(ip_version, {}).get(mask,{}).get(prange,{})['prevalent_last_seen'] = int(last_seen)
        
            if self.debug_flow_output_counter > DEBUG_FLOW_OUTPUT: 
                self.logger.debug(f"  already classified - {self.subnet_dict[int(ip_version)][int(mask)][prange]}")
                pass


            if (bundle_indicator in p_ingress) and (ingress in self.bundle_dict[p_ingress].keys()): # 2b) there is a prevalent bundle:
                self.bundle_dict[p_ingress][ingress] += i_count

                self.logger.debug(f"  already classified as bundle - {self.bundle_dict[p_ingress][ingress]}")
                    

            elif ingress == p_ingress: # 2a) there is one single prevalent link
                # do nothing since we already incremented totals
                pass
            else:
                self.subnet_dict.get(ip_version, {}).get(mask,{}).get(prange,{})['miss'] += i_count
                if self.debug_flow_output_counter > DEBUG_FLOW_OUTPUT: 
                    self.logger.debug("  already classified but ingress not correct - {}".format(self.subnet_dict.get(ip_version, {}).get(mask,{}).get(prange,{})))
                    pass

            



    def __decay_counter(self, ip_version, mask, prange, current_ts, method="none"): # default, linear, stefan
    
        self.logger.debug(f"{ip_version} {mask} {prange}")
        # 4/2/64.0.0.0
        totc = self.subnet_dict.get(ip_version,{}).get(mask,{}).get(prange, {})['total']
        #matc = self.subnet_dict.get(ip_version,{}).get(mask,{}).get(prange, {})['match']
        misc = self.subnet_dict.get(ip_version,{}).get(mask,{}).get(prange, {})['miss']
        last_seen = self.subnet_dict.get(ip_version,{}).get(mask,{}).get(prange, {})['prevalent_last_seen'] 
        prevalent_ingress = self.subnet_dict.get(ip_version,{}).get(mask,{}).get(prange, {})['prevalent_ingress']

        if type(last_seen) != int:
            self.logger.warning(self.subnet_dict.get(ip_version,{}).get(mask,{}).get(prange, {}))
        age = (current_ts-self.e) - last_seen



        self.logger.debug("current_ts: {}; e: {}; last_seen: {}; age:{} total: {} miss: {} ".format(current_ts, self.e, last_seen, age, totc,misc) )
        reduce = 0
        if method == 'default': # ingmar
            # my $bucketExpireKeepFraction = 0.9; # all counts get decreased to this fraction every time a bucket is flushed. This fraction decreases for stale buckets
            # $cidrIntRef->{ip}{$color}{$ipInt}{u} => $lastUpdate 
            #
            # sub getCleanKeepFactor{
            #   (my $expireTime, my $lastUpdate) = @_;
            #   my $age = $expireTime - $lastUpdate;
            #   return 1 - (($age <= 0) ? $bucketExpireKeepFraction : ($bucketExpireKeepFraction/(int($age/$bucketSize)+1)));
            # }
            # my $reduce = int($cidrIntRef->{ip}{$color}{$ipInt}{c} * (getCleanKeepFactor($expireTime, $cidrIntRef->{ip}{$color}{$ipInt}{u})));
            # $cidrIntRef->{ip}{$color}{$ipInt}{c} -= $reduce;
            def get_clean_keep_factor(age):
                # age= expire_time - last_update
                x = decay_ingmar_bucket_expire_keep_fraction if (age <=0) else decay_ingmar_bucket_expire_keep_fraction / (int(age/t) + 1)
                return 1- x  
            
            reduce = get_clean_keep_factor(age)
            totc -= totc * get_clean_keep_factor(age)
            misc -= misc * get_clean_keep_factor(age)

            if (bundle_indicator in prevalent_ingress):
                total = sum(self.bundle_dict[prevalent_ingress].values())
                
                for cur_ing in self.bundle_dict[prevalent_ingress].keys():
                    cur_val = self.bundle_dict[prevalent_ingress][cur_ing]
                    self.bundle_dict[prevalent_ingress][cur_ing] -= cur_val * reduce * (cur_val / total)


        elif method == "stefan": # 0.1% of min samples for specific mask exponentially increasing by expired time buckets
            s = self.__get_min_samples(ip_version, mask, decrement=True)
            reduce = int(math.pow(s, (int(age/t)+1 )))
            misc -= reduce * (misc / totc)
            totc -= reduce

            # reduce bundle values
            if (bundle_indicator in prevalent_ingress):
                total = sum(self.bundle_dict[prevalent_ingress].values())
                
                for cur_ing in self.bundle_dict[prevalent_ingress].keys():
                    cur_val = self.bundle_dict[prevalent_ingress][cur_ing]
                    self.bundle_dict[prevalent_ingress][cur_ing] -= reduce * (cur_val / total)

        elif method == "linear":
            if age > self.e:

                totc -= linear_decay #reduce * (matc / (matc + misc))
                misc -= linear_decay #reduce * (misc / (matc + misc))
            else:
                return

            if (bundle_indicator in prevalent_ingress):
                total = sum(self.bundle_dict[prevalent_ingress].values())
                
                for cur_ing in self.bundle_dict[prevalent_ingress].keys():
                    cur_val = self.bundle_dict[prevalent_ingress][cur_ing]
                    self.bundle_dict[prevalent_ingress][cur_ing] -= linear_decay * (cur_val / total)

        elif method == "none":
            return

        self.logger.debug(f" {ip_version} {mask} {prange} decrement by: {reduce} ({method})")

        self.subnet_dict.get(ip_version,{}).get(mask,{}).get(prange, {})['total'] = int(totc)
        self.subnet_dict.get(ip_version,{}).get(mask,{}).get(prange, {})['miss'] =  int(misc)

    # remove all ips older than e seconds
    def remove_expired_ips_from_range(self, ip_version, mask, prange, current_ts):
        '''
            this is the first step after inserting new IPs into ranges for current time bucket

            check if there is the attribute 'prevalent_last_seen' 
                -> Y: classified range: decay_counter method
                -> N: iterate over all underlying (masked) IPs and check every single IP if it is expired
                    (OPTIMIZATION: after removing the IPs, we calc current prevalent ingress and append it to the masked_ip as attribute)
                    -> we set the cache_ts here too, so we will override old data 
            there is only one for loop for the masked IPs for the current range
        '''
        
        counter_dict=defaultdict(int)

        self.logger.info(f"  > remove IPs older than {self.e} seconds")

        
        ## here we have to distinguish between
        if self.subnet_dict[ip_version][mask][prange].get("prevalent_last_seen", None) != None:
            
            #       already classified prefixes -> decrement function

            total_before = self.subnet_dict[ip_version][mask][prange].get("total")

            self.__decay_counter(ip_version, mask, prange, current_ts=current_ts, method=self.decay_method)

            total_now = self.subnet_dict[ip_version][mask][prange].get("total")
            self.logger.info(f"decay {ip_version} {mask} {prange}, {current_ts}: total before: {total_before}; total now: {total_now}")

            if total_now < self.__get_min_samples(ip_version, mask):
                self.logger.warning(f"!!!  {ip_version} {mask} {prange} below min_samples -> remove all information")
                self.subnet_dict[ip_version][mask].pop(prange)
        else: 

            ##      unclassified prefixies      -> iterate over ip addresses and pop expired ones
            count_counter=0
            pop_counter=0
            masked_ip_list= list(self.subnet_dict[ip_version][mask][prange].keys())
            
            while len(masked_ip_list) >0: 

                masked_ip = masked_ip_list.pop()

                last_seen=0
        
                count_counter += self.subnet_dict[ip_version][mask][prange][masked_ip]['total']
                try:
                    last_seen= self.subnet_dict[ip_version][mask][prange][masked_ip].get("last_seen", -1)

                except:
                    self.logger.warning(f"last seen not here: {masked_ip} {self.subnet_dict[ip_version][mask][prange][masked_ip]}")

                if last_seen < 0: 
                    self.logger.warning(f"no last seen found ->  {ip_version} {mask} {prange}")
                    continue

                if last_seen  < current_ts - self.e :
                    try: 
                        x = self.subnet_dict[ip_version][mask][prange].pop(masked_ip)
                        #pop_counter +=1
                        pop_counter += sum(x['ingress'].values())

                    except:
                        self.logger.warning(f"    ERROR:  {ip_version} {mask} {prange} cannot be deleted")
                        pass
                else:

                    for ingress in self.subnet_dict[ip_version][mask][prange][masked_ip]['ingress'].keys():
                        counter_dict[ingress] += self.subnet_dict[ip_version][mask][prange][masked_ip]['ingress'][ingress]
                    pass
                    
            # TODO check if this is correct finally
            self.logger.debug(f"  {ip_version} {mask} {prange}: {counter_dict}")
            self.logger.debug(f"count before: {count_counter} - expired {pop_counter} = now: {sum(counter_dict.values())} check: {count_counter-pop_counter}")
            # TODO update 'total' self.subnet_dict[ip_version][mask][prange]['total']
            self.ipd_cache[ip_version][mask][prange]['cache'] = counter_dict
            
            self.logger.info(f"     {ip_version} {mask} {prange}: {pop_counter} IPs expired")

    def dump_tree_to_file(self, current_ts):
        self.logger.debug("PROFILING: dump tree to filesystem - start")
        with open(f"{self.tree_output_folder}/{current_ts}.json", "w") as outfile:
            json.dump(self.subnet_dict, outfile, indent=4)
        self.logger.debug("PROFILING: dump tree to filesystem - done")



    def dump_classified_ranges_to_file(self, current_ts):
        # this should be the output format
        # only dump prevalent ingresses here
        #
        
        output_file = f"{self.output_folder}/range.{current_ts}.gz"

        self.logger.info(f"dump to file: {output_file}")
        with gzip.open(output_file, 'wb') as ipd_writer:
            # Needs to be a bytestring in Python 3
            with io.TextIOWrapper(ipd_writer, encoding='utf-8') as encode:
                #encode.write("test")

                for ip_version in self.subnet_dict.keys():
                    for mask in self.subnet_dict[ip_version].keys():
                        for prange in self.subnet_dict[ip_version][mask].keys():
                            
                            ingress=  self.subnet_dict[ip_version][mask][prange].get('prevalent', None)
                            if ingress == None:
                                continue
                            
                            min_samples = self.__get_min_samples(ip_version, mask)
                            miss_samples = int(self.subnet_dict[ip_version][mask][prange]['miss'])
                            total_samples = int(self.subnet_dict[ip_version][mask][prange]['total'])
                            
                            if min_samples >total_samples: 
                                self.logger.warning(f"total count lower than min samples: {total_samples} / {min_samples}")
                                self.logger.warning(f"{self.subnet_dict[ip_version][mask][prange]}")
                            ratio= 1-(miss_samples / total_samples)

                            self.logger.info(f"{current_ts}\t{ip_version}\trange\t{ratio:.3f}\t{total_samples}/{min_samples}\t{prange}/{mask}\t{ingress}")
                            encode.write(f"{current_ts}\t{ip_version}\trange\t{ratio:.3f}\t{total_samples}/{min_samples}\t{prange}/{mask}\t{ingress}\n")            
                    
        self.logger.info(f"dump finished")


    def run_ipd(self, current_ts):
        
        # iterate over all already classified ranges
         # smehner -> fixed 
        # now go over all already classified ranges        
        check_list=[]
        # get all ranges

        # 0.0.0.0/0
        # ::/0
        self.logger.info(f"prepare check_list")
        tmp_check_list = list(self.range_lookup_dict[4]) + list(self.range_lookup_dict[6])
        
        # not anymore: convert e.g. 0.0.0.0/0 to 4/0/0.0.0.0
        # convert e.g. 0.0.0.0/0 to (4,0,0.0.0.0)
        for elem in tmp_check_list: 
                check_list.append(self.__convert_range_string_to_tuple(elem))
        #check_list = sorted(check_list)
        
        self.logger.info(f"............. run IPD {current_ts}  -> {len(check_list)} elems.............")

        # debugging purpose
        for ipv in self.subnet_dict.keys():
            for mask in self.subnet_dict[ipv].keys():
                self.logger.info(f" ipv{ipv} mask: {mask} -> {len(self.subnet_dict[ipv][mask].keys())}")
        
        while len(check_list) > 0:
            
            # get the items 
            ip_version, mask, prange = check_list.pop()
            
            self.remove_expired_ips_from_range(ip_version, mask, prange, current_ts=current_ts)

            self.logger.info(f"   current_range: {ip_version} {mask} {prange}")

            if self.subnet_dict[ip_version][mask][prange].get('prevalent', None) != None: 
                
                # check already classified range if it is still prevalent
                if self.is_prevalent_ingress_still_valid(ip_version, mask, prange, current_ts):
                    # None -> do nothing
                    # tuple(supernet_path, the_other_one)
                    self.logger.debug("PROFILING: join siblings - start")
                    x = self.join_siblings(ip_version, mask, prange, current_ts=current_ts, counter_check=False)
                    if x != None:
                        supernet, other_one = x
                        check_list.append(self.__convert_range_string_to_tuple(supernet))
                        if other_one != None: 
                            try:
                                check_list.remove(self.__convert_range_string_to_tuple(other_one))
                            except:
                                pass
                        #check_list = sorted(check_list)
                    self.logger.debug("PROFILING: join siblings - done")
            else:
                # 
            
                r = self.check_if_enough_samples_have_been_collected(ip_version, mask, prange)
                if r == True:
                    prevalent_ingress = self.get_prevalent_ingress(ip_version, mask, prange,  current_ts=current_ts) # str or None
                    if prevalent_ingress != None:
                        self.logger.info(f"        YES -> color {ip_version} {mask} {prange} with {prevalent_ingress}")

                        self.set_prevalent_ingress(ip_version, mask, prange, prevalent_ingress, current_ts)
                        continue
                    else:
                        self.logger.info(f"        NO -> split subnet")
                        # self.logger.debug("PROFILING: split range - start")
                        self.split_range(ip_version, mask, prange)
                        # self.logger.debug("PROFILING: split range - done")
                        continue

                elif r == False:
                    self.logger.info("      NO -> join siblings")

                    # self.logger.debug("PROFILING: join siblings - start")
                    x = self.join_siblings(ip_version, mask, prange, current_ts=current_ts, counter_check=True)
                    if x != None:
                        supernet, other_one = x
                        check_list.append(self.__convert_range_string_to_tuple(supernet))
                        if other_one != None: 
                            try:
                                check_list.remove(self.__convert_range_string_to_tuple(other_one))
                            except:
                                pass
                        #check_list = sorted(check_list)
                    # self.logger.debug("PROFILING: join siblings - done")
                elif r == None:
                    self.logger.info("skip this range since there is nothing to do here")
                    continue
            

        if current_ts % bucket_output == 0: # dump every 5 min to file
            self.dump_classified_ranges_to_file(current_ts)
            if DUMP_TREE: self.dump_tree_to_file(current_ts)

        

        self.logger.debug("bundles: {}".format(self.bundle_dict) )
        self.logger.info(".............Finished.............")
        self.ipd_cache.clear()

    def run(self):

        # start NF reader 
        if IPv4_ONLY:
            self.logger.warning("!!! IPv4 Traffic only !!!")
        threading.Thread(target=self.read_netflow_worker, daemon=True).start()

        # start ipd stuff 20s after nf rader starts
        time.sleep(IPD_IDLE_BEFORE_START)

        while ((not self.read_data_finisehd) or (self.netflow_data_queue.qsize() > 0)):
            # time.sleep(1)
            self.logger.debug("PROFILING: get netflow bucket from queue - start")
            cur_ts, nf_data = self.netflow_data_queue.get()
            self.logger.debug("PROFILING: get netflow bucket from queue - done")
            # add flows to corresponding ranges 

            self.logger.debug("PROFILING: add netflow to corresponding ranges - start")
            for masked_ip in nf_data:
                for ingress in nf_data[masked_ip]:
                    icount= nf_data[masked_ip][ingress]
                    if self.debug_flow_output_counter > DEBUG_FLOW_OUTPUT: self.logger.debug(f"add to subnet: {cur_ts} {masked_ip} {ingress} {icount}")
                    self.add_to_subnet(last_seen=cur_ts, masked_ip=masked_ip, ingress=ingress, i_count=icount)
            
            self.logger.debug("PROFILING: add netflow to corresponding ranges - done")
            
            self.logger.debug("PROFILING: run ipd - start")
            self.run_ipd(cur_ts)
            self.logger.debug("PROFILING: run ipd - done")

            # break if queue is empty ~ reading netflow is done
            if (self.netflow_data_queue.qsize() == 0):
                self.logger.info("queue empty - wait 5s")
                time.sleep(5)
                
            self.logger.debug("ipd iteration done")
        


    def read_netflow(self):
        added_counter=0
        for gzfile in gzfiles:
            with gzip.open(f"{input_path}/{gzfile}", 'rb') as f:
                for line in f:
                    line = line.decode('utf-8').split(",")

                    router_name = router_ip_lookup_dict.get(line[1])
                    
                    if IPv4_ONLY:
                        ip_version = 4 if not ":" in line[4] else 6
                        if ip_version == 6: continue

                    in_iface = line[2]
                    
                    if len(line) < 15: continue
                    
                    if line[-3] == "TIMESTAMP_END": continue
                    if not ingresslink_dict.get("{}.{}".format(router_name,in_iface), False): continue
                    src_ip = line[4]    
                    cur_ts = int(int(line[-3]) / self.t) * self.t
                    added_counter +=1


                    yield (cur_ts, "{}.{}".format(router_name,in_iface), src_ip)
                    
    def read_netflow_worker(self):
        print("start read_netflow_worker ")
        nf_data = self.read_netflow()
        last_ts=None
        add_counter=0
        netflow_data_dict = self.__multi_dict(2, int)

        for nf_row in nf_data:
            # init 
            cur_ts= int(nf_row[0])
            ingress= nf_row[1]
            src_ip = nf_row[2]
            masked_ip=self.mask_ip(src_ip)

            # initial set current ts
            if last_ts == None:  last_ts = cur_ts

            # next epoch?
            if cur_ts > last_ts: 
                self.logger.info(f"{self.output_folder}\t{last_ts}\tflows added: {add_counter}") # #\tlpm cache hits: {self.cache_counter}\t(elems: {len(self.range_lookup_cache_dict[4])} bzw. {len(self.range_lookup_cache_dict[6])})")
                print(f"{self.output_folder}\t{last_ts}\tflows added: {add_counter} ") # \tlpm cache hits: {self.cache_counter}\t(elems: {len(self.range_lookup_cache_dict[4])} bzw. {len(self.range_lookup_cache_dict[6])})")
                add_counter=0
                # add temporary data to queue
                self.netflow_data_queue.put((last_ts,netflow_data_dict.copy()))
                netflow_data_dict.clear()
                
                last_ts = cur_ts # next epoch
            add_counter+=1
            # add data for next t seconds
            # self.add_to_subnet(last_seen=cur_ts, ingress=ingress, ip=src_ip)
            netflow_data_dict[masked_ip][ingress] += 1         # add all masked_ip's with same router for current ts
            

        print("finish read_netflow_worker ")
        self.read_data_finisehd=True

def do_it():
        pass
if __name__ == '__main__':   

    
    params = namedtuple('params', ['d', 't','b',  'e', 'q', 'c4', 'c6', 'cidrmax4', 'cidrmax6', 'decay', 'loglevel'])
    parser = argparse.ArgumentParser()

    parser.add_argument('-c4', default=64, type=float)
    parser.add_argument('-c6', default=24, type=float)
    parser.add_argument('-t', default=60, type=int)
    parser.add_argument('-b', default=300, type=int)
    parser.add_argument('-e', default=120, type=int)
    parser.add_argument('-q', default=0.95, type=float)
    parser.add_argument('-cidrmax4', default=28, type=int)
    parser.add_argument('-cidrmax6', default=48, type=int)
    parser.add_argument('-d', default="/data/fast/mehner/ipd/netflow_merged_sorted", type=str) # netflow100000.csv netflow100000000.csv
    parser.add_argument('-decay', default="default", type=str)
    parser.add_argument('-loglevel', default=20, type=int)

    
    args = parser.parse_args()
    print("--- parametrization ---")
    print(f"c4 {args.c4}")
    print(f"c6 {args.c6}")
    print(f"t {args.t}")
    print(f"b {args.b}")
    print(f"e {args.e}")
    print(f"q {args.q}")
    print(f"cidrmax4 {args.cidrmax4}")
    print(f"cidrmax6 {args.cidrmax6}")
    print(f"dataset {args.d}")
    print("------------------------")

    dataset=args.d
    t = args.t #60
    bucket_output = args.b #60
    e=  args.e #120
    q = args.q # 0.80
    decay_method=args.decay


    cidr_max = {
        4: args.cidrmax4,
        6: args.cidrmax6
    }
    c = {
        4: args.c4,
        6: args.c6
    }

    if TEST:
        params = params(dataset, 10, 0.05, 5, 0.501, 0.000025, 0.0000025, 28, 48, 'default', logging.DEBUG)
        #params = params(dataset, 30, 0.05, 120, 0.9501, 64, 24, 28, 48, 'default', logging.DEBUG)
   
    else:
        params = params(dataset, t, 0.05, e, q, c[4], c[6], cidr_max[4], cidr_max[6], decay_method, logging.DEBUG)

    ipd = IPD(params)
    ipd.run()