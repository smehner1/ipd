from enum import unique
from unicodedata import name
import pandas as pd 
import csv
import gzip
import pytricia
from netaddr import *
from collections import defaultdict, namedtuple
import math
import dpath.util as dp 
import io
import os
import argparse
import logging
from multiprocessing import Pool
from tqdm import tqdm
import datetime

PROCS = 90
decay_ingmar_bucket_expire_keep_fraction=0.9
linear_decay = 1000

bundle_indicator=".b_"

t=60
bucket_output = 5*t
b= 0.05         # allowed delta between bundle load

input_path="/data/fast/mehner/ipd/netflow_merged_sorted"
gzfiles=["@000000000000001605556860.gz", "@000000000000001605560460.gz", "@000000000000001605564060.gz", "@000000000000001605567660.gz", "@000000000000001605571260.gz", "@000000000000001605574860.gz", "@000000000000001605578460.gz", "@000000000000001605582060.gz", "@000000000000001605585660.gz", "@000000000000001605589260.gz", "@000000000000001605592860.gz", "@000000000000001605596460.gz", "@000000000000001605600060.gz", "@000000000000001605603660.gz", "@000000000000001605607260.gz", "@000000000000001605610860.gz", "@000000000000001605614460.gz", "@000000000000001605618060.gz", "@000000000000001605621660.gz", "@000000000000001605625260.gz", "@000000000000001605628860.gz", "@000000000000001605632460.gz", "@000000000000001605636060.gz", "@000000000000001605639660.gz", "@000000000000001605643260.gz"]
#gzfiles=["nf_test.gz"]
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
        return {'last_seen': 0,  'ingress' : ""}

    def __multi_dict(self, K, type):
        if K == 1:
            return defaultdict(type)
        else:
            return defaultdict(lambda: self.__multi_dict(K-1, type))

    def __init__(self, params):
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
        
        self.subnet_dict= self.__multi_dict(4, self.__subnet_atts)

        self.bundle_dict={}
        self.d = params.d
        self.t = params.t #60 ### TODO ggf fix notwenig
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

        ############################################
        ########### LOGGER CONFIGURATION ###########
        ############################################
        os.makedirs("log", exist_ok=True)
        logfile=f"log/q{self.q}_c{self.c[4]}-{self.c[6]}_cidr_max{self.cidr_max[4]}-{self.cidr_max[6]}_t{self.t}_e{self.e}_decay{self.decay_method}.log"
        logging.basicConfig(filename=logfile,
                        format='%(asctime)s %(levelname)s %(funcName)s %(message)s',
                        datefmt='%d-%b-%y %H:%M:%S',
                        filemode='w',
                        level=params.loglevel)

        # Creating an object
        self.logger = logging.getLogger()



    




    ## lookup in pytricia tree and return corresponding range
    def get_corresponding_range(self, ip):
        ip_version = 4 if not ":" in ip else 6
        
        if ip == "::": return "::/0"

        try:
            res =self.range_lookup_dict[ip_version][ip]
        except:
            self.logger.warning(f"key error: {ip}")
            self.logger.debug("  current ranges: {}".format(list(self.range_lookup_dict[ip_version])))

            res="0.0.0.0/0" if ip_version == 4 else "::/0"
        # self.logger.info("check corresponding range;  ip: {} ; range: {}".format(ip_address, res))
        return res

    def mask_ip(self, ip_address):
        ip_version = 6 if ":" in ip_address else 4
        return str(IPNetwork(f"{ip_address}/{self.cidr_max[ip_version]}").network)



    def __get_min_samples(self, path, decrement=False):
            t = path.split("/")
            ip_version = int(t[0])
            cidr = int(t[1])

            if decrement:
                cc= self.c[ip_version] * 0.001 # take 1% of min_samples as decrement base
            else:
                cc = self.c[ip_version]

            ipv_max = 32
            if ip_version == 6:
                ipv_max = 64
            min_samples=int(cc * math.sqrt( math.pow(2, (ipv_max - cidr))))

            # self.logger.info(f"min samples: {min_samples}")
            return min_samples

    def __split_ip_and_mask(self, prefix):
        # prefix should be in this format 123.123.123.123/12 or 2001:db8:abcd:0012::0/64

        ip = prefix.split("/")[0]
        mask = prefix.split("/")[1]

        return str(ip), int(mask)

    def __convert_range_string_to_range_path(self, range_string):
        ip_version = 4 if not ":" in range_string else 6

        prange, mask = range_string.split("/")

        return f"{ip_version}/{mask}/{prange}"

    def __convert_range_path_to_single_elems(self, path):
        t = path.split("/")
        ip_version = int(t[0])
        mask = int(t[1])
        prange= t[2]
        return ip_version, mask, prange

    def __sort_dict(self, dict_to_sort):
        return {k: dict_to_sort[k] for k in sorted(dict_to_sort, key=dict_to_sort.__getitem__, reverse=True)}


    def get_sample_count(self, path):

        ip_version, mask, prange = self.__convert_range_path_to_single_elems(path)
        self.logger.debug(path)
        # matc = self.subnet_dict.get(ip_version,{}).get(mask,{}).get(prange, {}).get('match', -1)
        count = self.subnet_dict.get(ip_version,{}).get(mask,{}).get(prange, {}).get('total', -1)
        # misc = self.subnet_dict.get(ip_version,{}).get(mask,{}).get(prange, {}).get('miss', -1)

        if count < 0:

            # if no prevalent ingress exists, count all items
            count= len(self.subnet_dict.get(ip_version,{}).get(mask,{}).get(prange, {}))

            if count <=0:
                self.logger.warning(f" key {path} does not exist")
                return -1

        return count

    def check_if_enough_samples_have_been_collected(self, prange):
        
        sample_count = self.get_sample_count(prange)
        if sample_count < 0: # if -1 -> key error
            return None

        min_samples= self.__get_min_samples(prange)

        self.logger.info(f"  > Check if enough samples have been collected (s_ipcount >= n_cidr ) {prange}   s_ipcount={sample_count} min_samples={min_samples}")
        if sample_count >= min_samples:
            # print("    YES → is a single color prevalent ? (s_color >=q)")
            return True
        else:
            return False

    # if raw=True: return not prevalent ingress, but dict with counters for all found routers
    def get_prevalent_ingress(self, path, raw=False):

        cur_prevalent=None
        ratio= -1
        sample_count= self.get_sample_count(path)

        # calculate prevalent ingress
        counter_dict=defaultdict(int)
        result_dict={}

        ip_version, mask, prange = self.__convert_range_path_to_single_elems(path)
        p_ingress = self.subnet_dict.get(ip_version, {}).get(mask, {}).get(prange, {}).get('prevalent', None)
        p_total = self.subnet_dict.get(ip_version, {}).get(mask, {}).get(prange, {}).get('total', None)
        p_miss = self.subnet_dict.get(ip_version, {}).get(mask, {}).get(prange, {}).get('miss', None)

        if p_ingress != None and p_total != None: # there is a prevalent ingress yet
            if p_total < 1: 
                pr = self.subnet_dict[ip_version][mask].pop(prange)
                self.logger.warning(f"p_total < 1: {path} ingress:{p_ingress} total:{p_total} miss:{p_miss} - pop: {pr}")
                
                return None

            ratio = 1- (p_miss / p_total)

            if raw:
                return {p_ingress : (p_total-p_miss), 'miss' : p_miss} # TODO total or matches ?

            if ratio >= self.q:
                self.logger.debug(f"        already classified: {p_ingress}: ({ratio:.2f})")
                cur_prevalent=p_ingress
            else:
                self.logger.warning(f"        prevalent ingress {p_ingress} for {path} below threshold ({ratio})")



        else:
            search_path="{}/**/ingress".format(path)
            for p, v in dp.search(self.subnet_dict, search_path, yielded=True):
                counter_dict[v]+=1

            # is single ingress prevalent?

            for ingress in counter_dict:
                ratio = counter_dict.get(ingress) / sample_count
                result_dict[ingress] = round(ratio,3)

                # self.logger.info("       ratio for {}: {:.2f}".format(ingress, ratio))
                if ratio >= self.q:  # we found a prevalent ingress point!
                    cur_prevalent = ingress
                    if not raw: break

            # check for bundles
            if cur_prevalent == None: # if we still have not found an ingress, maybe we have a bundle here
                bundle_candidates=set()
                last_value=None
                last_ingress=None
                self.logger.debug(self.__sort_dict(result_dict))
                for ingress in self.__sort_dict(result_dict):
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
                        cur_prevalent=list(bundle_candidates)
                        ratio = cum_ratio


            if raw:
                self.logger.debug(f"counter_dict: {counter_dict}")
                return counter_dict


        if cur_prevalent == None:
            ratio = -1
            self.logger.info("        no prevalent ingress found: {}".format(self.__sort_dict(result_dict)))

        self.logger.info("        prevalent for {}: {} ({:.2f})".format(path, cur_prevalent, ratio))

        return cur_prevalent

    def set_prevalent_ingress(self, path, ingress):
        # if an ingress is prevalent we set a 'prevalent' attribute for this path
        # then we can set the counter for miss and match
        # and pop the list with all single ips
        # then we need to distinguish between
        #   already classified ranges => increment counters for misses and matches; decrement by dec_function
        #   not classified ranges = add IPs
        #

        #dp.search(self.subnet_dict, f"{path}/**/ingress") # smehner removed
        match=0
        if type(ingress) == list: # handle bundle
            # count matches for that ingress'es
            bundle_id=len(self.bundle_dict)+1
            bundle_name="{}{}{}".format(ingress[0].split(".")[0], bundle_indicator, bundle_id)
            # bundle_name+=",".join(ingress)
            # bundle_name+=")"

            tmp_dict=defaultdict(int)
            for p,v in dp.search(self.subnet_dict, f"{path}/**/ingress", yielded=True):
                if v in ingress:
                    tmp_dict[v] +=1
                    match +=1

            self.bundle_dict[bundle_name] = tmp_dict

            ingress=bundle_name


        else: # handle single ingress link

            for p,v in dp.search(self.subnet_dict, f"{path}/**/ingress", yielded=True):
                if v == ingress: match += 1


        sample_count = self.get_sample_count(path)

        last_seen=0
        try:   
            last_seen = max(dp.search(self.subnet_dict, f"{path}/**/last_seen", yielded=True))[1]
        except:
            logging.critical("last_seen not avaliable: {}".format(dp.get(self.subnet_dict, f"{path}")))


        ip_version, mask, prange = self.__convert_range_path_to_single_elems(path)

        pr = self.subnet_dict[ip_version][mask].pop(prange)

        self.logger.debug(f" remove state for {len(pr)} IPs")
        miss = sample_count-match
        dp.new(self.subnet_dict, f"{path}/prevalent", ingress)
        # TODO prevalent_
        dp.new(self.subnet_dict, f"{path}/total", sample_count)
        # dp.new(self.subnet_dict, f"{path}/match", match)
        dp.new(self.subnet_dict, f"{path}/miss", miss)
        dp.new(self.subnet_dict, f"{path}/prevalent_last_seen", last_seen)


        #if DEBUG:
        min_samples=self.__get_min_samples(path)
        ratio= match / sample_count
        self.logger.info(f"        set prevalent ingress: {path} => {ingress}: {ip_version} range {ratio:.3f} {sample_count}/{min_samples} {prange}/{mask} {ingress} | miss: {miss} total: {sample_count}")


    # iterates over all ranges that are already classified
    def is_prevalent_ingress_still_valid(self ):
        self.logger.info("  > Prevalent color still valid (s_color >= q)")

        check_list=[]
        buffer_dict={}

        currently_prevalent_ingresses = dp.search(self.subnet_dict, "**/prevalent", yielded=True)

        # prepare inital list
        for p,v in currently_prevalent_ingresses:
            check_list.append(p)

        check_list.sort()
        while len(check_list) > 0:
            current_prevalent_path = check_list.pop()
            

            # if we have to handle a sibling where the other one already initiated join
            if  buffer_dict.get(current_prevalent_path,False):
                buffer_dict.pop(current_prevalent_path)
                continue

            self.logger.debug(f"    checking {current_prevalent_path}")
            ip_version, mask, prange = self.__convert_range_path_to_single_elems(current_prevalent_path)
            current_prevalent = self.subnet_dict[ip_version][mask][prange]['prevalent']

            #current_prevalent= i

            new_prevalent = self.get_prevalent_ingress(current_prevalent_path)


            # if new_prevalent is list and current_prevalent is bundle string, we split current_prevalent and compare list
            if (current_prevalent == new_prevalent) or ((type(new_prevalent) == list) and (bundle_indicator in current_prevalent) and  (list(self.bundle_dict.get(current_prevalent).keys()).sort() == sorted(new_prevalent))):
                self.logger.info("     YES → join siblings ? (join(s_color ) >= q) ")

                r = self.join_siblings(path=current_prevalent_path, counter_check=False)


                # JOIN and add sibling to buffer dict to pop in next iteration; further add new supernet to check_list
                if r != None:
                    joined_supernet, sibling_to_pop = r
                    buffer_dict[sibling_to_pop] = True
                    check_list.append(joined_supernet)
                    check_list.sort()

            else:
                x = self.subnet_dict[ip_version][mask].pop(prange)
                self.logger.info(f"     NO → remove all information for {prange}: {x}")
                
                #pop_list.append(p)


    def split_range(self, path):

        ip_version, mask, prange = self.__convert_range_path_to_single_elems(path)

        if self.cidr_max[ip_version] <= mask:
            self.logger.info("    max_cidr reached - do nothing")
            return

        nw= IPNetwork(f"{prange}/{mask}")

        # ip_version = str()
        #print(f"nw: {nw}")
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

        # now split self.subnet_dict with all IPs
        change_list=[]
        for p,v  in dp.search(self.subnet_dict, f"{path}/*", yielded=True): change_list.append((p,v))

        self.logger.debug("        #items {}; first 3 elems: {}".format(len(change_list), change_list[:3]))
        self.subnet_dict[ip_version][mask].pop(prange)
        for p,v in change_list:
            try:
                self.add_to_subnet(ip= p.split("/")[3], ingress=v.get("ingress"), last_seen=v.get("last_seen"))
            except:
                self.logger.warning(f"         splitting not possible: {p} {v}")


        self.logger.debug("         self.range_lookup_dict: {}".format(list(self.range_lookup_dict[ip_version])))

    def join_siblings(self, path, counter_check=True):
        self.logger.info(f"        join siblings for range {path}")

        ip_version, mask, prange = self.__convert_range_path_to_single_elems(path)

        ## check if join would be possible

        if mask == 0:
            self.logger.info("        join siblings not possible - we are at the root of the tree")
            return None

        nw = IPNetwork(f"{prange}/{mask}")

        #what is the potential sibling?
        nw_supernet=nw.supernet(mask-1)[0]
        supernet_ip=str(nw_supernet).split("/")[0]
        supernet_mask=int(str(nw_supernet).split("/")[1])

        siblings=list(nw_supernet.subnet(mask))
        the_other_one=None
        for sibling in siblings:

            self.logger.debug(f"sibling: {sibling}")
            # if one of both siblings does not exist -> skip joining
            if self.range_lookup_dict[ip_version].get(str(sibling), None) == None: return None

            if str(sibling) != f"{prange}/{mask}": the_other_one=str(sibling)


        # would joining satisfy s_color >= q?
        s1=self.get_prevalent_ingress(self.__convert_range_string_to_range_path(str(siblings[0])), raw=True)
        s2=self.get_prevalent_ingress(self.__convert_range_string_to_range_path(str(siblings[1])), raw=True)

        if (s1 == None or s2 == None) or (len(s1) == 0 and len(s2) == 0):
            self.logger.warning("        both prefixes are empty")
            self.logger.debug("lpm lookup: {}".format(list(self.range_lookup_dict[ip_version])))
            self.logger.debug("self.subnet_dict: {} {} {}".format(self.subnet_dict.get(ip_version, {}).get(supernet_mask, {}).get(supernet_ip,{})))

            # TODO pop s1 and s2 and create supernet
            return None
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
                #print("update ", bundle_dict.get(x))
                #print("pop ", x)
                # now we have a dict with all ingress links separately
                # e.g. {'miss': 32, 'VIE-SB5.12': 61000, 'VIE-SB5.10': 61571}


        tmp_merged_counter_dict =  {k: s1.get(k, 0) + s2.get(k, 0) for k in set(s1) | set(s2)}
        tmp_merged_sample_count = sum(tmp_merged_counter_dict.values())

        tmp_cur_prevalent = None
        for ingress in tmp_merged_counter_dict:
                ratio = tmp_merged_counter_dict.get(ingress) / tmp_merged_sample_count
                # self.logger.info("       ratio for {}: {:.2f}".format(ingress, ratio))
                if ratio >= self.q:
                    self.logger.debug(f" join would set {ingress} as prevalent for {nw_supernet}")
                    
                    tmp_cur_prevalent = ingress

        # if join(s_color) >= q  OR join(s_ipcount) < n_cidr-1 => let's join siblings
        if (tmp_cur_prevalent != None) or (tmp_merged_sample_count < self.__get_min_samples(self.__convert_range_string_to_range_path(str(nw_supernet))) and counter_check):
            self.logger.info(f" -> join {siblings[0]} and {siblings[1]} to  {nw_supernet}")
            # if both siblings exists -> delete it from self.range_lookup_dict and add supernet
            self.logger.debug("len before: {}".format(len(self.subnet_dict[ip_version][supernet_mask][supernet_ip].keys())))

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
                    self.logger.waning(f"key {sibling} does not exist")
                    self.logger.debug("   {}".format(self.range_lookup_dict[ip_version]))
                    pass
            self.logger.debug("len now: {}".format(len(self.subnet_dict[ip_version][supernet_mask][supernet_ip].keys())))

            #       supernet add to list                          sibling that can be removed
            return f"{ip_version}/{supernet_mask}/{supernet_ip}", the_other_one
            # pop_list=[]
            # add_list=[]
            # return f"{ip_version}/{supernet_mask}/{supernet_ip}", pop_list, add_list

        else:
            self.logger.info(" NO -> do nothing")
            return None


    def add_to_subnet(self, ip, ingress, last_seen):
        # cases:
        #   1) no prevalent ingress for that range found -> add ip and last_seen timestamp
        #   2a) there is one single prevalent link:       -> increment total and increment miss if it is not the correct ingress
        #   2b) there is a prevalent bundle:              -> increment total and increment miss in self.subnet_dict AND increment matches for ingresses in bundle dict

        ip_version = 4 if not ":" in ip else 6

        masked_ip = self.mask_ip(ip)
        prange, mask = self.__split_ip_and_mask(self.get_corresponding_range(masked_ip))


        # get current prev ingress if existing
        p_ingress=self.subnet_dict.get(ip_version, {}).get(mask,{}).get(prange,{}).get('prevalent', None)

        if p_ingress==None: # 1) no prevalent ingress found for that range
            dp.new(self.subnet_dict, [int(ip_version), int(mask), prange, masked_ip, 'last_seen'], int(last_seen))
            dp.new(self.subnet_dict, [int(ip_version), int(mask), prange, masked_ip, 'ingress'], ingress)

        else: # 2) there is already a prevalent link
            self.subnet_dict.get(ip_version, {}).get(mask,{}).get(prange,{})['total'] +=1 # increment totals
            self.subnet_dict.get(ip_version, {}).get(mask,{}).get(prange,{})['prevalent_last_seen'] = int(last_seen)

            if (bundle_indicator in p_ingress) and (ingress in self.bundle_dict[p_ingress].keys()): # 2b) there is a prevalent bundle:
                    self.bundle_dict[p_ingress][ingress] +=1
            elif ingress == p_ingress: # 2a) there is one single prevalent link
                # do nothing since we already incremented totals
                pass
            else:
                self.subnet_dict.get(ip_version, {}).get(mask,{}).get(prange,{})['miss'] +=1

            



    def __decay_counter(self, current_ts, path, last_seen, method="none"): # default, linear, stefan

        ip_version, mask, prange = self.__convert_range_path_to_single_elems(path)
        totc = self.subnet_dict.get(ip_version,{}).get(mask,{}).get(prange, {})['total']
        #matc = self.subnet_dict.get(ip_version,{}).get(mask,{}).get(prange, {})['match']
        misc = self.subnet_dict.get(ip_version,{}).get(mask,{}).get(prange, {})['miss']

        age = (current_ts-self.e) - last_seen

        # TODO decay from total

        self.logger.debug("total: {} miss: {} age:{}".format(totc,misc,age) )
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
            
            totc -= totc * get_clean_keep_factor(age)
            misc -= misc * get_clean_keep_factor(age)

        elif method == "stefan": # 0.1% of min samples for specific mask exponentially increasing by expired time buckets
            s = self.__get_min_samples(path=path, decrement=True)
            reduce = int(math.pow(s, (int(age/t)+1 )))
            misc -= reduce * (misc / totc)
            totc -= reduce


        elif method == "linear":
            if age > self.e:
                reduce = self.__get_min_samples(path=path, decrement=True)
                totc -= linear_decay #reduce * (matc / (matc + misc))
                misc -= linear_decay #reduce * (misc / (matc + misc))
            else:
                return

        elif method == "none":
            return

        self.logger.debug(f"{path} decrement by: {reduce} ({method})")

        self.subnet_dict.get(ip_version,{}).get(mask,{}).get(prange, {})['total'] = int(totc)
        self.subnet_dict.get(ip_version,{}).get(mask,{}).get(prange, {})['miss'] =  int(misc)

    # remove all ips older than e seconds
    def remove_old_ips_from_range(self, current_ts):
        self.logger.info(f"  > remove IPs older than {self.e} seconds")
        pop_list=[]

        ## here we have to distinguish between
        #       already classified prefixes -> decrement function

        for path, ts in dp.search(self.subnet_dict, "**/prevalent_last_seen", yielded=True):
            self.__decay_counter(current_ts=current_ts, path=path, last_seen=ts, method=self.decay_method)


        ##      unclassified prefixies      -> iterate over ip addresses and pop expired ones
        for path, ts in dp.search(self.subnet_dict, "**/last_seen",yielded=True):
            # print(path, ts)
            # age=
            if int(ts)  < current_ts - self.e :
                # self.logger.info("remove old ip: {} ({})".format(path, ts))
                pop_list.append(path)

        self.logger.info("    removing {} expired IP addresses".format(len(pop_list)))
        # b= len(self.subnet_dict["4"]["0"]["0.0.0.0"])
        for path in pop_list:
            try:
                path_elems= path.split("/")
                ip_version=int(path_elems[0])
                mask=int(path_elems[1])
                prange=path_elems[2]
                ip=path_elems[3]

                #dp.delete(self.subnet_dict, path.replace("/last_seen", "")) # too slow
                self.subnet_dict[ip_version][mask][prange].pop(ip)

            except:
                self.logger.warning("    ERROR: {} cannot be deleted".format(path))
                pass



    def dump_to_file(self, current_ts):
        # this should be the output format
        # only dump prevalent ingresses here
        #
        output_file=f"results/q{self.q}_c{self.c[4]}-{self.c[6]}_cidr_max{self.cidr_max[4]}-{self.cidr_max[6]}_t{self.t}_e{self.e}_decay{self.decay_method}"
        os.makedirs(output_file, exist_ok=True)
        output_file += f"/range.{current_ts}.gz"

        self.logger.info(f"dump to file: {output_file}")
        with gzip.open(output_file, 'wb') as ipd_writer:
            # Needs to be a bytestring in Python 3
            with io.TextIOWrapper(ipd_writer, encoding='utf-8') as encode:
                #encode.write("test")
                for p, i in dp.search(self.subnet_dict, "**/prevalent", yielded=True):
                #ipd_writer.write(b"I'm a log message.\n")
                    #if DEBUG:
                    self.logger.debug("{} {}".format(p,i))

                    ip_version, mask, prange = self.__convert_range_path_to_single_elems(p)
                    min_samples=self.__get_min_samples(p)
                    p= p.replace("/prevalent", "")
                    #match_samples=int(dp.get(self.subnet_dict, f"{p}/match"))
                    miss_samples= int(dp.get(self.subnet_dict, f"{p}/miss"))
                    total_samples= int(dp.get(self.subnet_dict, f"{p}/total"))

                    ratio= 1-(miss_samples / total_samples)

                    encode.write(f"{current_ts}\t{ip_version}\trange\t{ratio:.3f}\t{total_samples}/{min_samples}\t{prange}/{mask}\t{i}\n")

    def run_ipd(self, current_ts):
        self.remove_old_ips_from_range(current_ts=current_ts)
        self.is_prevalent_ingress_still_valid() # smehner -> fixed 
        # now go over all already classified ranges        
        
        
        check_list=[]
        buffer_dict={}

        for current_range in list(self.range_lookup_dict[4]) + list(self.range_lookup_dict[6]):
            check_list.append( self.__convert_range_string_to_range_path(current_range))

        while len(check_list) > 0:
            current_range_path = check_list.pop()

            # skip already prevalent ingresses
            ip_version, mask, prange = self.__convert_range_path_to_single_elems(current_range_path)
            if self.subnet_dict[ip_version][mask][prange].get('prevalent', None) != None: continue


            if buffer_dict.get(current_range_path, False):
                buffer_dict.pop(current_range_path)
            else:


                self.logger.info(f"   current_range: {current_range_path}")

                r = self.check_if_enough_samples_have_been_collected(current_range_path)
                if r == True:
                    prevalent_ingress = self.get_prevalent_ingress(current_range_path) # str or None
                    if prevalent_ingress != None:
                        self.logger.info(f"        YES -> color {current_range_path} with {prevalent_ingress}")

                        self.set_prevalent_ingress(current_range_path, prevalent_ingress)
                        continue
                    else:
                        self.logger.info(f"        NO -> split subnet")
                        self.split_range(current_range_path)
                        continue

                elif r == False:
                    self.logger.info("      NO -> join siblings")


                    x = self.join_siblings(current_range_path)
                    if x != None:
                        joined_supernet, sibling_to_pop = x
                        buffer_dict[sibling_to_pop] = True
                        check_list.append(joined_supernet)
            
        
                elif r == None:
                    self.logger.info("skip this range since there is nothing to do here")
                    continue



        if current_ts % bucket_output == 0: # dump every 5 min to file
            self.dump_to_file(current_ts)

        self.logger.debug("bundles: ", self.bundle_dict)
        self.logger.info(".............Finished.............\n\n")

    def run(self):
        
        nf_data = self.read_next_netflow()
        last_ts=None
        add_counter=0

        # run in separate thread
        for nf_row in nf_data:

            # init 
            cur_ts= int(nf_row[0])
            ingress= nf_row[1]
            src_ip = nf_row[2]

            # initial set current ts
            if last_ts == None:  last_ts = cur_ts

            # next epoch?
            if cur_ts > last_ts: 
                self.logger.info(f"added: {add_counter} flows for {cur_ts}")
                print(f"added: {add_counter} flows for {cur_ts}")
            
                last_ts = cur_ts # next epoch
                add_counter=0

                



            # add data for next t seconds
            self.add_to_subnet(last_seen=cur_ts, ingress=ingress, ip=src_ip)
            add_counter+=1

        # run in separate thread
        self.run_ipd(cur_ts)


    def read_next_netflow(self):

        for gzfile in gzfiles:
            with gzip.open(f"{input_path}/{gzfile}", 'rb') as f:
            
                for line in f:
                    line = line.decode('utf-8').split(",")

                    router_name = router_ip_lookup_dict.get(line[1])
                    in_iface = line[2]
                    
                    if len(line) < 15: continue
                    
                    if line[-3] == "TIMESTAMP_END": continue
                    if not ingresslink_dict.get("{}.{}".format(router_name,in_iface), False): continue
                    src_ip = line[4]    
                    cur_ts = int(int(line[-3]) / self.t) * self.t
                    #print(cur_ts, "{}.{}".format(router_name,in_iface), src_ip)
                    yield (cur_ts, "{}.{}".format(router_name,in_iface), src_ip)

def do_it(params):
    ipd = IPD(params)
    ipd.run()

if __name__ == '__main__':    
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', default="/data/slow/mehner/ipd/netflow_merged_sorted", type=str) # netflow100000.csv netflow100000000.csv

    args = parser.parse_args()

    dataset=args.d
    params = namedtuple('params', ['d', 't','b',  'e', 'q', 'c4', 'c6', 'cidrmax4', 'cidrmax6', 'decay', 'loglevel'])
    
    # params(dataset, 60, 0.05, 120, 0.95, 64, 24,28, 48, 'default', logging.INFO)
    
    param_list=[
        params(dataset, 60, 0.05, 120, 0.95, 64, 24, 28, 48, 'default', logging.INFO),
        # e
        params(dataset, 60, 0.05, 30, 0.95, 64, 24, 28, 48, 'default', logging.INFO),
        params(dataset, 60, 0.05, 300, 0.95, 64, 24, 28, 48, 'default', logging.INFO),

        # decay
        params(dataset, 60, 0.05, 120, 0.95, 64, 24, 28, 48, 'none', logging.INFO),
        params(dataset, 60, 0.05, 120, 0.95, 64, 24, 28, 48, 'linear', logging.INFO),
        params(dataset, 60, 0.05, 120, 0.95, 64, 24, 28, 48, 'stefan', logging.INFO),

        # q
        params(dataset, 60, 0.05, 120, 0.90, 64, 24, 28, 48, 'default', logging.INFO),
        params(dataset, 60, 0.05, 120, 0.80, 64, 24, 28, 48, 'default', logging.INFO),
        params(dataset, 60, 0.05, 120, 0.51, 64, 24, 28, 48, 'default', logging.INFO),

        # c 
        params(dataset, 60, 0.05, 120, 0.95, 32, 12,28, 48, 'default', logging.INFO),
        params(dataset, 60, 0.05, 120, 0.95, 4, 1, 28, 48, 'default', logging.INFO),

        # cidrmax
        params(dataset, 60, 0.05, 120, 0.95, 64, 24,24, 44, 'default', logging.INFO),
        params(dataset, 60, 0.05, 120, 0.95, 64, 24,20, 40, 'default', logging.INFO),
        params(dataset, 60, 0.05, 120, 0.95, 64, 24,30, 50, 'default', logging.INFO),
        
        # easy
        params(dataset, 60, 0.05, 300, 0.80, 4, 1, 28, 48, 'default', logging.INFO),
        params(dataset, 60, 0.05, 300, 0.80, 8, 2, 28, 48, 'none', logging.INFO),

        ]
    # do_it(param_list[0])
    pool = Pool(processes=PROCS)
    res= pool.imap(do_it, param_list)


    for a in res:
        print("a, ", a)


    pool.close()
    pool.join()