#!/usr/bin/env python3
import csv
import gzip
import pytricia
from netaddr import *
from collections import defaultdict, namedtuple
import math
import io
import os
from time import process_time, time
from json import loads, dump, load
from sys import stdin
import psutil
import argparse
import configparser
import logging


class IPD:
    def __subnet_atts(self):
        return {'last_seen': 0,  'ingress': defaultdict(int), "total": 0}

    def __multi_dict(self, K, type):
        if K == 1:
            return defaultdict(type)
        else:
            return defaultdict(lambda: self.__multi_dict(K-1, type))

    def read_router_ip_mapping(self, router_ip_mapping_file):
        # provided by the ISP
        #
        # this file contains the internal router IP and its name
        #
        # format:
        #   router_ip router_name
        #   50.216.43.22 C1-R1
        #   50.216.43.23 C1-R2
        #   50.216.43.24 C1-R3

        with open(router_ip_mapping_file, 'r') as csv_file:
            router_ip_mapping_csv = csv.reader(csv_file, delimiter=' ')
            router_ip_lookup_dict = {rows[0]: rows[1]
                                     for rows in router_ip_mapping_csv}
        return router_ip_lookup_dict

    def read_ingresslink_file(self, ingresslink_file):
        # provided by the ISP
        #
        # this file contains the interfaces of every router (on a daily base in out case) where the traffic ingresses
        # this is necessary because in Netflow it is not possible to distinguish between ingressing and egressing traffic
        #
        # format:
        #   router name, ingress interface,ASN
        #   PEER_SRC_IP=C1-R1,IN_IFACE=204,&=123
        #   PEER_SRC_IP=C1-R2,IN_IFACE=301,&=456
        #   PEER_SRC_IP=C2-R1,IN_IFACE=207,&=789

        print("> load ingresslink file")
        ingresslink_dict = {}

        with gzip.open("{}".format(ingresslink_file), 'rb') as f:
            for line in f:
                line = line.decode('utf-8').split(",")
                router = line[0].replace("PEER_SRC_IP=", "")
                in_iface = line[1].replace("IN_IFACE=", "")

                # ingresslink_list.append("{}.{}".format(router, in_iface))
                ingresslink_dict["{}.{}".format(router, in_iface)] = True
        print("  ...done\n")

        print(len(ingresslink_dict))
        return ingresslink_dict

    def __init__(self):

        # setting up everything
        self.read_data_finisehd = False
        self.iteration_counter = 0
        self.iteration_counter_dump = 0

        # need PID to extract RAM usage of the process
        self.process = psutil.Process(os.getpid())

        parser = argparse.ArgumentParser()

        config = configparser.ConfigParser()
        config.read('ipd.config')

        # cli parameters
        parser.add_argument('-t', default=config['IPD']['t'], type=int)
        parser.add_argument('-q', default=config['IPD']['q'], type=float)
        parser.add_argument('-cidrmax4', default=config['IPD']['cidr_max_v4'], type=int)
        parser.add_argument('-cidrmax6', default=config['IPD']['cidr_max_v6'], type=int)
        parser.add_argument('-c4', default=config['IPD']['min_samples_v4'], type=float)
        parser.add_argument('-c6', default=config['IPD']['min_samples_v6'], type=float)
        parser.add_argument('-e', default=config['IPD']['e'], type=int)
        parser.add_argument('-decay', default=config['IPD']['decay'], type=str)
        parser.add_argument('-loglevel', default=config['LOGGING']['loglevel'], type=int)
        parser.add_argument('-bundle_delta', default=config['MISC']['allowed_bundle_share_delta'], type=float)

        args = parser.parse_args()

        print("--- parametrization ---")
        print(f"t {args.t}")
        print(f"q {args.q}")
        print(f"cidrmax4 {args.cidrmax4}")
        print(f"cidrmax6 {args.cidrmax6}")
        print(f"c4 {args.c4}")
        print(f"c6 {args.c6}")
        print(f"e {args.e}")
        print(f"decay {args.decay}")
        print(f"b {args.bundle_delta}")
        print(f"loglevel {args.loglevel}")
        print("------------------------")

        # PyTricia uses 32 bit for constructing the trie by default.
        # this is fine for IPv4 but for IPv6 it is not enough, so setting max number of bits to cidrmax6
        def __pytricia_init():
            return pytricia.PyTricia(args.cidrmax6)

        # add 0.0.0.0/0 and ::/0 as starting point for the algorithm
        self.range_lookup_dict = self.__multi_dict(1, __pytricia_init)
        self.range_lookup_dict[4].insert("0.0.0.0/0", "0.0.0.0/0")
        self.range_lookup_dict[6].insert("::/0", "::/0")

        self.min_sample_cache = self.__multi_dict(2, int)

        self.subnet_dict = self.__multi_dict(4, self.__subnet_atts)
        self.ipd_cache = self.__multi_dict(4, dict)
        self.netflow_data_dict = self.__multi_dict(3, int)

        self.bundle_dict = {}
        self.bundle_id = 0
        self.t = args.t
        self.e = args.e
        self.q = args.q
        self.decay_method = args.decay
        self.b = args.bundle_delta
        self.loglevel = args.loglevel

        self.cidr_max = {
            4: args.cidrmax4,
            6: args.cidrmax6
        }
        self.c = {
            4: args.c4,
            6: args.c6
        }

        parameterset_string = f"q{self.q}_c{self.c[4]}-{self.c[6]}_cidr_max{self.cidr_max[4]}-{self.cidr_max[6]}_t{self.t}_e{self.e}_decay{self.decay_method}"

        self.linear_decay = config.getint('MISC', 'linear_decay')
        self.default_decay_keep_fraction = config.getfloat('MISC', 'default_decay_keep_fraction')
        self.bundle_indicator = config['MISC']['bundle_indicator']
        self.output_freq = config.getint('MISC', 'output_freq')
        self.tree_dump_freq = config.getint('MISC', 'tree_dump_freq')

        self.IPv4_ONLY = config.getboolean('GENERAL', 'ip_v4_only')

        self.result_path = config.get('PATH', 'result_path')
        self.result_prefix = config.get('GENERAL', 'result_prefix')

        # get ingress link dict
        self.ingresslink_dict = self.read_ingresslink_file(config['PATH']['ingresslink_file'])

        # get router ip mapping dict
        self.router_ip_lookup_dict = self.read_router_ip_mapping(config['PATH']['router_ip_mapping_file'])

        # get Netflow column mapping
        self.col_mapping = loads(config['NETFLOW']['netflow_column_mapping'])

        self.range_output_folder = f"{self.result_path}/{self.result_prefix}/range/{parameterset_string}"

        self.subnet_output_folder = f"{self.result_path}/{self.result_prefix}/subnet/{parameterset_string}"
        self.tree_output_folder = f"{self.result_path}/{self.result_prefix}/tree/{parameterset_string}"

        os.makedirs(self.subnet_output_folder, exist_ok=True)
        os.makedirs(self.range_output_folder, exist_ok=True)
        if self.tree_dump_freq > 0:
            os.makedirs(self.tree_output_folder, exist_ok=True)

        # RESOURCE LOG
        os.makedirs(f"{self.result_path}/{self.result_prefix}/resource_log", exist_ok=True)
        self.resource_logfile = f"{self.result_path}/{self.result_prefix}/resource_log/{parameterset_string}.log"

        self.init_resource_consumption_logfile()

        ############################################
        ########### LOGGER CONFIGURATION ###########
        ############################################

        os.makedirs(f"{self.result_path}/{self.result_prefix}/log/", exist_ok=True)
        logfile = f"{self.result_path}/{self.result_prefix}/log/{parameterset_string}.log"

        logging.basicConfig(filename=logfile,
                            format='%(asctime)s %(levelname)s %(funcName)s %(message)s',
                            # datefmt='%y-%m-%d %H:%M:%S',
                            filemode="w",
                            level=self.loglevel)

        # Creating an object
        self.logger = logging.getLogger()

    def init_resource_consumption_logfile(self):
        fmode = "w"
        with open(self.resource_logfile, fmode, newline='') as csvfile:
            writer = csv.writer(csvfile, delimiter=',')
            writer.writerow(['ts', 'ipd_ranges_count', 'ipd_cpu_runtime', 'iteration_cpu_runtime',
                            'ipd_runtime', 'iteration_runtime', 'ram_usage', 'shared_ram_usage', 'total_ram', 'avail_ram'])

    def log_resource_consumption(self, cur_ts, range_count, ipd_cpu_runtime, iteration_cpu_runtime, ipd_runtime, iteration_runtime, ram_usage, ram_shared, ram_total, ram_avail):
        with open(self.resource_logfile, 'a', newline='') as csvfile:
            writer = csv.writer(csvfile, delimiter=',')
            writer.writerow([cur_ts, range_count, ipd_cpu_runtime, iteration_cpu_runtime,
                            ipd_runtime, iteration_runtime, ram_usage, ram_shared, ram_total, ram_avail])

    def get_ram_usage(self):

        mem = psutil.virtual_memory()

        # from src code:
        #       This method returns the same information as memory_info(),
        #       plus, on some platform(Linux, macOS, Windows), also provides
        #       additional metrics(USS, PSS and swap).
        #       The additional metrics provide a better representation of actual
        #       process memory usage.
        # rss         RSS       resident set size, the non-swapped physical; memory that a task has used ( in bytes)
        ram_usage = int(self.process.memory_full_info().rss / 1024 / 1024)
        # 'mem_process_shared'
        ram_shared = int(self.process.memory_full_info().shared / 1024 / 1024)
        # 'mem_node_total'
        ram_total = int(mem.total / 1024 / 1024)
        # 'mem_node_available'
        ram_avail = int(mem.available / 1024 / 1024)
        return ram_usage, ram_shared, ram_total, ram_avail

    # lookup in pytricia tree and return corresponding range
    # input: IP str "192.168.0.2"
    # output: range str. "0.0.0.0/0"
    def get_corresponding_range(self, ip):
        ip_version = 4 if not ":" in ip else 6

        if ip == "::":
            return "::/0"

        try:
            res = self.range_lookup_dict[ip_version][ip]
        except:
            self.logger.warning(f"key error: {ip}")
            res = "0.0.0.0/0" if ip_version == 4 else "::/0"
        return res

    # input: IP str "192.168.0.2"
    # output: IP str. "192.168.0.0/28"
    def mask_ip(self, ip_address):
        ip_version = 6 if ":" in ip_address else 4
        return str(IPNetwork(f"{ip_address}/{self.cidr_max[ip_version]}").network)

    def __get_min_samples(self, ip_version, mask):
        cc = self.c[ip_version]

        ipv_max = 32
        if ip_version == 6:
            ipv_max = 64

        min_samples = self.min_sample_cache[ip_version].get(mask, -1)
        if min_samples < 0:
            if ip_version == 4:
                ipv_max = 32
                min_samples = int(cc * math.sqrt(math.pow(2, (ipv_max - mask))))
            elif ip_version == 6:
                ipv_max = 64
                min_samples = int(cc * math.sqrt(math.sqrt(math.pow(2, (ipv_max - mask)))))
            else:
                self.logger.critical(f"ip_version not known: {ip_version}")

            self.min_sample_cache[ip_version][mask] = min_samples

        return max(1, min_samples)

    def __split_ip_and_mask(self, prefix):
        # prefix should be in this format 123.123.123.123/12 or 2001:db8:abcd:0012::0/64
        ip, mask = prefix.split("/")

        return str(ip), int(mask)

     # convert e.g. "0.0.0.0/0" to (4,0,0.0.0.0)
    def __convert_range_string_to_tuple(self, range_string):
        try:
            ip_version = 4 if not ":" in range_string else 6
        except:
            self.logger.warning(f"cannot obtain ipversion -> {range_string}")
        prange, mask = range_string.split("/")

        return (int(ip_version), int(mask), prange)

    def __sort_dict(self, dict_to_sort):
        return {k: dict_to_sort[k] for k in sorted(dict_to_sort, key=dict_to_sort.__getitem__, reverse=True)}

    # get the current samples for a range
    def get_sample_count(self, ip_version, mask, prange):
        count = 0

        # already classified
        try:
            count = self.subnet_dict.get(int(ip_version), {}).get(int(mask), {}).get(prange, {}).get('total', -1)
        except ValueError:
            self.logger.critical(self.range_output_folder)
            self.logger.critical(f"mask: {mask}, ip_version: {ip_version}, prange: {prange}")
            exit(1)

        if type(count) != int:
            self.logger.warning(f"type(count): {type(count)}  {count}")

        # if no prevalent ingress exists, try to get cached data
        if count < 0:
            try:
                count = sum(self.ipd_cache.get(int(ip_version), {}).get(int(mask), {}).get(prange, {}).get('cache', -1).values())
            except:
                # otherwise: count all items
                count = 0

                for masked_ip in self.subnet_dict[ip_version][mask][prange]:
                    count += self.subnet_dict.get(ip_version, {}).get(mask, {}).get(prange, {}).get(masked_ip, {}).get('total', 0)

                if count <= 0 or count == {}:
                    self.logger.info(f" key {ip_version} {mask} {prange} does not exist")
                    self.logger.debug(self.subnet_dict[ip_version][mask])
                    return -1

        return count

    # check if min_samples threshold is reached for this range
    def check_if_enough_samples_have_been_collected(self, ip_version, mask, prange):

        sample_count = self.get_sample_count(ip_version, mask, prange)
        if sample_count < 0:  # if -1 -> key error
            self.logger.info(f"key not found {ip_version} {mask} {prange}")
            return None

        min_samples = self.__get_min_samples(ip_version, mask)

        self.logger.info(
            f"  > Check if enough samples have been collected (s_ipcount >= n_cidr ) {ip_version} {mask} {prange}  s_ipcount={sample_count} min_samples={min_samples}")

        if sample_count >= min_samples:
            return True
        else:
            return False

    # if raw=True: return not prevalent ingress, but dict with counters for all found routers
    def get_prevalent_ingress(self, ip_version, mask, prange, raw=False):

        cur_prevalent = None
        ratio = -1

        # input: counter dict
        # output: prevalent ingress or None
        def __get_prev_ing(counter_dict):
            prevalent_ingress = None
            prevalent_ratio = -1.00

            total = sum(counter_dict.values())

            # single ingresses are handled here
            for ingress in counter_dict.keys():
                ratio = counter_dict[ingress]/total

                if ratio >= self.q:
                    prevalent_ingress = ingress
                    prevalent_ratio = ratio

            if prevalent_ingress == None:  # still no prevalent ingress? -> check for bundles

                self.logger.debug("CHECK FOR BUNDLES NOW")
                bundle_candidates = set()
                last_value = None
                last_ingress = None
                result_dict = __get_shares(counter_dict)
                self.logger.debug(result_dict)

                for ingress in result_dict.keys():
                    value = result_dict.get(ingress)
                    if value < 0.095:  # less than 9.5% share is not interesting; so break in this case
                        break  # since it is sorted; otherwise we should use continue here

                    # first iteration
                    if last_value == None:
                        last_value = value
                        last_ingress = ingress
                        continue

                    # 2nd ... nth iteration
                    if value + self.b >= last_value:
                        # check if there is the same router
                        if len(bundle_candidates) == 0 and (ingress.split(".")[0] == last_ingress.split(".")[0]):
                            bundle_candidates.add(last_ingress)
                            bundle_candidates.add(ingress)
                            # if there are bundle candidates: check if current ingress is same router as before
                        elif len(bundle_candidates) > 0 and (list(bundle_candidates)[0].split(".")[0]) == ingress.split(".")[0]:
                            bundle_candidates.add(ingress)

                    last_value = value
                    last_ingress = ingress

                if len(bundle_candidates) > 0:
                    self.logger.debug(f"bundle candidates: {bundle_candidates}")
                    cum_ratio = 0
                    for i in bundle_candidates:
                        cum_ratio += result_dict.get(i)

                    if cum_ratio >= self.q:
                        # if cum_ratio exceeds q, this will be a bundle
                        prevalent_ingress = list(bundle_candidates)
                        ratio = cum_ratio

                if prevalent_ingress == None:
                    ratio = -1.0
            self.logger.debug(f"        prevalent for {ip_version} {mask} {prange}: {prevalent_ingress} ({prevalent_ratio:.2f})")

            return prevalent_ingress

        def __get_shares(counter_dict):
            total = sum(counter_dict.values())
            tmp_dict = {}
            for ingress in counter_dict.keys():
                ratio = counter_dict.get(ingress) / total
                tmp_dict[ingress] = round(ratio, 3)

            return self.__sort_dict(tmp_dict)
            # there was no prevalent

        # something like this:
        # defaultdict(int,
        # {'C1-R2.157': 5,
        # 'C1-R2.153': 6,
        # 'C3-R10.10': 1,
        # 'C1-R3.17': 1,
        # 'C2-R2.5': 1})
        counter_dict = self.ipd_cache[ip_version][mask][prange].get('cache', defaultdict(int))

        # use cached data
        if len(counter_dict) > 0:
            # if > 0 then we have data
            if raw:
                return counter_dict
            self.logger.debug(f" current shares: {list(__get_shares(counter_dict).items())[:5]}")
            return (__get_prev_ing(counter_dict))

        else:  # calculate everything from new

            result_dict = {}

            p_ingress = self.subnet_dict[ip_version][mask][prange].get('prevalent', None)
            p_total = self.subnet_dict[ip_version][mask][prange].get('total', None)
            p_miss = self.subnet_dict[ip_version][mask][prange].get('miss', None)

            # already classified
            if p_ingress != None and p_total != None:  # there is a prevalent ingress yet
                if p_total < 1:
                    pr = self.subnet_dict[ip_version][mask].pop(prange)
                    self.logger.info(f"p_total < 1: {ip_version} {mask} {prange} ingress:{p_ingress} total:{p_total} miss:{p_miss} - pop: {pr}")

                    return None

                if self.bundle_indicator in p_ingress:

                    pass

                ratio = 1 - (p_miss / p_total)

                counter_dict = {p_ingress: (p_total-p_miss), 'miss': p_miss}

                res = __get_prev_ing(counter_dict)
                if res == None:
                    self.logger.warning(
                        f"        prevalent ingress {p_ingress} for {ip_version} {mask} {prange} below threshold ({ratio}) (will be popped in another step)")

            else:  # not classified yet

                # get all masked ips for current range
                masked_ips_list = list(
                    self.subnet_dict[ip_version][mask][prange].keys())

                while len(masked_ips_list) > 0:
                    masked_ip = masked_ips_list.pop()

                    # iterate over all found ingresses for masked ip -> fill counter_dict
                    for ingress in list(self.subnet_dict[ip_version][mask][prange][masked_ip]['ingress'].keys()):
                        counter_dict[ingress] += self.subnet_dict[ip_version][mask][prange][masked_ip]['ingress'][ingress]

                # is single ingress prevalent?
                cur_prevalent = __get_prev_ing(counter_dict)
                if raw:
                    return counter_dict

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
        if type(ingress) == list:  # bundle
            self.bundle_id += 1
            prevalent_name = "{}{}{}".format(ingress[0].split(".")[0], self.bundle_indicator, self.bundle_id)  # name of bundle
        else:  # single
            prevalent_name = ingress
            # convert single ingress to list to iterate over all ( =1) ingresses
            ingress = [ingress]

        sample_count = sum(
            self.ipd_cache[ip_version][mask][prange]['cache'].values())
        miss = sample_count

        tmp_dict = defaultdict(int)
        for single_ingress in ingress:
            miss -= self.ipd_cache[ip_version][mask][prange]['cache'][single_ingress]
            tmp_dict[single_ingress] += self.ipd_cache[ip_version][mask][prange]['cache'][single_ingress]

        if self.bundle_indicator in prevalent_name:
            self.bundle_dict[prevalent_name] = tmp_dict

        pr = self.subnet_dict[ip_version][mask].pop(prange)

        self.logger.info(f" remove state for {len(pr)} IPs")

        self.subnet_dict[ip_version][mask][prange]['prevalent'] = prevalent_name
        self.subnet_dict[ip_version][mask][prange]['total'] = sample_count
        self.subnet_dict[ip_version][mask][prange]['miss'] = miss
        self.subnet_dict[ip_version][mask][prange]['prevalent_last_seen'] = current_ts

        min_samples = self.__get_min_samples(ip_version, mask)
        ratio = (sample_count - miss) / sample_count
        self.logger.info(
            f"        set prevalent ingress: {ip_version} {mask} {prange} => {prevalent_name}: {ip_version} range {ratio:.3f} {sample_count}/{min_samples} {prange}/{mask} {prevalent_name} | miss: {miss} total: {sample_count}")
        if self.bundle_indicator in ingress:
            self.logger.debug(self.bundle_dict.get(ingress))

    # iterates over all ranges that are already classified
    def is_prevalent_ingress_still_valid(self, ip_version, mask, prange, current_ts):

        self.logger.info("  > Prevalent color still valid (s_color >= q)")

        current_prevalent = self.subnet_dict[ip_version][mask][prange]['prevalent']
        new_prevalent = self.get_prevalent_ingress(ip_version, mask, prange)

        # if new_prevalent is list and current_prevalent is bundle string, we split current_prevalent and compare list
        if (current_prevalent == new_prevalent) or ((type(new_prevalent) == list) and (self.bundle_indicator in current_prevalent) and (list(self.bundle_dict.get(current_prevalent).keys()).sort() == sorted(new_prevalent))):
            self.logger.info("     YES → join siblings ? (join(s_color ) >= q) ")
            return True
        else:
            try:
                x = self.subnet_dict[ip_version][mask].pop(prange)
                if self.bundle_indicator in current_prevalent:
                    self.logger.info(f"remove {current_prevalent} from bundle_dict")
                    self.bundle_dict.pop(current_prevalent)
                    self.logger.info(f"     NO → remove all information for {prange}: {len(x)}")
            except:
                self.logger.warn(f" pop {prange} failed")

            return False

    def split_range(self, ip_version, mask, prange):

        if self.cidr_max[ip_version] <= mask:
            self.logger.info("    cidr_max reached - do nothing")
            return

        nw = IPNetwork(f"{prange}/{mask}")

        # add range to pytrcia tree and remove supernet
        info_txt = f"          split {prange}/{mask} into"
        for splitted_nw in nw.subnet(mask+1):
            self.range_lookup_dict[ip_version].insert(str(splitted_nw), str(splitted_nw))
            info_txt += f" {splitted_nw} and"
        info_txt = info_txt[:-4]
        self.logger.debug(info_txt)

        self.range_lookup_dict[ip_version].delete(str(nw))
        masked_ip_list = list(self.subnet_dict[ip_version][mask][prange].keys())

        self.logger.debug(f"        #items {len(masked_ip_list)}")

        # move ingress links and sample counters to the splitted subnets
        for masked_ip in masked_ip_list:
            try:
                for ingress in self.subnet_dict[ip_version][mask][prange][masked_ip].get("ingress").keys():
                    last_seen = self.subnet_dict[ip_version][mask][prange][masked_ip].get("last_seen")
                    i_count = self.subnet_dict[ip_version][mask][prange][masked_ip][("ingress")][ingress]
                    self.add_to_subnet(masked_ip=masked_ip, ingress=ingress, last_seen=last_seen, i_count=i_count)
            except:
                self.logger.warning(f"         splitting not possible: {ip_version} {mask} {prange} {masked_ip}")

        # pop parent range if splitting is done
        self.subnet_dict[ip_version][mask].pop(prange)

    def join_siblings(self, ip_version, mask, prange, current_ts, counter_check=True):
        self.logger.debug(f"        join siblings for range {ip_version} {mask} {prange}")

        # check if join would be possible
        if mask == 0:
            self.logger.debug("        join siblings not possible - we are at the root of the tree")
            return None

        nw = IPNetwork(f"{prange}/{mask}")

        # get supernet
        nw_supernet = nw.supernet(mask-1)[0]
        supernet_ip = str(nw_supernet).split("/")[0]
        supernet_mask = int(str(nw_supernet).split("/")[1])

        # get siblings
        siblings = list(nw_supernet.subnet(mask))
        the_other_one = None

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
                self.logger.debug(f"sibling does not exist: {str(sibling)} - abort joining")
                return None

            if str(sibling) != f"{prange}/{mask}":
                the_other_one = str(sibling)

        # remove expired ips from the other one
        self.remove_expired_ips_from_range(ip_version, int(
            the_other_one.split('/')[1]), the_other_one.split('/')[0], current_ts)

        # first get counter_dicts from both siblings
        s1_ip_version, s1_mask, s1_prange = self.__convert_range_string_to_tuple(str(siblings[0]))
        s1 = self.get_prevalent_ingress(s1_ip_version, s1_mask, s1_prange, raw=True)

        s2_ip_version, s2_mask, s2_prange = self.__convert_range_string_to_tuple(str(siblings[1]))
        s2 = self.get_prevalent_ingress(s2_ip_version, s2_mask, s2_prange, raw=True)

        # if empty -> make an empty dict instead of None
        s1 = s1 if s1 != None else {}
        s2 = s2 if s2 != None else {}

        if (len(s1) == 0 and len(s2) == 0):
            self.logger.debug("both prefixes have no prevalent ingress")

        # s1 or s2 return
        #   a dict with ingress router {"C5-R9.12" : matching samples, "miss" : miss samples}
        #   a dict with all routers and there counters
        #   a dict with bundle id: {"C6-R32.b_xxxx" : matching samples, "miss" : miss samples}
        for sibling_dict in [s1, s2]:
            # input {'C5-R9.b_123': 123141, 'miss': 32}
            for x in [i for i in sibling_dict.keys() if self.bundle_indicator in i]:
                sibling_dict.update(self.bundle_dict.get(x))
                sibling_dict.pop(x)

                # now we have a dict with all ingress links separately
                # e.g. {'miss': 32, 'C5-R9.12': 61000, 'C5-R9.10': 61571}

        # now check if we will get a prevalent ingress in case of joining
        tmp_merged_counter_dict = {k: s1.get(k, 0) + s2.get(k, 0) for k in set(s1) | set(s2)}
        tmp_merged_sample_count = sum(tmp_merged_counter_dict.values())

        tmp_cur_prevalent = None
        for ingress in tmp_merged_counter_dict:
            ratio = tmp_merged_counter_dict.get(ingress) / tmp_merged_sample_count

            if ratio >= self.q:
                self.logger.debug(f"    join possible: join would set {ingress} as prevalent for {nw_supernet}")

                tmp_cur_prevalent = ingress
            else:
                self.logger.debug("    join not possible")
                pass

        # if join(s_color) >= q  OR join(s_ipcount) < n_cidr-1 => let's join siblings
        min_samples = self.__get_min_samples(ip_version, supernet_mask)
        if (tmp_cur_prevalent != None) or (tmp_merged_sample_count < min_samples and counter_check):

            self.logger.info(f" begin to join {siblings[0]} and {siblings[1]} to  {nw_supernet}")
            # if both siblings exists -> delete it from self.range_lookup_dict and add supernet
            self.logger.debug("len before: {}".format(len(list(self.subnet_dict[ip_version][supernet_mask][supernet_ip].keys()))))

            # insert new range to lpm lookup tree
            self.range_lookup_dict[ip_version].insert(
                str(nw_supernet), str(nw_supernet))

            # remove old prefixes from self.subnet_dict and self.range_lookup_dict
            for sibling in siblings:

                # merge subnet trees to supernet
                self.logger.debug("{} -> {}".format(sibling, len(self.subnet_dict[ip_version][mask][str(sibling).split("/")[0]])))
                p = self.subnet_dict[ip_version][supernet_mask][supernet_ip].update(
                    self.subnet_dict[ip_version][mask].pop(str(sibling).split("/")[0]))
                self.logger.debug(f" remove prefix: {p}")
                try:
                    self.range_lookup_dict[ip_version].delete(str(sibling))
                except:
                    self.logger.warning(f"key {sibling} does not exist - cannot remove from LPM lookup tree")
                    pass
            self.logger.debug("len now: {}".format(len(list(self.subnet_dict[ip_version][supernet_mask][supernet_ip].keys()))))

            #     supernet add to list   sibling that can be removed
            return str(nw_supernet), str(the_other_one)

        else:
            self.logger.info(" NO -> do nothing")
            return None

    def add_to_subnet(self, masked_ip, ingress, last_seen, i_count=1):
        # cases:
        #   1) no prevalent ingress for that range found  -> add ip and last_seen timestamp
        #   2a) there is one single prevalent link:       -> increment total and increment miss if it is not the correct ingress
        #   2b) there is a prevalent bundle:              -> increment total and increment miss in self.subnet_dict AND increment matches for ingresses in bundle dict

        ip_version = 4 if not ":" in masked_ip else 6

        prange, mask = self.__split_ip_and_mask(self.get_corresponding_range(masked_ip))

        # get current prev ingress if existing
        p_ingress = self.subnet_dict.get(ip_version, {}).get(mask, {}).get(prange, {}).get('prevalent', None)

        if p_ingress == None:  # 1) no prevalent ingress found for that range

            self.subnet_dict[int(ip_version)][int(mask)][prange][masked_ip]['last_seen'] = int(last_seen)
            self.subnet_dict[int(ip_version)][int(mask)][prange][masked_ip]['ingress'][ingress] += i_count
            self.subnet_dict[int(ip_version)][int(mask)][prange][masked_ip]['total'] += i_count

        else:  # 2) there is already a prevalent link

            self.subnet_dict.get(ip_version, {}).get(mask, {}).get(prange, {})['total'] += i_count  # increment totals
            self.subnet_dict.get(ip_version, {}).get(mask, {}).get(prange, {})['prevalent_last_seen'] = int(last_seen)

            # 2b) there is a prevalent bundle:
            if (self.bundle_indicator in p_ingress) and (ingress in self.bundle_dict[p_ingress].keys()):
                self.bundle_dict[p_ingress][ingress] += i_count

                self.logger.debug(f"  already classified as bundle - {self.bundle_dict[p_ingress]}")

            elif ingress == p_ingress:  # 2a) there is one single prevalent link
                # do nothing since we already incremented totals
                pass
            else:
                self.subnet_dict.get(ip_version, {}).get(mask, {}).get(prange, {})['miss'] += i_count

    # default, linear, none
    def __decay_counter(self, ip_version, mask, prange, current_ts, method="none"):

        self.logger.debug(f"{ip_version} {mask} {prange}")
        # 4/2/64.0.0.0
        totc = self.subnet_dict.get(ip_version, {}).get(mask, {}).get(prange, {})['total']
        misc = self.subnet_dict.get(ip_version, {}).get(mask, {}).get(prange, {})['miss']
        last_seen = self.subnet_dict.get(ip_version, {}).get(mask, {}).get(prange, {})['prevalent_last_seen']
        prevalent_ingress = self.subnet_dict.get(ip_version, {}).get(mask, {}).get(prange, {})['prevalent_ingress']

        if type(last_seen) != int:
            self.logger.warning(self.subnet_dict.get(ip_version, {}).get(mask, {}).get(prange, {}))
        age = (current_ts-self.e) - last_seen

        self.logger.debug("current_ts: {}; e: {}; last_seen: {}; age:{} total: {} miss: {} ".format(current_ts, self.e, last_seen, age, totc, misc))
        reduce = 0
        if method == 'default':

            def get_clean_keep_factor(age):
                x = float(self.default_decay_keep_fraction) / (int(age / self.t) + 1) if age > 0 else self.default_decay_keep_fraction
                return 1 - x

            reduce = get_clean_keep_factor(age)
            totc -= totc * get_clean_keep_factor(age)
            misc -= misc * get_clean_keep_factor(age)

            if (self.bundle_indicator in prevalent_ingress):
                total = sum(self.bundle_dict[prevalent_ingress].values())

                for cur_ing in self.bundle_dict[prevalent_ingress].keys():
                    cur_val = self.bundle_dict[prevalent_ingress][cur_ing]
                    self.bundle_dict[prevalent_ingress][cur_ing] -= cur_val * reduce * (cur_val / total)

        elif method == "linear":
            if age > self.e:

                totc -= self.linear_decay
                misc -= self.linear_decay
            else:
                return

            if (self.bundle_indicator in prevalent_ingress):
                total = sum(self.bundle_dict[prevalent_ingress].values())

                for cur_ing in self.bundle_dict[prevalent_ingress].keys():
                    cur_val = self.bundle_dict[prevalent_ingress][cur_ing]
                    self.bundle_dict[prevalent_ingress][cur_ing] -= self.linear_decay * (cur_val / total)

        elif method == "none":
            return

        self.logger.debug(
            f" {ip_version} {mask} {prange} decrement by: {reduce} ({method})")

        self.subnet_dict.get(ip_version, {}).get(mask, {}).get(prange, {})['total'] = int(totc)
        self.subnet_dict.get(ip_version, {}).get(mask, {}).get(prange, {})['miss'] = int(misc)

    # remove all ips older than e seconds
    def remove_expired_ips_from_range(self, ip_version, mask, prange, current_ts):
        # first step after inserting new IPs into ranges for current time bucket
        # check for attribute 'prevalent_last_seen'
        #   -> Y: classified range: decay_counter method
        #   -> N: iterate over all underlying (masked) IPs and check every single IP if it is expired
        #  (-> we set the cache_ts here too, so we will override old data
        #    there is only one for loop for the masked IPs for the current range)

        counter_dict = defaultdict(int)

        self.logger.info(f"  > remove IPs older than {self.e} seconds")

        # here we have to distinguish between
        if self.subnet_dict[ip_version][mask][prange].get("prevalent_last_seen", None) != None:

            #       already classified prefixes -> decrement function
            total_before = self.subnet_dict[ip_version][mask][prange].get("total")

            self.__decay_counter(ip_version, mask, prange, current_ts=current_ts, method=self.decay_method)

            total_now = self.subnet_dict[ip_version][mask][prange].get("total")
            self.logger.info(f"decay {ip_version} {mask} {prange}, {current_ts}: total before: {total_before}; total now: {total_now}")

            if total_now < self.__get_min_samples(ip_version, mask):
                self.logger.info(f"!!!  {ip_version} {mask} {prange} below min_samples -> remove all information")
                self.subnet_dict[ip_version][mask].pop(prange)

                # get current prevalent ingress to remove it from bundle dict if necessary
                prevalent = self.subnet_dict[ip_version][mask][prange].get("prevalent")
                if (prevalent != None) and (self.bundle_indicator in prevalent):
                    self.logger.info(f"remove {prevalent} from bundle_dict")
                    self.bundle_dict.pop(prevalent)
        else:

            # unclassified prefixies      -> iterate over ip addresses and pop expired ones
            count_counter = 0
            pop_counter = 0
            masked_ip_list = list(self.subnet_dict[ip_version][mask][prange].keys())

            while len(masked_ip_list) > 0:

                masked_ip = masked_ip_list.pop()

                last_seen = 0

                count_counter += self.subnet_dict[ip_version][mask][prange][masked_ip]['total']
                try:
                    last_seen = self.subnet_dict[ip_version][mask][prange][masked_ip].get("last_seen", -1)

                except:
                    self.logger.warning(f"last seen not here: {masked_ip} {self.subnet_dict[ip_version][mask][prange][masked_ip]}")

                if last_seen < 0:
                    self.logger.warning(f"no last seen found ->  {ip_version} {mask} {prange}")
                    continue

                if last_seen < current_ts - self.e:
                    try:
                        x = self.subnet_dict[ip_version][mask][prange].pop(masked_ip)
                        # pop_counter +=1
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
            self.logger.debug(
                f"count before: {count_counter} - expired {pop_counter} = now: {sum(counter_dict.values())} check: {count_counter-pop_counter}")
            # TODO update 'total' self.subnet_dict[ip_version][mask][prange]['total']
            self.ipd_cache[ip_version][mask][prange]['cache'] = counter_dict

            self.logger.info(f"     {ip_version} {mask} {prange}: {pop_counter} IPs expired")

    def dump_tree_to_file(self, current_ts):
        with open(f"{self.tree_output_folder}/{current_ts}.json", "w") as outfile:
            dump(self.subnet_dict, outfile, indent=4)
        with open(f"{self.tree_output_folder}/{current_ts}_bundles.json", "w") as outfile:
            dump(self.bundle_dict, outfile, indent=4)
        with open(f"{self.tree_output_folder}/{current_ts}_cache.json", "w") as outfile:
            dump(self.ipd_cache, outfile, indent=4)

        tmp_dict = self.__multi_dict(2, int)

        # get v4 and v6 lpm
        for ipv in self.range_lookup_dict.keys():
            # get all items
            for item in list(self.range_lookup_dict[ipv]):
                tmp_dict[ipv][item] = self.range_lookup_dict[ipv][item]
        with open(f"{self.tree_output_folder}/{current_ts}_range_lpm.json", "w") as outfile:
            dump(tmp_dict, outfile, indent=4)
        tmp_dict.clear()
        tmp_dict = {}
        self.logger.debug("PROFILING: dump tree to filesystem - done")

    #                                           range || subnet
    def dump_ranges_to_file(self, current_ts, what="range"):
        # format:
        # unix_ts, ip_version, 'range', confidence, samples/samplesneeded, range, ingress router
        # 1612001700      4       range   1.000   12732733/139022 64.0.0.0/7     C1-R2.710
        # 1612001700      4       range   0.998   13527047/69511  128.0.0.0/9     C1-R2.110
        # 1612001700      4       range   0.993   17985418/69511  128.128.0.0/9   C1-R2.117

        if what == "subnet":
            output_file = f"{self.subnet_output_folder}/{what}.{current_ts}.gz"

        elif what == "range":
            output_file = f"{self.range_output_folder}/{what}.{current_ts}.gz"
        else:
            self.logger.warning(f"don't know what to dump! -> {what} is unknown")
            return

        self.logger.info(f"dump to file: {output_file}")
        with gzip.open(output_file, 'wb') as ipd_writer:

            with io.TextIOWrapper(ipd_writer, encoding='utf-8') as encode:

                for ip_version in self.subnet_dict.keys():
                    for mask in self.subnet_dict[ip_version].keys():
                        for prange in self.subnet_dict[ip_version][mask].keys():

                            ingress = self.subnet_dict[ip_version][mask][prange].get('prevalent', None)
                            min_samples = self.__get_min_samples(ip_version, mask)

                            # range files only contain classified ranges; subnet files contain everything
                            if what == 'range' and ingress == None:
                                continue

                            # subnet and range with no prevalent ingress
                            elif what == 'subnet' and ingress == None:
                                ingress_summary = defaultdict(int)
                                total_samples = 0

                                # get all ingress routers and counters for every masked_ip for the current range
                                for masked_ip, details in self.subnet_dict[ip_version][mask][prange].items():
                                    total_samples += details.get('total', 0)
                                    for ingress_key, count in details.get('ingress', {}).items():
                                        ingress_summary[ingress_key] += count

                                if ingress_summary:
                                    # Sort ingress_summary by value in descending order
                                    sorted_ingress = dict(sorted(ingress_summary.items(), key=lambda item: item[1], reverse=True))

                                    # Extract the ingress key with the highest count
                                    top_ingress_key, top_count = next(iter(sorted_ingress.items()))

                                    # Convert the sorted ingress_summary to a string representation
                                    ingress_str = ','.join(f"{key}={value}" for key, value in sorted_ingress.items())
                                    ingress = f"{top_ingress_key}({ingress_str})"

                                    ratio = top_count/total_samples
                                else:
                                    # skip empty ranges
                                    continue

                            # should be range or subnet and ingres != None
                            else:
                                try:
                                    miss_samples = int(self.subnet_dict[ip_version][mask][prange]['miss'])
                                    total_samples = int(self.subnet_dict[ip_version][mask][prange]['total'])
                                except:
                                    continue

                                if min_samples > total_samples:
                                    self.logger.warning(f"total count lower than min samples: {total_samples} / {min_samples}")
                                    self.logger.warning(f"{self.subnet_dict[ip_version][mask][prange]}")
                                ratio = 1-(miss_samples / total_samples)

                            self.logger.info(
                                f"{current_ts}\t{ip_version}\t{what}\t{ratio:.3f}\t{total_samples}/{min_samples}\t{prange}/{mask}\t{ingress}")
                            encode.write(f"{current_ts}\t{ip_version}\t{what}\t{ratio:.3f}\t{total_samples}/{min_samples}\t{prange}/{mask}\t{ingress}\n")

        self.logger.info(f"dump finished")

    # this method is called every IPD iteration
    def run_ipd(self, current_ts):

        # list with all pranges that need to be processed in the current iteration
        check_list = []

        self.logger.info(f"prepare check_list")
        tmp_check_list = list(self.range_lookup_dict[4]) + list(self.range_lookup_dict[6])

        # convert e.g. 0.0.0.0/0 to (4,0,0.0.0.0)
        for elem in tmp_check_list:
            check_list.append(self.__convert_range_string_to_tuple(elem))

        current_ram_usage_bytes = int(self.process.memory_info().rss / 1024 / 1024)  # in bytes -> MB

        self.logger.warning(f"............. run IPD {current_ts}  -> {len(check_list)} elems  RAM: {current_ram_usage_bytes} .............")

        # debugging purpose
        for ipv in self.subnet_dict.keys():
            for mask in self.subnet_dict[ipv].keys():
                self.logger.warning(f" ipv{ipv} mask: {mask} -> {len(self.subnet_dict[ipv][mask].keys())}")

        # process ramges
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
                    x = self.join_siblings(ip_version, mask, prange, current_ts=current_ts, counter_check=False)
                    if x != None:
                        supernet, other_one = x
                        check_list.append(self.__convert_range_string_to_tuple(supernet))
                        if other_one != None:
                            try:
                                check_list.remove(self.__convert_range_string_to_tuple(other_one))
                            except:
                                pass

            else:
                r = self.check_if_enough_samples_have_been_collected(ip_version, mask, prange)
                if r == True:
                    prevalent_ingress = self.get_prevalent_ingress(ip_version, mask, prange)  # str or None
                    if prevalent_ingress != None:
                        self.logger.info(f"        YES -> color {ip_version} {mask} {prange} with {prevalent_ingress}")

                        self.set_prevalent_ingress(ip_version, mask, prange, prevalent_ingress, current_ts)
                        continue
                    else:
                        self.logger.info(f"        NO -> split subnet")
                        self.split_range(ip_version, mask, prange)
                        continue

                elif r == False:
                    self.logger.info("      NO -> join siblings")

                    x = self.join_siblings(ip_version, mask, prange, current_ts=current_ts, counter_check=True)
                    if x != None:
                        supernet, other_one = x
                        check_list.append(self.__convert_range_string_to_tuple(supernet))
                        if other_one != None:
                            try:
                                check_list.remove(self.__convert_range_string_to_tuple(other_one))
                            except:
                                pass

                elif r == None:
                    self.logger.info("skip this range since there is nothing to do here")
                    continue

        # dump subnet, range and the full tree
        self.iteration_counter += 1
        if self.tree_dump_freq > 0:
            self.iteration_counter_dump += 1

        if self.iteration_counter == self.output_freq:
            self.dump_ranges_to_file(current_ts, what="range")
            self.dump_ranges_to_file(current_ts, what="subnet")
            self.iteration_counter = 0

        if self.tree_dump_freq > 0 and self.iteration_counter_dump == self.tree_dump_freq:
            self.dump_tree_to_file(current_ts)
            self.logger.warning(f"dump state at {current_ts} to disk")
            self.iteration_counter_dump = 0

        self.logger.debug("bundles: {}".format(self.bundle_dict))
        self.logger.warning(".............Finished.............\n")
        self.ipd_cache.clear()

    def run(self):

        # start NF reader
        if self.IPv4_ONLY:
            self.logger.warning("!!! IPv4 Traffic only !!!")

        # init generator
        nf_data = self.read_netflow()
        last_ts = None
        add_counter = 0
        ipd_t_end = 0
        ipd_cpu_t_end = 0

        # iterate over all netflow rows using our generator
        for nf_row in nf_data:
            # init
            cur_ts = int(nf_row[0])

            ingress = nf_row[1]
            src_ip = nf_row[2]
            masked_ip = self.mask_ip(src_ip)

            # initial set current ts
            if last_ts == None:
                last_ts = cur_ts

            # next epoch?
            if cur_ts > last_ts:
                self.logger.debug(f"{self.range_output_folder}\t{last_ts}\tflows added: {add_counter}")
                print(f"{self.range_output_folder}\t{last_ts}\tflows added: {add_counter} ")
                add_counter = 0

                # measure time for ipd run
                ipd_cpu_t_start = process_time()
                ipd_t_start = time()

                self.run_ipd(cur_ts)

                last_ipd_cpu_t_end = ipd_cpu_t_end if ipd_cpu_t_end > 0 else process_time()
                last_ipd_t_end = ipd_t_end if ipd_t_end > 0 else time()

                ipd_cpu_t_end = process_time()
                ipd_t_end = time()

                ipd_cpu_runtime = ipd_cpu_t_end - ipd_cpu_t_start
                ipd_runtime = ipd_t_end - ipd_t_start

                iteration_runtime = ipd_t_end - last_ipd_t_end
                iteration_cpu_runtime = ipd_cpu_t_end - last_ipd_cpu_t_end

                print(f"IPD RUNTIME cpu: {ipd_cpu_runtime:.3f} wall: {ipd_runtime:.3f}")

                # header of resource_logfile
                # cur_ts, RAM usage from memory_info, RAM usage from memory_full_info, shared_ram, total_ram, availale_ram,
                ram_usage, ram_shared, ram_total, ram_avail = self.get_ram_usage()
                ranges_count = len(list(self.range_lookup_dict[4]) + list(self.range_lookup_dict[6]))
                self.log_resource_consumption(cur_ts, ranges_count, f'{ipd_cpu_runtime:.4f}', f'{iteration_cpu_runtime:.4f}',
                                              f'{ipd_runtime:.4f}', f'{iteration_runtime:.4f}', ram_usage, ram_shared, ram_total, ram_avail)

                last_ts = cur_ts  # next epoch

            self.add_to_subnet(last_seen=cur_ts, masked_ip=masked_ip, ingress=ingress, i_count=1)
            add_counter += 1

    # reads netflow from stdin

    def read_netflow(self):
        for line in stdin:

            line = line.split(self.col_mapping.get('sep'))
            router_name = self.router_ip_lookup_dict.get(line[self.col_mapping.get('peer_src_ip')])

            if self.IPv4_ONLY:
                ip_version = 4 if not ":" in line[self.col_mapping.get(
                    'src_ip')] else 6
                if ip_version == 6:
                    continue

            in_iface = line[self.col_mapping.get('in_iface')]

            if len(line) < 4:
                continue

            if line[self.col_mapping.get('ts_end')] == "TIMESTAMP_END":
                continue
            if not self.ingresslink_dict.get("{}.{}".format(router_name, in_iface), False):
                continue
            src_ip = line[self.col_mapping.get('src_ip')]
            cur_ts = int(int(line[self.col_mapping.get('ts_end')]) / self.t) * self.t

            yield (cur_ts, "{}.{}".format(router_name, in_iface), src_ip)

    def read_netflow_worker(self):
        print("start read_netflow_worker ")
        nf_data = self.read_netflow()
        last_ts = None
        add_counter = 0

        for nf_row in nf_data:
            # init
            cur_ts = int(nf_row[0])
            ingress = nf_row[1]
            src_ip = nf_row[2]
            masked_ip = self.mask_ip(src_ip)

            # initial set current ts
            if last_ts == None:
                last_ts = cur_ts

            # next epoch?
            if cur_ts > last_ts:
                self.logger.debug(f"{self.range_output_folder}\t{last_ts}\tflows added: {add_counter}")
                print(f"{self.range_output_folder}\t{last_ts}\tflows added: {add_counter} ")

                add_counter = 0

                last_ts = cur_ts  # next epoch

            # add data for next t seconds
            # self.add_to_subnet(last_seen=cur_ts, ingress=ingress, ip=src_ip)
            # add all masked_ip's with same router for current ts
            self.netflow_data_dict[cur_ts][masked_ip][ingress] += 1
            add_counter += 1

        print("finish read_netflow_worker ")
        self.netflow_data_dict[-1] = None


if __name__ == '__main__':
    ipd = IPD()
    ipd.run()
