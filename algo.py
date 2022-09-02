
from unicodedata import name
import pandas as pd 
import csv
import gzip
import pytricia
from netaddr import *
from collections import defaultdict
import math
import dpath.util as dp 
import io
import os
import argparse
import logging

decay_ingmar_bucket_expire_keep_fraction=0.9
linear_decay = 1000

bundle_indicator=".b_"

# if classified range will be in range dict
# def __range_atts():
    # NOTE last seen will be updated if there is any new IP that belongs to this range
    #   if last_seen < 'current now' - e: drop prefix
    # return {'last_seen': 0, 'ingress': "", 'match' : 0, 'miss' : 0}

# if not yet classified range will be in subnet dict - here ip addresses are monitored
def __subnet_atts():
    return {'last_seen': 0,  'ingress' : ""}

def __multi_dict(K, type):
    if K == 1:
        return defaultdict(type)
    else:
        return defaultdict(lambda: __multi_dict(K-1, type))

# something like range_dict[ip_version][range]{last_seen: ... , ingress: ... , match: ... , miss: ... }
# range_dict=__multi_dict(2, __range_atts)

# something like subnet_dict[ip_version][range][{ip: ... , ingress: ... , last_seen: ... }]
#subnet_dict=__multi_dict(3, __subnet_atts)
subnet_dict=__multi_dict(4, __subnet_atts) # smehner TESTING

# initialization
range_lookup_dict = __multi_dict(1, pytricia.PyTricia) #defaultdict(lambda: pytricia.PyTricia())
range_lookup_dict[4].insert("0.0.0.0/0", "0.0.0.0/0")
range_lookup_dict[6].insert("::/0", "::/0")

bundle_dict={}

## lookup in pytricia tree and return corresponding range
def get_corresponding_range(ip):
    ip_version = 4 if not ":" in ip else 6
    try:
        res =range_lookup_dict[ip_version][ip]
    except:
        logger.warning(f"key error: {ip}")
        logger.debug("  current ranges: {}".format(list(range_lookup_dict[ip_version])))

        res="0.0.0.0/0" if ip_version == 4 else "::/0"
    # logger.info("check corresponding range;  ip: {} ; range: {}".format(ip_address, res))
    return res

def mask_ip(ip_address):
    ip_version = 6 if ":" in ip_address else 4
    return str(IPNetwork(f"{ip_address}/{cidr_max[ip_version]}").network)



def __get_min_samples(path, decrement=False):
        t = path.split("/")
        ip_version = int(t[0])
        cidr = int(t[1])

        if decrement:
            cc= c[ip_version] * 0.001 # take 1% of min_samples as decrement base
        else:
            cc = c[ip_version]


        ipv_max = 32
        if ip_version == 6:
            ipv_max = 128
        min_samples=int(cc * math.sqrt( math.pow(2, (ipv_max - cidr))))

        # logger.info(f"min samples: {min_samples}")
        return min_samples

def __split_ip_and_mask(prefix):
    # prefix should be in this format 123.123.123.123/12 or 2001:db8:abcd:0012::0/64

    ip = prefix.split("/")[0]
    mask = prefix.split("/")[1]

    return str(ip), int(mask)

def __convert_range_string_to_range_path(range_string):
    ip_version = 4 if not ":" in range_string else 6

    prange, mask = range_string.split("/")

    return f"{ip_version}/{mask}/{prange}"

def __convert_range_path_to_single_elems(path):
    t = path.split("/")
    ip_version = int(t[0])
    mask = int(t[1])
    prange= t[2]
    return ip_version, mask, prange

def __sort_dict(dict_to_sort):
    return {k: dict_to_sort[k] for k in sorted(dict_to_sort, key=dict_to_sort.__getitem__, reverse=True)}


def get_sample_count(path):

    ip_version, mask, prange = __convert_range_path_to_single_elems(path)
    logger.debug(path)
    # matc = subnet_dict.get(ip_version,{}).get(mask,{}).get(prange, {}).get('match', -1)
    count = subnet_dict.get(ip_version,{}).get(mask,{}).get(prange, {}).get('total', -1)
    # misc = subnet_dict.get(ip_version,{}).get(mask,{}).get(prange, {}).get('miss', -1)

    if count < 0:

        # if no prevalent ingress exists, count all items
        count= len(subnet_dict.get(ip_version,{}).get(mask,{}).get(prange, {}))

        if count <=0:
            logger.warning(f" key {path} does not exist")
            return -1

    return count

def check_if_enough_samples_have_been_collected(prange):
    logger.info(f"  > Check if enough samples have been collected (s_ipcount >= n_cidr ) {prange}")
    sample_count = get_sample_count(prange)
    if sample_count < 0: # if -1 -> key error
        return None

    min_samples=__get_min_samples(prange)
    logger.debug(f"sample_count: {sample_count} || min_samples= {min_samples}")

    if sample_count >= min_samples:
        # print("    YES → is a single color prevalent ? (s_color >=q)")
        return True
    else:
        return False

# if raw=True: return not prevalent ingress, but dict with counters for all found routers
def get_prevalent_ingress(path, raw=False):

    cur_prevalent=None
    ratio= -1
    sample_count=get_sample_count(path)

    # calculate prevalent ingress
    counter_dict=defaultdict(int)
    result_dict={}

    ip_version, mask, prange = __convert_range_path_to_single_elems(path)
    p_ingress = subnet_dict.get(ip_version, {}).get(mask, {}).get(prange, {}).get('prevalent', None)
    p_total = subnet_dict.get(ip_version, {}).get(mask, {}).get(prange, {}).get('total', None)
    p_miss = subnet_dict.get(ip_version, {}).get(mask, {}).get(prange, {}).get('miss', None)

    if p_ingress != None and p_total != None: # there is a prevalent ingress yet
        if p_total < 1: 
            pr = subnet_dict[ip_version][mask].pop(prange)
            logger.warning(f"p_total < 1: {path} ingress:{p_ingress} total:{p_total} miss:{p_miss} - pop: {pr}")
            
            return None

        ratio = 1- (p_miss / p_total)

        if raw:
            return {p_ingress : (p_total-p_miss), 'miss' : p_miss} # TODO total or matches ?

        if ratio >= q:
            logger.debug(f"        already classified: {p_ingress}: ({ratio:.2f})")
            cur_prevalent=p_ingress
        else:
            logger.warning(f"        prevalent ingress {p_ingress} for {path} below threshold ({ratio})")



    else:
        search_path="{}/**/ingress".format(path)
        for p, v in dp.search(subnet_dict, search_path, yielded=True):
            counter_dict[v]+=1

        # is single ingress prevalent?

        for ingress in counter_dict:
            ratio = counter_dict.get(ingress) / sample_count
            result_dict[ingress] = round(ratio,3)

            # logger.info("       ratio for {}: {:.2f}".format(ingress, ratio))
            if ratio >= q:  # we found a prevalent ingress point!
                cur_prevalent = ingress
                if not raw: break

        # check for bundles
        if cur_prevalent == None: # if we still have not found an ingress, maybe we have a bundle here
            bundle_candidates=set()
            last_value=None
            last_ingress=None
            logger.debug(__sort_dict(result_dict))
            for ingress in __sort_dict(result_dict):
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
                logger.debug(f"bundle candidates: {bundle_candidates}")
                cum_ratio=0
                for i in bundle_candidates: cum_ratio += result_dict.get(i)

                if cum_ratio >= q:
                    # if cum_ratio exceeds q, this will be a bundle
                    cur_prevalent=list(bundle_candidates)
                    ratio = cum_ratio


        if raw:
            logger.debug(f"counter_dict: {counter_dict}")
            return counter_dict


    if cur_prevalent == None:
        ratio = -1
        logger.info("        no prevalent ingress found: {}".format(__sort_dict(result_dict)))

    logger.info("        prevalent for {}: {} ({:.2f})".format(path, cur_prevalent, ratio))

    return cur_prevalent

def set_prevalent_ingress(path, ingress):
    # if an ingress is prevalent we set a 'prevalent' attribute for this path
    # then we can set the counter for miss and match
    # and pop the list with all single ips
    # then we need to distinguish between
    #   already classified ranges => increment counters for misses and matches; decrement by dec_function
    #   not classified ranges = add IPs
    #

    dp.search(subnet_dict, f"{path}/**/ingress")
    match=0
    if type(ingress) == list: # handle bundle
        # count matches for that ingress'es
        bundle_id=len(bundle_dict)+1
        bundle_name="{}{}{}".format(ingress[0].split(".")[0], bundle_indicator, bundle_id)
        # bundle_name+=",".join(ingress)
        # bundle_name+=")"

        tmp_dict=defaultdict(int)
        for p,v in dp.search(subnet_dict, f"{path}/**/ingress", yielded=True):
            if v in ingress:
                tmp_dict[v] +=1
                match +=1

        bundle_dict[bundle_name] = tmp_dict

        ingress=bundle_name


    else: # handle single ingress link

        for p,v in dp.search(subnet_dict, f"{path}/**/ingress", yielded=True):
            if v == ingress: match += 1


    sample_count = get_sample_count(path)

    last_seen=0
    try:   
        last_seen = max(dp.search(subnet_dict, f"{path}/**/last_seen", yielded=True))[1]
    except:
        logging.critical("last_seen not avaliable: {}".format(dp.get(subnet_dict, f"{path}")))


    ip_version, mask, prange = __convert_range_path_to_single_elems(path)

    pr = subnet_dict[ip_version][mask].pop(prange)

    logger.debug(f" remove state for {len(pr)} IPs")
    miss = sample_count-match
    dp.new(subnet_dict, f"{path}/prevalent", ingress)
    # TODO prevalent_
    dp.new(subnet_dict, f"{path}/total", sample_count)
    # dp.new(subnet_dict, f"{path}/match", match)
    dp.new(subnet_dict, f"{path}/miss", miss)
    dp.new(subnet_dict, f"{path}/prevalent_last_seen", last_seen)


    #if DEBUG:
    min_samples=__get_min_samples(path)
    ratio= match / sample_count
    logger.info(f"        set prevalent ingress: {path} => {ingress}: {ip_version} range {ratio:.3f} {sample_count}/{min_samples} {prange}/{mask} {ingress} | miss: {miss} total: {sample_count}")


# iterates over all ranges that are already classified
def is_prevalent_ingress_still_valid():
    logger.info("  > Prevalent color still valid (s_color >= q)")

    check_list=[]
    buffer_dict={}

    currently_prevalent_ingresses = dp.search(subnet_dict, "**/prevalent", yielded=True)

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

        logger.debug(f"    checking {current_prevalent_path}")
        ip_version, mask, prange = __convert_range_path_to_single_elems(current_prevalent_path)
        current_prevalent = subnet_dict[ip_version][mask][prange]['prevalent']

        #current_prevalent= i

        new_prevalent = get_prevalent_ingress(current_prevalent_path)


        # if new_prevalent is list and current_prevalent is bundle string, we split current_prevalent and compare list
        if (current_prevalent == new_prevalent) or ((type(new_prevalent) == list) and (bundle_indicator in current_prevalent) and  (list(bundle_dict.get(current_prevalent).keys()).sort() == sorted(new_prevalent))):
            logger.info("     YES → join siblings ? (join(s_color ) >= q) ")

            r = join_siblings(path=current_prevalent_path, counter_check=False)


            # JOIN and add sibling to buffer dict to pop in next iteration; further add new supernet to check_list
            if r != None:
                joined_supernet, sibling_to_pop = r
                buffer_dict[sibling_to_pop] = True
                check_list.append(joined_supernet)
                check_list.sort()

        else:
            x = subnet_dict[ip_version][mask].pop(prange)
            logger.info(f"     NO → remove all information for {prange}: {x}")
            
            #pop_list.append(p)


def split_range(path):

    ip_version, mask, prange = __convert_range_path_to_single_elems(path)

    if cidr_max[ip_version] <= mask:
        logger.info("    max_cidr reached - do nothing")
        return

    nw= IPNetwork(f"{prange}/{mask}")

    # ip_version = str()
    #print(f"nw: {nw}")
    # add range to pytrcia tree and remove supernet
    info_txt=f"          split {prange}/{mask} into"
    for splitted_nw in nw.subnet(mask+1):
        #logger.info(f"     add {splitted_nw}")
        range_lookup_dict[ip_version].insert(str(splitted_nw), str(splitted_nw))
        info_txt+=f" {splitted_nw} and"
    info_txt= info_txt[:-4]
    logger.info(info_txt)
    # logger.info(f"     del {nw}")

    range_lookup_dict[ip_version].delete(str(nw))

    # now split subnet_dict with all IPs
    change_list=[]
    for p,v  in dp.search(subnet_dict, f"{path}/*", yielded=True): change_list.append((p,v))

    logger.debug("        #items {}; first 3 elems: {}".format(len(change_list), change_list[:3]))
    subnet_dict[ip_version][mask].pop(prange)
    for p,v in change_list:
        try:
            add_to_subnet(ip= p.split("/")[3], ingress=v.get("ingress"), last_seen=v.get("last_seen"))
        except:
            logger.warning(f"         splitting not possible: {p} {v}")


    logger.debug("         range_lookup_dict: {}".format(list(range_lookup_dict[ip_version])))

def join_siblings(path, counter_check=True):
    logger.info(f"        join siblings for range {path}")

    ip_version, mask, prange = __convert_range_path_to_single_elems(path)

    ## check if join would be possible

    if mask == 0:
        logger.info("        join siblings not possible - we are at the root of the tree")
        return None

    nw = IPNetwork(f"{prange}/{mask}")

    #what is the potential sibling?
    nw_supernet=nw.supernet(mask-1)[0]
    supernet_ip=str(nw_supernet).split("/")[0]
    supernet_mask=int(str(nw_supernet).split("/")[1])

    siblings=list(nw_supernet.subnet(mask))
    the_other_one=None
    for sibling in siblings:

        logger.debug(f"sibling: {sibling}")
        # if one of both siblings does not exist -> skip joining
        if range_lookup_dict[ip_version].get(str(sibling), None) == None: return None

        if str(sibling) != f"{prange}/{mask}": the_other_one=str(sibling)


    # would joining satisfy s_color >= q?
    s1=get_prevalent_ingress(__convert_range_string_to_range_path(str(siblings[0])), raw=True)
    s2=get_prevalent_ingress(__convert_range_string_to_range_path(str(siblings[1])), raw=True)

    if (s1 == None or s2 == None) or (len(s1) == 0 and len(s2) == 0):
        logger.warning("        both prefixes are empty")
        logger.debug("lpm lookup: {}".format(list(range_lookup_dict[ip_version])))
        logger.debug("subnet_dict: {} {} {}".format(subnet_dict.get(ip_version, {}).get(supernet_mask, {}).get(supernet_ip,{})))

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
            sibling_dict.update(bundle_dict.get(x))
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
            # logger.info("       ratio for {}: {:.2f}".format(ingress, ratio))
            if ratio >= q:
                logger.debug(f" join would set {ingress} as prevalent for {nw_supernet}")
                
                tmp_cur_prevalent = ingress

    # if join(s_color) >= q  OR join(s_ipcount) < n_cidr-1 => let's join siblings
    if (tmp_cur_prevalent != None) or (tmp_merged_sample_count < __get_min_samples(__convert_range_string_to_range_path(str(nw_supernet))) and counter_check):
        logger.info(f" -> join {siblings[0]} and {siblings[1]} to  {nw_supernet}")
        # if both siblings exists -> delete it from range_lookup_dict and add supernet
        logger.debug("len before: {}".format(len(subnet_dict[ip_version][supernet_mask][supernet_ip].keys())))

        # insert new range to lpm lookup tree
        range_lookup_dict[ip_version].insert(str(nw_supernet), str(nw_supernet))

        # remove old prefixes from subnet_dict and range_lookup_dict
        for sibling in siblings:

            # merge subnet trees to supernet
            logger.debug("{} -> {}".format(sibling, len(subnet_dict[ip_version][mask][str(sibling).split("/")[0]])))
            p= subnet_dict[ip_version][supernet_mask][supernet_ip].update(subnet_dict[ip_version][mask].pop(str(sibling).split("/")[0]))
            logger.debug(f" remove prefix: {p}")
            try:
                range_lookup_dict[ip_version].delete(str(sibling))
            except:
                logger.waning(f"key {sibling} does not exist")
                logger.debug("   {}".format(range_lookup_dict[ip_version]))
                pass
        logger.debug("len now: {}".format(len(subnet_dict[ip_version][supernet_mask][supernet_ip].keys())))

        #       supernet add to list                          sibling that can be removed
        return f"{ip_version}/{supernet_mask}/{supernet_ip}", the_other_one
        # pop_list=[]
        # add_list=[]
        # return f"{ip_version}/{supernet_mask}/{supernet_ip}", pop_list, add_list

    else:
        logger.info(" NO -> do nothing")
        return None


def add_to_subnet(ip, ingress, last_seen):
    # cases:
    #   1) no prevalent ingress for that range found -> add ip and last_seen timestamp
    #   2a) there is one single prevalent link:       -> increment total and increment miss if it is not the correct ingress
    #   2b) there is a prevalent bundle:              -> increment total and increment miss in subnet_dict AND increment matches for ingresses in bundle dict

    ip_version = 4 if not ":" in ip else 6

    masked_ip = mask_ip(ip)
    prange, mask = __split_ip_and_mask(get_corresponding_range(masked_ip))


    # get current prev ingress if existing
    p_ingress=subnet_dict.get(ip_version, {}).get(mask,{}).get(prange,{}).get('prevalent', None)

    if p_ingress==None: # 1) no prevalent ingress found for that range
        dp.new(subnet_dict, [int(ip_version), int(mask), prange, masked_ip, 'last_seen'], int(last_seen))
        dp.new(subnet_dict, [int(ip_version), int(mask), prange, masked_ip, 'ingress'], ingress)

    else: # 2) there is already a prevalent link
        subnet_dict.get(ip_version, {}).get(mask,{}).get(prange,{})['total'] +=1 # increment totals
        subnet_dict.get(ip_version, {}).get(mask,{}).get(prange,{})['prevalent_last_seen'] = int(last_seen)

        if (bundle_indicator in p_ingress) and (ingress in bundle_dict[p_ingress].keys()): # 2b) there is a prevalent bundle:
                bundle_dict[p_ingress][ingress] +=1
        elif ingress == p_ingress: # 2a) there is one single prevalent link
            # do nothing since we already incremented totals
            pass
        else:
            subnet_dict.get(ip_version, {}).get(mask,{}).get(prange,{})['miss'] +=1

        



def __decay_counter(current_ts, path, last_seen, method="none"): # default, linear, stefan

    ip_version, mask, prange = __convert_range_path_to_single_elems(path)
    totc = subnet_dict.get(ip_version,{}).get(mask,{}).get(prange, {})['total']
    #matc = subnet_dict.get(ip_version,{}).get(mask,{}).get(prange, {})['match']
    misc = subnet_dict.get(ip_version,{}).get(mask,{}).get(prange, {})['miss']

    age = (current_ts-e) - last_seen

    # TODO decay from total

    logger.debug("total: {} miss: {} age:{}".format(totc,misc,age) )
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
        s = __get_min_samples(path=path, decrement=True)
        reduce = int(math.pow(s, (int(age/t)+1 )))
        misc -= reduce * (misc / totc)
        totc -= reduce


    elif method == "linear":
        if age > e:
            reduce = __get_min_samples(path=path, decrement=True)
            totc -= 10 #reduce * (matc / (matc + misc))
            misc -= 10 #reduce * (misc / (matc + misc))
        else:
            return

    elif method == "none":
        return

    logger.debug(f"{path} decrement by: {reduce} ({method})")

    subnet_dict.get(ip_version,{}).get(mask,{}).get(prange, {})['total'] = int(totc)
    subnet_dict.get(ip_version,{}).get(mask,{}).get(prange, {})['miss'] =  int(misc)

# remove all ips older than e seconds
def remove_old_ips_from_range(current_ts):
    logger.info(f"  > remove IPs older than {e} seconds")
    pop_list=[]

    ## here we have to distinguish between
    #       already classified prefixes -> decrement function

    for path, ts in dp.search(subnet_dict, "**/prevalent_last_seen", yielded=True):
        __decay_counter(current_ts=current_ts, path=path, last_seen=ts, method=decay_method)


    ##      unclassified prefixies      -> iterate over ip addresses and pop expired ones
    for path, ts in dp.search(subnet_dict, "**/last_seen",yielded=True):
        # print(path, ts)
        # age=
        if int(ts)  < current_ts - e :
            # logger.info("remove old ip: {} ({})".format(path, ts))
            pop_list.append(path)

    logger.info("    removing {} expired IP addresses".format(len(pop_list)))
    # b= len(subnet_dict["4"]["0"]["0.0.0.0"])
    for path in pop_list:
        try:
            path_elems= path.split("/")
            ip_version=int(path_elems[0])
            mask=int(path_elems[1])
            prange=path_elems[2]
            ip=path_elems[3]

            #dp.delete(subnet_dict, path.replace("/last_seen", "")) # too slow
            subnet_dict[ip_version][mask][prange].pop(ip)

        except:
            logger.warning("    ERROR: {} cannot be deleted".format(path))
            pass



def dump_to_file(current_ts):
    # this should be the output format
    # only dump prevalent ingresses here
    #
    output_file=f"results/q{q}_c{c[4]}-{c[6]}_cidr_max{cidr_max[4]}-{cidr_max[6]}_t{t}_e{e}_decay{decay_method}"
    os.makedirs(output_file, exist_ok=True)
    output_file += f"/range.{current_ts}.gz"

    logger.info(f"dump to file: {output_file}")
    with gzip.open(output_file, 'wb') as ipd_writer:
        # Needs to be a bytestring in Python 3
        with io.TextIOWrapper(ipd_writer, encoding='utf-8') as encode:
            #encode.write("test")
            for p, i in dp.search(subnet_dict, "**/prevalent", yielded=True):
            #ipd_writer.write(b"I'm a log message.\n")
                #if DEBUG:
                logger.debug("{} {}".format(p,i))

                ip_version, mask, prange = __convert_range_path_to_single_elems(p)
                min_samples=__get_min_samples(p)
                p= p.replace("/prevalent", "")
                #match_samples=int(dp.get(subnet_dict, f"{p}/match"))
                miss_samples= int(dp.get(subnet_dict, f"{p}/miss"))
                total_samples= int(dp.get(subnet_dict, f"{p}/total"))

                ratio= 1-(miss_samples / total_samples)

                encode.write(f"{current_ts}\t{ip_version}\trange\t{ratio:.3f}\t{total_samples}/{min_samples}\t{prange}/{mask}\t{i}\n")



if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument('-c4', default=64, type=float)
    parser.add_argument('-c6', default=24, type=float)
    parser.add_argument('-t', default=60, type=int)
    parser.add_argument('-b', default=300, type=int)
    parser.add_argument('-e', default=120, type=int)
    parser.add_argument('-q', default=0.95, type=float)
    parser.add_argument('-cidrmax4', default=28, type=int)
    parser.add_argument('-cidrmax6', default=48, type=int)
    parser.add_argument('-d', default="/data/slow/mehner/netflow.csv", type=str) # netflow100000.csv netflow100000000.csv
    parser.add_argument('-decay', default="default", type=str)
    parser.add_argument('-debug', default=False, type=bool)
    parser.add_argument('-loglevel', default="info", type=str)

    
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
    print(f"decay {args.decay}")
    print(f"debug {args.debug}")
    print("------------------------")

    dataset=args.d
    t = args.t #60
    bucket_output = args.b #60
    e=  args.e #120
    q = args.q # 0.80
    decay_method=args.decay
    DEBUG =args.debug

    cidr_max = {
        4: args.cidrmax4,
        6: args.cidrmax6
    }
    c = {
        4: args.c4,
        6: args.c6
    }

    loglev= {"info": logging.INFO,
        "debug": logging.DEBUG,
        "warning": logging.WARNING,
        "critical": logging.CRITICAL}

    ############################################
    ########### LOGGER CONFIGURATION ###########
    ############################################
    os.makedirs("log", exist_ok=True)
    logfile=f"log/q{q}_c{c[4]}-{c[6]}_cidr_max{cidr_max[4]}-{cidr_max[6]}_t{t}_e{e}_decay{decay_method}.log"
    logging.basicConfig(filename=logfile,
                        format='%(asctime)s %(levelname)s %(funcName)s %(message)s',
                        datefmt='%d-%b-%y %H:%M:%S',
                        filemode='w',
                        level=loglev.get(args.loglevel, logging.INFO))



    # Creating an object
    logger = logging.getLogger()
    
    print('read preprocessed netflow file')
    netflow_df= pd.read_csv(dataset, names= ["src_ip","ts_end","ingress"])

    print(f'bin ts_end to {t}s bins and sort by ts')
    netflow_df['ts_end'] = netflow_df.ts_end.apply(lambda x: int(int(x) / t) * t) 
    netflow_df.sort_values(by = 'ts_end', inplace=True)

    for current_ts in sorte (netflow_df.ts_end.unique()):
        cur_slice = netflow_df.loc[netflow_df.ts_end == current_ts]
        
        for i in cur_slice.itertuples():
            add_to_subnet(ip=i.src_ip, ingress=i.ingress, last_seen=i.ts_end)
        logger.info(f"current ts: {current_ts} ({len(cur_slice)})")

        remove_old_ips_from_range(current_ts=current_ts)
        is_prevalent_ingress_still_valid() # smehner -> fixed 
        # now go over all already classified ranges        
        
        
        check_list=[]
        buffer_dict={}

        for current_range in list(range_lookup_dict[4]) + list(range_lookup_dict[6]):
            check_list.append( __convert_range_string_to_range_path(current_range))

        while len(check_list) > 0:
            current_range_path = check_list.pop()

            # skip already prevalent ingresses
            ip_version, mask, prange = __convert_range_path_to_single_elems(current_range_path)
            if subnet_dict[ip_version][mask][prange].get('prevalent', None) != None: continue


            if buffer_dict.get(current_range_path, False):
                buffer_dict.pop(current_range_path)
            else:


                logger.info(f"   current_range: {current_range_path}")

                r = check_if_enough_samples_have_been_collected(current_range_path)
                if r == True:
                    prevalent_ingress = get_prevalent_ingress(current_range_path) # str or None
                    if prevalent_ingress != None:
                        logger.info(f"        YES -> color {current_range_path} with {prevalent_ingress}")

                        set_prevalent_ingress(current_range_path, prevalent_ingress)
                        continue
                    else:
                        logger.info(f"        NO -> split subnet")
                        split_range(current_range_path)
                        continue

                elif r == False:
                    logger.info("      NO -> join siblings")


                    x = join_siblings(current_range_path)
                    if x != None:
                        joined_supernet, sibling_to_pop = x
                        buffer_dict[sibling_to_pop] = True
                        check_list.append(joined_supernet)
            
        
                elif r == None:
                    logger.info("skip this range since there is nothing to do here")
                    continue



        if current_ts % bucket_output == 0: # dump every 5 min to file
            dump_to_file(current_ts)

        logger.debug("bundles: ", bundle_dict)
        logger.info(".............Finished.............\n\n")