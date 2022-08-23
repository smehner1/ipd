
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


##################################
### PROTOTYPING IPDRange Class ###
##################################


### DICT implementation

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


## lookup in pytricia tree and return corresponding range
def get_corresponding_range(ip):
    ip_version = 4 if not ":" in ip else 6
    try:
        res =range_lookup_dict[ip_version][ip]
    except:
        if DEBUG: print("KEYERROR: ", ip)
        if DEBUG: print("  current ranges:", list(range_lookup_dict[ip_version]))
    
        res="0.0.0.0/0" if ip_version == 4 else "::/0"
    # if DEBUG: print("check corresponding range;  ip: {} ; range: {}".format(ip_address, res))
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

        if DEBUG: print(f"min samples: {min_samples}")
        return min_samples

def __split_ip_and_mask(prefix):
    # prefix should be in this format 123.123.123.123/12 or 2001:db8:abcd:0012::0/64

    ip = prefix.split("/")[0]
    mask = prefix.split("/")[1]
        
    return str(ip), int(mask)

def __convert_range_string_to_range_path(range_string):
    ip_version = 4 if not ":" in range_string else 6

    range, mask = range_string.split("/")

    return f"{ip_version}/{mask}/{range}"

def __convert_range_path_to_single_elems(path):
    t = path.split("/")
    ip_version = int(t[0])
    mask = int(t[1])
    range= t[2]
    return ip_version, mask, range
            

def get_sample_count(path):
    count=0
    ip_version, mask, range = __convert_range_path_to_single_elems(path)
    if DEBUG: print (path)
    matc = subnet_dict.get(ip_version,{}).get(mask,{}).get(range, {}).get('match', -1)
    misc = subnet_dict.get(ip_version,{}).get(mask,{}).get(range, {}).get('miss', -1)

    
    count = matc+misc

    if count < 0: 
        
        # if no prevalent ingress exists, count all items 
        count= len(subnet_dict.get(ip_version,{}).get(mask,{}).get(range, {}))
        
        if count <=0:
            if DEBUG: print("ERROR: key {} does not exist".format(path))
            return -1
        else:
            return count

def check_if_enough_samples_have_been_collected(range):
    if DEBUG: print("  > Check if enough samples have been collected (s_ipcount >= n_cidr ) ")
    sample_count = get_sample_count(range)
    if sample_count < 0: # if -1 -> key error
        return None

    min_samples=__get_min_samples(range)
    if DEBUG: print(f"sample_count: {sample_count} || min_samples= {min_samples}")
    if sample_count >= min_samples:
        # print("    YES → is a single color prevalent ? (s_color >=q)")            
        return True
    else:
        return False

# if verbose=True: return not prevalent ingress, but dict with counters for all found routers
def get_prevalent_ingress(path, raw=False):
    def __init_with_zero():
        return 0
    
    cur_prevalent=None
    sample_count=get_sample_count(path)

    # calculate prevalent ingress
    counter_dict=defaultdict(__init_with_zero)
    result_dict={}
    search_path="{}/**/ingress".format(path)
    for p, v in dp.search(subnet_dict, search_path, yielded=True): 
        counter_dict[v]+=1

    try:
        p_ingress= dp.get(subnet_dict, f"{path}/prevalent")
        p_match= dp.get(subnet_dict, f"{path}/match")
        p_miss= dp.get(subnet_dict, f"{path}/miss")

        # if there is no match - it cannot be prevalent and we avoid div by zero case
        if p_match == 0: return None
        
        ratio = p_match / (p_match+p_miss)
    
        if raw:
            return {p_ingress : p_match, 'miss' : p_miss}

        if ratio >= q:
            if DEBUG: print(f"        already classified: {p_ingress}: ({ratio:.2f})")
            cur_prevalent=p_ingress
        else:
            if DEBUG: print(f"        WARNING: prevalent ingress {p_ingress} for {path} below threshold ({ratio})")

    except KeyError:

        ratio= -1
        for ingress in counter_dict:
            ratio = counter_dict.get(ingress) / sample_count
            result_dict[ingress] = round(ratio,3)
            # if DEBUG: print("       ratio for {}: {:.2f}".format(ingress, ratio))
            if ratio >= q: 
                cur_prevalent = ingress
                if not raw:
                    break

        if raw:
            return counter_dict

    if cur_prevalent == None: 
        ratio = -1
        if DEBUG: 
            print(" no prevalent ingress found: ") 

            #sorted_value_index = np.argsort(result_dict.values())
            dictionary_keys = list(result_dict.keys())
            sorted_dict = {dictionary_keys[i]: sorted(result_dict.values(), reverse=True)[i] for i in range(len(dictionary_keys))}
    
            print(sorted_dict)


    if DEBUG: print("        prevalent for {}: {} ({:.2f})".format(path, cur_prevalent, ratio))

    return cur_prevalent
    
def set_prevalent_ingress(path, ingress):
    # TODO if an ingress is prevalent we set a 'prevalent' attribute for this path 
    # TODO then we can set the counter for miss and match
    # TODO and pop the list with all single ips
    # TODO then we need to distinguish between 
    #   already classified ranges => increment counters for misses and matches; decrement by dec_function
    #   not classified ranges = add IPs 
    #               
    dp.new(subnet_dict, f"{path}/prevalent", ingress)
    sample_count = get_sample_count(path)

    match=0
    for p,v in dp.search(subnet_dict, f"{path}/**/ingress", yielded=True): 
        if v == ingress: match += 1 

    last_seen = max(dp.search(subnet_dict, f"{path}/**/last_seen", yielded=True))[1]

    ip_version, mask, range = __convert_range_path_to_single_elems(path)
    tmp_counter=len(subnet_dict[ip_version][mask][range])
    pr = subnet_dict[ip_version][mask].pop(range)
    if DEBUG: print(f" remove state for all IPs in {pr}")
    dp.new(subnet_dict, f"{path}/prevalent", ingress)
    dp.new(subnet_dict, f"{path}/match", match)
    dp.new(subnet_dict, f"{path}/miss", sample_count - match)
    dp.new(subnet_dict, f"{path}/last_seen", last_seen)

    
    #if DEBUG: 
    print(f"SET PREVALENT INGRESS: {path} => {ingress}       counter values - match: {match}  miss: {sample_count-match}  sample_count: {sample_count} (last_seen: {last_seen}) ------ {tmp_counter}")


# iterates over all ranges that are already classified
def is_prevalent_ingress_still_valid():
    if DEBUG: print("  > Prevalent color still valid (s_color >= q)")
    
    pop_list=[]
    for p, i in dp.search(subnet_dict, "**/prevalent", yielded=True): 
        if DEBUG: print(f"    checking {p}")
            
        current_prevalent= i

        new_prevalent = get_prevalent_ingress(p)

        if current_prevalent == new_prevalent:
            if DEBUG: print("     YES → join siblings ? (join(s_color ) >= q) ")
            while True:
                r = join_siblings(path=p, counter_check=False)
                if r != None:
                    if DEBUG: print("       YES → join siblings and check again ")
                else:
                    if DEBUG: print("       NO → do nothing ")
                    break

        else:
            if DEBUG: print(f"     NO → remove all information for {p}")
            pop_list.append(p)
    
    for p in pop_list:
        ip_version, mask, range = __convert_range_path_to_single_elems(p)
        subnet_dict[ip_version][mask].pop(range)

        # range_lookup_dict[ip_version].delete(f"{range}/{mask}")



def split_range(path):
    if DEBUG: print(f"        split range {path}")
    
    ip_version, mask, range = __convert_range_path_to_single_elems(path)

    if cidr_max[ip_version] <= mask:
        if DEBUG: print("    max_cidr reached - do nothing")
        return
    
    nw= IPNetwork(f"{range}/{mask}")
    
    # ip_version = str()
    #print(f"nw: {nw}")
    # add range to pytrcia tree and remove supernet 
    info_txt=f"          split {range}/{mask} into"
    for splitted_nw in nw.subnet(mask+1):
        #if DEBUG: print(f"     add {splitted_nw}")
        range_lookup_dict[ip_version].insert(str(splitted_nw), str(splitted_nw))
        info_txt+=f" {splitted_nw} and"
    info_txt= info_txt[:-4]
    if DEBUG: print(info_txt)
    # if DEBUG: print(f"     del {nw}")

    range_lookup_dict[ip_version].delete(str(nw))

    # now split subnet_dict with all IPs 
    change_list=[]
    for p,v  in dp.search(subnet_dict, f"{path}/*", yielded=True): change_list.append((p,v))

    if DEBUG: print("        #items {}; first 3 elems: {}".format(len(change_list), change_list[:3]))
    subnet_dict[ip_version][mask].pop(range)
    for p,v in change_list: 
        try:
            add_to_subnet(ip= p.split("/")[3], ingress=v.get("ingress"), last_seen=v.get("last_seen"))
        except:
            if DEBUG: print("ERROR while splitting: ", p, v)

    if DEBUG: print("         ", list(range_lookup_dict[4]))

def join_siblings(path, counter_check=True):
    if DEBUG: print(f"        join siblings for range {path}")

    ip_version, mask, range = __convert_range_path_to_single_elems(path)
    
    ## check if join would be possible 

    if mask == 0:
        if DEBUG: print("    join siblings not possible - we are at the root of the tree")
        return None

    nw = IPNetwork(f"{range}/{mask}")
    if DEBUG: print("NET", nw)

    #what is the potential sibling?
    nw_supernet=nw.supernet(mask-1)[0]
    supernet_ip=str(nw_supernet).split("/")[0]
    supernet_mask=int(str(nw_supernet).split("/")[1])

    siblings=list(nw_supernet.subnet(mask))
    for sibling in siblings:
        if DEBUG: print("SIBLING: ", sibling)
        # if one of both siblings does not exist -> skip joining
        if range_lookup_dict[ip_version].get(str(sibling), None) == None: return None

    # would joining satisfy s_color >= q?
    s1=get_prevalent_ingress(__convert_range_string_to_range_path(str(siblings[0])), raw=True)
    s2=get_prevalent_ingress(__convert_range_string_to_range_path(str(siblings[1])), raw=True)

    if DEBUG: print(s1)
    if DEBUG: print(s2)


    tmp_merged_counter_dict =  {k: s1.get(k, 0) + s2.get(k, 0) for k in set(s1) | set(s2)}
    tmp_merged_sample_count = sum(tmp_merged_counter_dict.values())
    
    tmp_cur_prevalent = None
    for ingress in tmp_merged_counter_dict:
            ratio = tmp_merged_counter_dict.get(ingress) / tmp_merged_sample_count
            # if DEBUG: print("       ratio for {}: {:.2f}".format(ingress, ratio))
            if ratio >= q: 
                if DEBUG: print(f" HEY HEY -> join would set {ingress} as prevalent for {nw_supernet}")
                tmp_cur_prevalent = ingress
    

    # if join(s_color) >= q  OR join(s_ipcount) < n_cidr-1 => let's join siblings
    if (tmp_cur_prevalent != None) or (tmp_merged_sample_count < __get_min_samples(__convert_range_string_to_range_path(str(nw_supernet))) and counter_check):
        if DEBUG: print(f" HEY I AM SO EXICITED -> join {siblings[0]} and {siblings[1]} to  {nw_supernet}")
        # if both siblings exists -> delete it from range_lookup_dict and add supernet
        if DEBUG: print("len before: {}".format(len(subnet_dict[ip_version][supernet_mask][supernet_ip].keys())))
        
        range_lookup_dict[ip_version].insert(str(nw_supernet), str(nw_supernet))
        for sibling in siblings:
            if DEBUG: print("sibling: ", sibling)

            # merge subnet trees to supernet 
            if DEBUG: print("{} -> {}".format(sibling, len(subnet_dict[ip_version][mask][str(sibling).split("/")[0]])))
            subnet_dict[ip_version][supernet_mask][supernet_ip].update(subnet_dict[ip_version][mask].pop(str(sibling).split("/")[0]))
            try:
                range_lookup_dict[ip_version].delete(str(sibling))
            except:
                if DEBUG: print(f"KEYERROR {sibling} does not exist")
                if DEBUG: print("   {}".format(range_lookup_dict[ip_version]))
                pass
        if DEBUG: print("len now: {}".format(len(subnet_dict[ip_version][supernet_mask][supernet_ip].keys())))
        return f"{ip_version}/{supernet_mask}/{supernet_ip}"    
    else:
        if DEBUG: print(" NO -> do nothing")
        return None

def add_to_subnet(ip, ingress, last_seen):
    # something like subnet_dict[ip_version][range][ip]{ingress: ... , last_seen: ... }]
    # if DEBUG: print("adding ", ip, ingress, last_seen)

    ip_version = 4 if not ":" in ip else 6

    masked_ip = mask_ip(ip)
    range, mask = __split_ip_and_mask(get_corresponding_range(masked_ip))
    

    # if subnet is already prevalent -> do not add IPs but increment counters
    p_ingress=subnet_dict.get(ip_version, {}).get(mask,{}).get(range,{}).get('prevalent', None)
    if p_ingress!=None:
        if ingress == p_ingress:
            subnet_dict.get(ip_version, {}).get(mask,{}).get(range,{})['match'] +=1
            #if DEBUG: print(f"({masked_ip},{ingress},{last_seen}) : {p_ingress} == {ingress} --> counter: {subnet_dict.get(ip_version, {}).get(mask,{}).get(range,{})['match']}" )
        else:
            subnet_dict.get(ip_version, {}).get(mask,{}).get(range,{})['miss'] +=1
            #if DEBUG: print(f"({masked_ip},{ingress},{last_seen}) : {p_ingress} != {ingress} --> counter: {subnet_dict.get(ip_version, {}).get(mask,{}).get(range,{})['miss']}" )
        subnet_dict.get(ip_version, {}).get(mask,{}).get(range,{})['prevalent_last_seen'] = int(last_seen)
    else:
        # key is not existing
        dp.new(subnet_dict, [int(ip_version), int(mask), range, masked_ip, 'last_seen'], int(last_seen))
        dp.new(subnet_dict, [int(ip_version), int(mask), range, masked_ip, 'ingress'], ingress)
        # if DEBUG: print("adding ", ip, ingress, last_seen)
    

def __decay_counter(current_ts, path, last_seen, method="none"): # default, linear, stefan

    # sub getCleanKeepFactor{
    #   (my $expireTime, my $lastUpdate) = @_;

    #   my $age = $expireTime - $lastUpdate;
    #   return 1 - (($age <= 0) ? $bucketExpireKeepFraction : ($bucketExpireKeepFraction/(int($age/$bucketSize)+1)));
    # }
    # my $reduce = int($cidrIntRef->{ip}{$color}{$ipInt}{c} * (getCleanKeepFactor($expireTime, $cidrIntRef->{ip}{$color}{$ipInt}{u})));

    # $cidrIntRef->{ip}{$color}{$ipInt}{c} -= $reduce;
    ip_version, mask, range = __convert_range_path_to_single_elems(path)
    matc = subnet_dict.get(ip_version,{}).get(mask,{}).get(range, {})['match'] 
    misc = subnet_dict.get(ip_version,{}).get(mask,{}).get(range, {})['miss'] 

    age = current_ts - last_seen


    print (matc, misc, age)
    reduce = 0
    if method == 'default':
        
        if age <=0:
            reduce = bucketExpireKeepFraction / (int(age/t)+1 )
        else: 
            reduce = bucketExpireKeepFraction

        matc *= reduce
        misc *= reduce

    elif method == "stefan": # 0.1% of min samples for specific mask exponentially increasing by expired time buckets
        s = __get_min_samples(path=path, decrement=True) 
        reduce = int(math.pow(s, (int(age/t)+1 )))
        matc -= reduce * (matc / (matc + misc))
        misc -= reduce * (misc / (matc + misc))

    elif method == "linear":
        if age > e: 
            reduce = __get_min_samples(path=path, decrement=True)
            matc -= 10 #reduce * (matc / (matc + misc))
            misc -= 10 #reduce * (misc / (matc + misc))
        else:
            return

    elif method == "none":
        return
    if DEBUG: print(f"{path} decrement by: {reduce} ({method})")

    subnet_dict.get(ip_version,{}).get(mask,{}).get(range, {})['match'] = int(matc)
    subnet_dict.get(ip_version,{}).get(mask,{}).get(range, {})['miss'] =  int(misc)

# remove all ips older than e seconds
def remove_old_ips_from_range(current_ts):
    if DEBUG: print(f"  > remove IPs older than {e} seconds")
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
            # if DEBUG: print("remove old ip: {} ({})".format(path, ts))
            pop_list.append(path)

    if DEBUG: print("    removing {} expired IP addresses".format(len(pop_list)))
    # b= len(subnet_dict["4"]["0"]["0.0.0.0"])
    for path in pop_list: 
        try:
            path_elems= path.split("/")
            ip_version=int(path_elems[0])
            mask=int(path_elems[1])
            range=path_elems[2]
            ip=path_elems[3]
            
            #dp.delete(subnet_dict, path.replace("/last_seen", "")) # too slow
            subnet_dict[ip_version][mask][range].pop(ip)

        except:
            if DEBUG: print("    ERROR: {} cannot be deleted".format(path))
            pass
    


def dump_to_file(current_ts):
    # this should be the output format
    # only dump prevalent ingresses here
    # 
    output_file=f"results/q{q}_c{c[4]}-{c[6]}_cidr_max{cidr_max[4]}-{cidr_max[6]}_t{t}_e{e}_decay{decay_method}"
    os.makedirs(output_file, exist_ok=True)
    output_file += f"/range.{current_ts}.gz"
    print(f"DUMP TO FILE {output_file}")
    with gzip.open(output_file, 'wb') as ipd_writer:
        # Needs to be a bytestring in Python 3
        with io.TextIOWrapper(ipd_writer, encoding='utf-8') as encode:
            #encode.write("test")
            for p, i in dp.search(subnet_dict, "**/prevalent", yielded=True): 
            #ipd_writer.write(b"I'm a log message.\n")
                #if DEBUG: 
                print(p,i)
                ip_version, mask, range = __convert_range_path_to_single_elems(p)
                min_samples=__get_min_samples(p)
                p= p.replace("/prevalent", "")
                match_samples=int(dp.get(subnet_dict, f"{p}/match"))
                miss_samples= int(dp.get(subnet_dict, f"{p}/miss"))
                samples= match_samples+miss_samples #get_sample_count(p)
                ratio=match_samples/(match_samples+miss_samples)

                encode.write(f"{current_ts}\t{ip_version}\trange\t{ratio:.3f}\t{samples}/{min_samples}\t{range}/{mask}\t{i}\n")




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


    print("min_sanples /10: {}".format(__get_min_samples("4/10/")))
    print("min_sanples /20: {}".format(__get_min_samples("4/20/")))
    print("min_sanples /28: {}".format(__get_min_samples("4/28/")))
    print()


    
    





    print('read preprocessed netflow file')
    netflow_df= pd.read_csv(dataset, names= ["src_ip","ts_end","ingress"])

    print(f'bin ts_end to {t}s bins and sort by ts')
    netflow_df['ts_end'] = netflow_df.ts_end.apply(lambda x: int(int(x) / t) * t) 
    netflow_df.sort_values(by = 'ts_end', inplace=True)

    for current_ts in sorted(netflow_df.ts_end.unique()):
        
        if DEBUG: print("\n\n ..........................")
        if DEBUG: print( "CURRRENT RUN: {}".format(current_ts))
        if DEBUG: print("..........................")

        cur_slice = netflow_df.loc[netflow_df.ts_end == current_ts]
        
        for i in cur_slice.itertuples():
            add_to_subnet(ip=i.src_ip, ingress=i.ingress, last_seen=i.ts_end)
        
        if DEBUG: print(f"current ts: {current_ts}")
        remove_old_ips_from_range(current_ts=current_ts)

        is_prevalent_ingress_still_valid()

        # now go over all already classified ranges        
        for current_range in list(range_lookup_dict[4]) + list(range_lookup_dict[6]):
            if DEBUG: print(f"\n   current_range: {current_range}")

            # dpath path
            current_range_path = __convert_range_string_to_range_path(current_range)
            
            while True:
                r = check_if_enough_samples_have_been_collected(current_range_path)
                if r == True:
                    prevalent_ingress = get_prevalent_ingress(current_range_path) # str or None
                    if prevalent_ingress != None:
                        if DEBUG: print(f"        YES -> color {current_range_path} with {prevalent_ingress}")
                        # TODO color range with link color
                        set_prevalent_ingress(current_range_path, prevalent_ingress)
                        break
                    else:
                        if DEBUG: print(f"        NO -> split subnet")
                        split_range(current_range_path)
                        break

                elif r == False:
                    if DEBUG: print("      NO -> join siblings")
                    current_range_path = join_siblings(current_range_path)

                    if current_range_path == None: break
                
                elif r == None:
                    if DEBUG: print("skip this range since there is nothing to do here")
                    break
        #if current_ts % bucket_output == 0: # dump every 5 min to file
        dump_to_file(current_ts)
        if DEBUG: print("\n   -------------- \n")