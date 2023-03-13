import pandas as pd
import sys

input_file=sys.argv[1]

output_file=sys.argv[2]
# split netflow files into multiple ones -> convert this smal ones to parquet

print(f"{input_file.split('/')[-1]} --> {output_file.split('/')[-1]}")
df = pd.read_csv(input_file, compression="gzip", sep=" ", names=['peer_src_ip', 'in_iface', 'src_ip', 'ts'])#, nrows=10000000)
df.to_parquet(output_file)

# convert reduced netflow gz txt files to parquet
# split gz
# execute:
#  cd /data/slow/mehner/ipd/netflow_merged_sorted_reduced
#  parallel -j 10  '''x={1}; pre=$(echo $x:t:r |sed "s|@00000000000000||"); echo $x ; split $x ../netflow_merged_sorted_reduced_splitted/"$pre"_ --lines=10000 -a 6 -d '''  ::: $(ls)

