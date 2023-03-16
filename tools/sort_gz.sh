#!/bin/zsh

# . =env_parallel.zsh
# we have 26 parsers and n hours of netflow 
# 1 file = 1 hour

netflow_path="/data/slow/mehner/ipd/netflow_recording/parser_"
BASE="/data/slow/mehner/ipd"
output_path="$BASE/netflow_merged_sorted"
input_path="$BASE/netflow_merged"
tmp_path="$BASE/tmp"


# merge_gz() {
#   echo "start  netflow_path$parser/archived/$1"
#   for parser in {00..25}; do
#     zcat "$netflow_path$parser/archived/$1" 
#   done | gzip -c > "$output_path/$1"
#   echo "   done"
# }


#env_parallel merge_gz {} ::: 
for gzfile in @000000000000001605556860.gz @000000000000001605560460.gz @000000000000001605564060.gz @000000000000001605567660.gz @000000000000001605571260.gz @000000000000001605574860.gz @000000000000001605578460.gz @000000000000001605582060.gz @000000000000001605585660.gz @000000000000001605589260.gz @000000000000001605592860.gz @000000000000001605596460.gz @000000000000001605600060.gz @000000000000001605603660.gz @000000000000001605607260.gz @000000000000001605610860.gz @000000000000001605614460.gz @000000000000001605618060.gz @000000000000001605621660.gz @000000000000001605625260.gz @000000000000001605628860.gz @000000000000001605632460.gz @000000000000001605636060.gz @000000000000001605639660.gz @000000000000001605643260.gz; do
  echo $gzfile
  mkdir -pv $tmp_path/$gzfile
  zcat $input_path/$gzfile | sort --temporary-directory=$tmp_path/$gzfile  --parallel=64 --field-separator="," --key=13 --buffer-size=500000M |gzip  > $output_path/$gzfile # | gzip
done

#sort --temporary-directory=DIR  --parallel=64 --field-separator="," --key=13 --buffer-size=400000M --output_file 