#!/bin/zsh

reduced_nf_path="/data/slow/mehner/ipd/netflow_merged_sorted_reduced"
#reduced_splitted_nf_path="/data/slow/mehner/ipd/netflow_merged_sorted_reduced_splitted"

reduced_splitted_nf_path="/data/slow/mehner/ipd/netflow_merged_sorted_reduced_parquet/test"
reduced_splitted_pq_nf_path="/data/slow/mehner/ipd/netflow_merged_sorted_reduced_parquet/test_pq"

BASE=$(pwd)

convert_script="/home/mehneste/ipd_algo/convert_gz_to_parquet.py"

# split nf files
# rm -Rf $reduced_splitted_nf_path
# mkdir -pv $reduced_splitted_nf_path

# cd $reduced_nf_path


# for i in $(ls $reduced_nf_path);
# do
#     echo $i
#     ts=$(echo $i |sed 's|@00000000000000||' |sed 's|.gz||')
#     echo $ts
#     zcat $reduced_nf_path/$i | parallel -l500000 --block 100m --pipe gzip ">" ./test/1605582060_{#}.gz 
# done

#rename all with padding
#rename 's/(\d+)(?=.*\.)/sprintf("%06d",$1)/eg' $reduced_splitted_nf_path/*

#mkdir $reduced_splitted_pq_nf_path

# for i in $(ls $reduced_splitted_nf_path);
# do
#     echo $i

#     $convert_script $reduced_splitted_nf_path/$i $reduced_splitted_pq_nf_path/$i.pq
# done

parallel -j 20 python3 $convert_script $reduced_splitted_nf_path/{1} $reduced_splitted_pq_nf_path/{1}.pq ::: $(ls $reduced_splitted_nf_path)



#cd $reduced_splitted_nf_path
#parallel 