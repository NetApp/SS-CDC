#!/bin/sh
arg_num=$#
bin=ss-cdc
dir=/mnt/nvme0n1/$1/ 

#nm='0 1 10 99'
nm='0'
segment_sizes='1'
min_chunk_sizes='2 4 8'
average_chunk_sizes='12 13 14' 

echo "$0 for $1"

for min_chunk_size in $min_chunk_sizes; do

	echo min_chunk_size="$min_chunk_size"
for i in 1 2 3
do
	date
	echo =====$i===== 
	echo ./$bin -d $dir -nm 0 -ss 1 -skip -H crc:p1 -m $min_chunk_size -bmb 14 -cc
	./$bin -d $dir -nm 0 -ss 1 -skip -H crc:p1 -m $min_chunk_size -bmb 14 -cc 
done
done

for chunk_size in $average_chunk_sizes; do

	echo chunk_size="$chunk_size"
for i in 1 2 3
do
	date
	echo =====$i===== 
	echo ./$bin -d $dir -nm 0 -ss 1 -skip -H crc:p1 -m 2 -bmb $chunk_size -cc
	./$bin -d $dir -nm 0 -ss 1 -skip -H crc:p1 -m 2 -bmb $chunk_size -cc 
done
done
