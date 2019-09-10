#!/bin/sh
arg_num=$#
i=1
hash=crc
bin=ss-cdc
dir=/mnt/nvme1n1/test/ 

#nm='0 1 10 99'
nm='0'
segment_sizes='1'
min_chunk_sizes='2 4 8'
average_chunk_sizes='12 13' 

for min in $min_chunk_sizes; do
	echo min="$min"
	date
	echo ./$bin -d $dir -nm 0 -ss 4 -skip -H crc:p1 -m $min -bmb 14 -cc
	./$bin -d $dir -nm 0 -ss 4 -skip -m $min -bmb 14 -H crc:p1 -cc 
	date
	echo ./$bin -d $dir -nm 0 -ss 4 -skip -H crc:p1 -m $min -bmb 14 -S -cc
	./$bin -d $dir -nm 0 -ss 4 -skip -H crc:p1 -m $min -bmb 14 -S -cc 
done

for chunk_size in $average_chunk_sizes; do
	echo chunk_size="$chunk_size"
	date
	echo ./$bin -d $dir -nm 0 -ss 4 -skip -H crc:p1 -m 2 -bmb $chunk_size -cc
	./$bin -d $dir -nm 0 -ss 4 -skip -H crc:p1 -m 2 -bmb $chunk_size -cc 
	date
	echo ./$bin -d $dir -nm 0 -ss 4 -skip -H crc:p1 -m 2 -bmb $chunk_size -S -cc
	./$bin -d $dir -nm 0 -ss 4 -skip -H crc:p1 -m 2 -bmb $chunk_size -S -cc
done
