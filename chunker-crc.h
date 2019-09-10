#ifndef CHUNKER_CRC_H_H
#define CHUNKER_CRC_H_H
#if 0
#define doCrc(hash, cbytes) {\
					__m512i idx= _mm512_and_epi32(_mm512_xor_epi32(hash,cbytes), cmask);\
					__m512i tentry = _mm512_setr_epi32(\
							crct[vector_idx(idx, 0)], crct[vector_idx(idx, 1)], crct[vector_idx(idx, 2)], crct[vector_idx(idx,3)],\
							crct[vector_idx(idx, 4)], crct[vector_idx(idx, 5)], crct[vector_idx(idx, 6)], crct[vector_idx(idx, 7)],\
							crct[vector_idx(idx, 8)], crct[vector_idx(idx, 9)], crct[vector_idx(idx, 10)], crct[vector_idx(idx, 11)],\
							crct[vector_idx(idx, 12)], crct[vector_idx(idx, 13)], crct[vector_idx(idx, 14)], crct[vector_idx(idx, 15)]);\
					hash = _mm512_srli_epi32(hash, 8);\
					cbytes = _mm512_srli_epi32(cbytes, 8);\
					hash = _mm512_xor_epi32(hash,tentry);}
#else
#define doCrc(hash, cbytes) {\
					__m512i idx= _mm512_and_epi32(_mm512_xor_epi32(hash,cbytes), cmask);\
					__m512i tentry = _mm512_i32gather_epi32(idx, crct, 4);\
					hash = _mm512_srli_epi32(hash, 8);\
					cbytes = _mm512_srli_epi32(cbytes, 8);\
					hash = _mm512_xor_epi32(hash,tentry);}
#endif
					

static inline void doCrc_serial_crc(uint32_t c, uint32_t* x)
{
	*x = (*x >> 8) ^ crct[(*x ^ c) & 0xff];
}


int chunking_phase_one_serial_crc(struct file_struct *fs){
	uint64_t n_bytes_left;
	uint64_t offset = 0;

	n_bytes_left = fs->test_length;
	if(fs->length <= HASHLEN || fs->length<= min_chunksize) {
				//printf("Serial: For file with %lu bytes, no chunking\n", fs->length);
				// set remaining bitmap to 0000...1
				return 0;
	}

	//fs->length = segment_size * 16;
	uint32_t hash = 0;
	uint8_t *str = (uint8_t *)fs->map;
	int local_offset = 0;

	if (skip_mini == 0){
		while( offset < fs->test_length ){
			if(offset < HASHLEN){
				doCrc_serial_crc(str[offset], &hash);	
				offset++;
				continue;
			}

			hash^=crcu[str[offset-HASHLEN]];
			doCrc_serial_crc(str[offset], &hash);
			if((hash & break_mask) == magic_number){
				uint8_t b = fs->breakpoint_bm_base[offset/8];
				b |= 1<<offset%8;
				fs->breakpoint_bm_base[offset/8] = b;
				//printf("hash %x offset %d left %x right %x\n", hash, offset, str[offset-HASHLEN], str[offset]);
			}
			offset++;
		}
	} else{
		uint32_t last_offset = 0;
		while( offset < fs->test_length ){
			if(local_offset < HASHLEN){
				doCrc_serial_crc(str[offset], &hash);	
				local_offset ++;
				offset++;
				continue;
			}

			hash^=crcu[str[offset-HASHLEN]];
			doCrc_serial_crc(str[offset], &hash);
			if(offset-last_offset >= min_chunksize && (hash & break_mask) == magic_number){
				uint8_t b = fs->breakpoint_bm_base[offset/8];
				b |= 1<<offset%8;
				fs->breakpoint_bm_base[offset/8] = b;
				//printf("hash %x offset %d left %x right %x\n", hash, offset, str[offset-HASHLEN], str[offset]);
				last_offset = offset;
				offset+=min_chunksize-HASHLEN;
				local_offset = 0;
			}else
				offset+=1;
		}
	}
	return 0;
}


	int chunking_phase_one_parallel_crcv1(struct file_struct *fs){
		__m512i vindex = _mm512_setr_epi32(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15);
		__m512i mm_break_mark = _mm512_set1_epi32(break_mask);
		__m512i cmask = _mm512_set1_epi32(0xff);
		__m512i mm_zero = _mm512_set1_epi32(0);
		uint64_t n_bytes_left;
		uint64_t offset = 0;
		uint32_t cur_segsize, last_segsize;

		n_bytes_left = fs->test_length;
	//printf("%x to test\n", n_bytes_left);
	
	uint32_t bytes_per_thread, bytes_last_thread;
	bytes_per_thread = (n_bytes_left/16)/32*32;
	bytes_last_thread = n_bytes_left - bytes_per_thread*15;
	//printf("Parallel: %u bytes %u bytes\n", bytes_per_thread, bytes_last_thread);
	
	
	int i=0;
	__m512i hash = mm_zero;
	while (n_bytes_left > 0){
		if (n_bytes_left >= n_threads*segment_size){
			cur_segsize = last_segsize = segment_size;
			n_bytes_left -= n_threads*segment_size;
		}else{
			if (n_bytes_left <= n_threads * HASHLEN || n_bytes_left <= min_chunksize){
				printf("Parallel: For file with %lu bytes, no chunking with min=%u max=%u\n", n_bytes_left, n_threads*HASHLEN, min_chunksize);
				// set remaining bitmap to 0000...1
				return 0;
			}

			cur_segsize = n_bytes_left/n_threads/32*32;
			last_segsize = n_bytes_left-cur_segsize*(n_threads-1);
			n_bytes_left = 0;
		}

		//printf("Processing data stream at [0X%x-0X%x-1]: 0x%x bytes/thread parallel\n", offset, offset+cur_segsize*n_threads, cur_segsize);
		// For the first HASHLEN bytes, calculate hash value
		for (; i<HASHLEN; i+=4){
			__m512i cbytes = _mm512_i32gather_epi32(vindex*bytes_per_thread, (void*)((uint8_t*)fs->map+offset+i), 1);
			//__m512i cbytes = _mm512_i32gather_epi32(vindex*cur_segsize, (void*)((uint8_t*)fs->map+offset+i), 1);
			//doCrc: x = (x >> 8) ^ crct[(x ^ c) & 0xff];
			for (int j=0; j<sizeof(int); j++){
				doCrc(hash, cbytes);
			}
		}

		// For the next bytes in the segment, rolling
		__m512i mm_bm = mm_zero;
		__m512i bm;
		i = HASHLEN;
		for(; i<cur_segsize+HASHLEN; i+=4){
			__m512i left_cbytes = _mm512_i32gather_epi32(vindex*bytes_per_thread, (void*)((uint8_t*)fs->map+offset+i-HASHLEN), 1);
			__m512i cbytes = _mm512_i32gather_epi32(vindex*bytes_per_thread, (void*)(((uint8_t*)fs->map)+offset+i), 1);
			__m512i idx2 = _mm512_and_epi32(left_cbytes, cmask);
			//__m512i mm_bm = _mm512_set1_epi32(0);
			if (i%32 == 0){
				mm_bm = mm_zero;
			}

			//if(i+cur_segsize*3>=0x14a0 && i+cur_segsize*3<0x14b0){
				//printf("%x: %u %u %x\n", i+cur_segsize*3, vector_idx(left_cbytes,3), vector_idx(cbytes, 3), vector_idx(hash, 3));
			//}

			for (int j=0; j<sizeof(int); j++) {
					__m512i uentry = _mm512_i32gather_epi32(idx2, crcu, 4);
					hash = _mm512_xor_epi32(hash, uentry);
					doCrc(hash, cbytes);

					__m512i ret = _mm512_and_epi32(hash, mm_break_mark);

					__mmask16 bits = _mm512_cmpeq_epi32_mask(ret,_mm512_set1_epi32(magic_number));
					if(bits > 0) {
						//ret = _mm512_maskz_abs_epi32(bits,_mm512_set1_epi32(1));
						ret = _mm512_maskz_set1_epi32(bits,1);
						ret = _mm512_slli_epi32(ret, (i&31)+j);
						mm_bm = _mm512_or_epi32(mm_bm, ret);
						//for(int k=0; k<16; k++){
							//if((bits>>k) & 0x1)
								//printf("break at %d i %d %d\n", k*cur_segsize+i+j, i, i%32);
						//}
					}

					left_cbytes = _mm512_srli_epi32(left_cbytes, 8);
					idx2 = _mm512_and_epi32(left_cbytes, cmask);
			}

			if ((i&31)== 28 && _mm512_cmpneq_epi32_mask(mm_bm,_mm512_set1_epi32(0)) > 0){
				bm = _mm512_i32gather_epi32(vindex*bytes_per_thread>>3, (void*)(fs->breakpoint_bm+(offset>>3)+((i>>5)<<2)), 1);
				bm = _mm512_or_epi32(mm_bm, bm);
				_mm512_i32scatter_epi32((void*)(fs->breakpoint_bm+(offset>>3)+((i>>5)<<2)), vindex*bytes_per_thread>>3, bm, 1);
			}
		}


		if(cur_segsize < last_segsize){
			uint8_t *str = (uint8_t*)fs->map+bytes_per_thread*15;
			uint32_t hash2 = vector_idx(hash, 15);
			//printf("Processing data stream at [0x%x-0x%lx]: sequential\n", offset+cur_segsize*n_threads, fs->test_length-1);
			//sequential process of the remaining bytes
			while(i < last_segsize){
				hash2^=crcu[str[i-HASHLEN]];
				doCrc_serial_crc(str[i], &hash2);
				if((hash2 & break_mask) == magic_number ){
					uint8_t b = fs->breakpoint_bm[(i+bytes_per_thread*15)/8];
					b |= 1<<(i+bytes_per_thread*15)%8;
					fs->breakpoint_bm[(i+bytes_per_thread*15)/8] = b;
					//printf("Seq: i %d\n", i);
				}
				i++;
			}
			n_bytes_left = 0;
		}
		
		//offset += cur_segsize*n_threads;
		offset += cur_segsize;
	}

#if 0
	for (int k=0; k< fs->length; k+=8){
		uint8_t b = fs->breakpoint_bm[k/8];
		if ( b> 0){
			int j=0; 
			while(b > 0){
				if(b&0x1)
					printf("offset %d\n", k+j);
				b = b >> 1;
				j++;
			}
		}
	}
#endif

	return 0;
}

int chunking_phase_one_parallel_crcv0(struct file_struct *fs){
	return 0;
}
#endif
