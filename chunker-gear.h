#ifndef CHUNKER_GEAR_H_H
#define CHUNKER_GEAR_H_H

#define doGear(hash, cbytes) {\
					hash = _mm512_slli_epi32(hash, 1);\
					__m512i idx = _mm512_and_epi32(cbytes, cmask);\
					cbytes = _mm512_srli_epi32(cbytes, 8);\
					__m512i tentry = _mm512_i32gather_epi32(idx, crct, 4);\
					hash = _mm512_add_epi32(hash,tentry);\
					hash = _mm512_and_epi32(hash,mm_break_mark);}





static inline uint32_t GEAR_HASHLEN() { return break_mask_bit;}

static inline void doGear_serial(uint32_t c, uint32_t* x)
{
	//*x = (*x >> 8) ^ ((*x ^ c) & 0xff);
	*x = ((*x<<1) + crct[c&0xff])&break_mask;
}

int chunking_phase_one_serial_gear(struct file_struct *fs){
	uint32_t n_bytes_left;
	uint32_t offset = 0;
	int cur_segsize, last_segsize;

	n_bytes_left = fs->test_length;
	if(fs->length <= GEAR_HASHLEN() || n_bytes_left <= min_chunksize) {
				printf("Serial: For file with %lu bytes, no chunking\n", fs->length);
				// set remaining bitmap to 0000...1
				return 0;
	}

	uint32_t hash = 0;
	uint8_t *str = (uint8_t *)fs->map;
	uint32_t local_offset = 0, last_offset = 0;
	

	if (skip_mini == 0){
		while( offset < fs->test_length ){
			doGear_serial(str[offset], &hash);
			if(offset < GEAR_HASHLEN()){
				offset ++;
				continue;
			}
			if(hash  == magic_number){
					uint8_t b = fs->breakpoint_bm_base[offset/8];
					b |= 1<<offset%8;
					fs->breakpoint_bm_base[offset/8] = b;
					//printf("Serial: offset %d hash %x\n", offset, hash);
			}
			offset++;
		}
	}else{
		while( offset < fs->test_length ){
			doGear_serial(str[offset], &hash);
			if(local_offset < GEAR_HASHLEN()){
				offset ++;
				local_offset ++;
				continue;
			}
			if(hash  == magic_number && offset - last_offset >= min_chunksize){
				uint8_t b = fs->breakpoint_bm_base[offset/8];
				b |= 1<<offset%8;
				fs->breakpoint_bm_base[offset/8] = b;
				last_offset = offset;
				offset -= GEAR_HASHLEN();
				local_offset = 0;
			}else
				offset++;
		}
	}
	return 0;
}


int chunking_phase_one_parallel_gear(struct file_struct *fs){
	__m512i vindex = _mm512_setr_epi32(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15);
	__m512i mm_break_mark = _mm512_set1_epi32(break_mask);
	__m512i cmask = _mm512_set1_epi32(0xff);
	uint32_t n_bytes_left;
	uint32_t offset = 0;
	int cur_segsize, last_segsize;

	//n_bytes_left = segment_size * 16;
	n_bytes_left = fs->test_length;
	uint32_t bytes_per_thread, bytes_last_thread;
	bytes_per_thread = (n_bytes_left/16)/32*32;
	bytes_last_thread = n_bytes_left - bytes_per_thread*15;
	//printf("Parallel: %u bytes %u bytes\n", bytes_per_thread, bytes_last_thread);

	int i=0;
	int j=0;
	__m512i hash = _mm512_set1_epi32(0);
	while (n_bytes_left > 0){
		if (n_bytes_left >= n_threads*segment_size){
			cur_segsize = last_segsize = segment_size;
			n_bytes_left -= n_threads*segment_size;
		}else{
			if (n_bytes_left <= n_threads * GEAR_HASHLEN() || n_bytes_left <= min_chunksize){
				printf("Parallel: For file with %u bytes, no chunking %u %u\n", n_bytes_left, n_threads*GEAR_HASHLEN(), min_chunksize);
				// set remaining bitmap to 0000...1
				return 0;
			}

			cur_segsize = n_bytes_left/n_threads/32*32;
			last_segsize = n_bytes_left-cur_segsize*(n_threads-1);
			n_bytes_left = 0;
		}

		//printf("Processing data stream at [0X%x-0X%x-1]: 0x%x bytes/thread parallel\n", offset, offset+cur_segsize*n_threads, cur_segsize);
		__m512i mm_bm = _mm512_set1_epi32(0);
		__m512i bm;

		//printf("LOOP: i %u j %u i32 %u\n", i,j, i%32);
		while(i<offset+cur_segsize+(GEAR_HASHLEN()+7)/8*8){
			__m512i cbytes = _mm512_i32gather_epi32(vindex*bytes_per_thread, (void*)(((uint8_t*)fs->map)+i), 1);

			for (j=0; j<sizeof(int); j++) {
				doGear(hash, cbytes);
				if (i+j < GEAR_HASHLEN())
					continue;

				//__m512i ret = _mm512_and_epi32(hash, mm_break_mark);
				__mmask16 bits = _mm512_cmpeq_epi32_mask(hash,_mm512_set1_epi32(magic_number));
				if(bits > 0) {
					__m512i ret = _mm512_maskz_set1_epi32(bits,1);
					ret = _mm512_slli_epi32(ret, (i&31)+j);
					mm_bm = _mm512_or_epi32(mm_bm, ret);

					//for (int k=0; k<16; k++)
						//if(vector_idx(hash, k) == magic_number)
							//printf("parallel: offset %u hash %x\n", offset+i+k*cur_segsize+j, vector_idx(hash, k));
				}
			}

			if (((i&31)== 28 || i+4 >= offset+cur_segsize+GEAR_HASHLEN()) && _mm512_cmpneq_epi32_mask(mm_bm,_mm512_set1_epi32(0)) > 0){
				bm = _mm512_i32gather_epi32(vindex*bytes_per_thread>>3, (void*)(fs->breakpoint_bm+((i>>5)<<2)), 1);
				bm = _mm512_or_epi32(mm_bm, bm);
				_mm512_i32scatter_epi32((void*)(fs->breakpoint_bm+((i>>5)<<2)), vindex*bytes_per_thread>>3, bm, 1);
				mm_bm = _mm512_set1_epi32(0);
			}
			i += 4;
		}


		if(cur_segsize < last_segsize){
			uint8_t *str = (uint8_t*)fs->map+bytes_per_thread*15;
			uint32_t hash2 = vector_idx(hash, 15);
			//printf("Processing data stream at [0x%x-0x%lx]: sequential\n", offset+cur_segsize*n_threads, fs->test_length-1);
			//sequential process of the remaining bytes
			while(i < last_segsize){
				doGear_serial(str[i], &hash2);
				if((hash2 & break_mask) == magic_number ){
					uint8_t b = fs->breakpoint_bm[(i+bytes_per_thread*15)/8];
					b |= 1<<(i+bytes_per_thread*15)%8;
					fs->breakpoint_bm[(i+15*bytes_per_thread)/8] = b;
					//printf("Seq: i %d\n", i);
				}
				i++;
			}
			n_bytes_left = 0;
		}
		
		offset += cur_segsize;
	}

#if 0
	for (int k=0; k< fs->length; k+=8){
		uint8_t b = fs->breakpoint_bm[k/8];
		if ( b> 0){
			int j=0; 
			while(b > 0){
				if(b&0x1)
					printf("parallel: offset %d\n", k+j);
				b = b >> 1;
				j++;
			}
		}
	}
#endif

	return 0;
}


#endif
