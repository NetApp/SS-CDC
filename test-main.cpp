#include "common.h"

int main(int argc, char *argv[]){
	uint64_t start, end, ptime = 0;
	uint64_t start_s, end_s, stime = 0;
	char fname_ab[256];
	char hname[64];
	char *fname;
	int n = 0;
	
	if ( parse_args(argc, argv) != 0)
		return 0;

	init_fp_pool(1*1024*1024, SHA_DIGEST_LENGTH);
	if (dir){
		collect_files(dir);
		strcpy(fname_ab, dir);
		fname = fname_ab+strlen(dir);
		while(next_file(fname) && n < num_files_test){
			fs.fname = fname_ab;
			if (init_fs(&fs))
				continue;

			run_chunking_with_timer();
			finialize_fs(&fs);
			n++;
		}
		clear_files();
	}else {
			if(init_fs(&fs) == 0){
				run_chunking_with_timer();
				finialize_fs(&fs);
			}
	}

	deinit_fp_pool();
	sprintf(hname, "hash %s", hash_name);
	print_stats(hname);
	return 0;
}
