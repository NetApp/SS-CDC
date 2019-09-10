This repository’s contents is being provided by NetApp, Inc. for non-commercial research purposes only. Review the LICENSE for more details.

**DESCRIPTION:**  
The code provides an example C language based implementation of the idea proposed in the paper "SS-CDC: a two-stage parallel content-defined chunking for deduplicating backup storage". It provides an efficient parallel content-defined chunking (CDC) implementation for deduplication systems with Intel AVX-512 instructions, which can achieve high chunking speed as well as zero deduplication ratio reduction compared to sequential CDC methods.  

The code was tested with Linux OS (Ubuntu, and should also work on other Linux releases) and hardware platform where the processor supports Intel AVX-512 instructions.

 
**DEPENDENCIES:**   
The system CPU must support the Intel AVX-512 instruction set (typically 2016 Skylake or later Intel processors).  
 
The following library and header file need to present on the system for compilation:   
libopenssl  (for SHA-1)   
              immintrin.h (for Intel AVX-512 instruction related function call)  
 
For the compilation,  the option "-march=skylake-avx512" is needed. Please refer to the Makefile for additional compile options.  
 
**ATTRIBUTION INFORMATION:**  
Please use one of the following formats for referencing this work in any published papers, websites, etc.: 
* plain format for non-Latex use:   
Fan Ni, Xing Lin, and Song Jiang. 2019. SS-CDC: a two-stage parallel content-defined chunking for deduplicating backup storage. In Proceedings of the 12th ACM International Conference on Systems and Storage (SYSTOR '19). ACM, New York, NY, USA, 86-96. DOI: https://doi.org/10.1145/3319647.3325834  
 
* bibtex format for latex use:   
@inproceedings{NLJ19,   
author = {Ni, Fan and Lin, Xing and Jiang, Song},   
title = {SS-CDC: A Two-stage Parallel Content-defined Chunking for Deduplicating Backup Storage},   
booktitle = {Proceedings of the 12th ACM International Conference on Systems and Storage},  
series = {SYSTOR '19},  
year = {2019},   
isbn = {978-1-4503-6749-3},   
location = {Haifa, Israel},  
pages = {86--96},   
numpages = {11},   
url = {http://doi.acm.org/10.1145/3319647.3325834},   
doi = {10.1145/3319647.3325834},   
acmid = {3325834},   
publisher = {ACM},   
address = {New York, NY, USA},   
keywords = {content-defined-chunking (CDC), deduplication, storage},   
}   
 
**SUPPORT:**   
NetApp does not provide support or troubleshooting for the users of this repository’s contents, and the contents are provided without warranty. Review the LICENSE for more details.  

**MAINTENANCE AND CONTRIBUTIONS:**   
NetApp does not provide maintenance for this repository, and contributions to the repository’s contents are not being accepted.  
