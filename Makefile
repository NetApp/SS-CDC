SRC=test-main.cpp
BIN=ss-cdc
Debug_Bin=ss-cdc.debug
all:
	gcc -march=skylake-avx512 -O3 -o $(BIN) $(SRC) -lssl -lcrypto
	gcc -march=skylake-avx512 -g -o $(Debug_Bin) $(SRC) -lssl -lcrypto
clean:
	rm -f $(BIN) $(Debug_Bin)
