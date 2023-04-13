TARGETS: SPPoA.exe  

SHELL := /bin/bash

SPPoA.exe: SPPoA.c SPPoA.h sha256.c sha256.h ripemd160.c
	gcc -g -Warray-bounds sha256.c ripemd160.c SPPoA.c -o SPPoA.exe 

SPPoA.js: SPPoA.c SPPoA.h sha256.c sha256.h ripemd160.c
	source ~/dev/emsdk/emsdk_env.sh && emcc -s ALLOW_MEMORY_GROWTH -s MAXIMUM_MEMORY=4GB -DWASM sha256.c ripemd160.c SPPoA.c -o SPPoA.js -sEXPORTED_RUNTIME_METHODS=ccall -s FORCE_FILESYSTEM=1 

clean:
	rm SPPoA.exe SPPoA.js
