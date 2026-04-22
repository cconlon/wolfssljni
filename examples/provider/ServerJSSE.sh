#!/bin/bash

# Example usage:
#   ./examples/provider/ServerJSSE.sh -p 11111 -v 4
#   ./examples/provider/ServerJSSE.sh -v 4 -pqc X25519MLKEM768
# Run ./examples/provider/ServerJSSE.sh -? for the full option list.

cd ./examples/build
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:../../lib/:/usr/local/lib
java -classpath ../../lib/wolfssl-jsse.jar:./ -Dsun.boot.library.path=../../lib/ -Dwolfjsse.debug=true ServerJSSE "$@"

