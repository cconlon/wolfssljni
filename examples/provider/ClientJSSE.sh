#!/bin/bash

# Example usage:
#   ./examples/provider/ClientJSSE.sh -h 127.0.0.1 -p 11111 -v 4
#   ./examples/provider/ClientJSSE.sh -v 4 -pqc X25519MLKEM768
#   ./examples/provider/ClientJSSE.sh -v 4 -pqc ML-KEM-768
# Run ./examples/provider/ClientJSSE.sh -? for the full option list.

cd ./examples/build
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:../../lib/:/usr/local/lib
java -classpath ../../lib/wolfssl.jar:../../lib/wolfssl-jsse.jar:./ -Dsun.boot.library.path=../../lib/ -Dwolfjsse.debug=true ClientJSSE "$@"

