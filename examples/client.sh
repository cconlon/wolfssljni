#!/bin/bash

# Example usage:
#   ./examples/client.sh -h 127.0.0.1 -p 11111 -v 4
#   ./examples/client.sh -v 4 -pqc X25519MLKEM768  (PQC hybrid TLS 1.3)
#   ./examples/client.sh -v 4 -pqc ML-KEM-768      (PQC standalone)
# Run ./examples/client.sh -? for the full option list.

cd ./examples/build
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:../../lib/:/usr/local/lib
java -classpath ../../lib/wolfssl.jar:./ -Dsun.boot.library.path=../../lib/ -Xcheck:jni Client $@

