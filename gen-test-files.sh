#!/bin/bash

mkdir test test/a test/b
echo "aaaaaaaaaaaaaaaa" > test/a/test.txt
echo "bbbbbbbbbbbbbbbb" > test/b/test.txt

dd if=/dev/urandom of=sample.txt bs=1G count=1 iflag=fullblock
sha256sum sample.txt > sample.txt.sum