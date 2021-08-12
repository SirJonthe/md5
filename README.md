# md5

## Description

A C++ implementation of the MD5 message digest algorithm heavily inspired by the Wikipedia (as per y2019-m10-d01) implementation found at

https://en.wikipedia.org/wiki/MD5

This implementation does not allocate data on the heap while processing (but may allocate a some data on the stack if the input message is not 4-byte aligned).

## Note

I can not vouch for the correctness of the implementation of the algorithm.
