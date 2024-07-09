# BCMPR and OSY Benchmark implementations

This folder contains:

- Benchmark code for estimating the performance of the [BCMPR](https://eprint.iacr.org/2024/178.pdf) PCF using the GAR wPRF.
- Benchmark code for estimating the performance of the [OSY](https://eprint.iacr.org/2021/262.pdf) PCF from DCR. 

The current implementation uses the OpenSSL BIGNUM and Elliptic Curve implementations.
Both implementations are for benchmarking purposes and do not fully implement the PCF functionality.
In particular, they simply estimate the computation time required of exponentiation in the respective groups and some mininal AES-based hashing. 
However, these implementations can be used as a basis to fully implement both constructions. 
