# QuietOT Implementation 🤫

[QuietOT](https://eprint.iacr.org/2024/1079.pdf) (to appear at AsiaCrypt 2024) is a lightweight oblivious transfer extension protocol with a non-interactive public-key setup.
This implementation is intended to benchmark the performance of QuietOT, and can be used to reproduce a subset of the results reported in Table 2 of the evaluation section. 


## Organization

| **Directory**                    |                                                                |
| :------------------------------- | :------------------------------------------------------------- |
| [quiet-bipsw/](quiet-bipsw/)     | Implementation of QuietOT with the BIPSW wPRF.                 |
| [quiet-gar/](quiet-gar/)         | Implementation of QuietOT using the GAR wPRF.                  |
| [bcmpr-bipsw/](bcmpr-bipsw/)     | Implementation of the BCMPR PCF using the BIPSW wPRF.           |
| [other/](other/)                 | Partial implementations of the BCMPR and OSY pseudorandom correlation functions for benchmarking purposes. |

## Dependencies

- OpenSSL
- GNU Make
- Cmake
- Clang

### Installing dependecies on Ubuntu and CentOS
| Install dependencies (Ubuntu):         | Install dependencies (CentOS):              |
| -------------------------------------- | ------------------------------------------- |
| `sudo apt-get install build-essential` | `sudo yum groupinstall 'Development Tools'` |
| `sudo apt-get install cmake`           | `sudo yum install cmake`                    |
| `sudo apt install libssl-dev`          | `sudo yum install openssl-devel`            |
| `sudo apt install clang`               | `sudo yum install clang`                    |

### Installing dependencies on MacOS
On MacOS, use [homebrew](https://brew.sh/) to install dependencies.
`cmake` and `clang` can be installed via `xcode-select --install`.
OpenSSL can be installed via `brew install openssl` or manually.
```
brew install openssl
xcode-select --install  # Installs cmake and clang
```
<b>Note:</b> If installing OpenSSL manually on Mac, then you will need to update the library path in the Makefiles to point to the correct directory. 
Change this `-I/opt/homebrew/opt/openssl/include` to `-I[PATH]/openssl/include`

#### Troubleshooting (MacOS)
If you see "library 'crypto' not found", try:
1. Check if OpenSSL is properly installed: `brew list openssl`
2. Verify the OpenSSL path: `brew --prefix openssl`

## Hardware Requirements
Memory: At least 4GB RAM recommended.

Processor: 
  - Basic version works on any x86_64 processor.
  - AVX512 acceleration requires Intel processor with AVX512 support.

Expected performance:
- With AVX512: ~1,200,000 OT/s.
- Without AVX512: ~500,000 OT/s on Linux.
- Without AVX512: ~1,200,000 OT/s on M1 Mac.
      
<br><br>

## Quick Start

To get QuietOT up and running quickly:

```bash
git clone https://github.com/sachaservan/QuietOT.git
cd QuietOT
cd quiet-bipsw
make && ./bin/test
```

## Running tests and benchmarks

### Test and benchmark for QuietOT:

```bash
cd [quiet-bipsw | quiet-gar]
make && ./bin/test 
```

By default, the benchmarks are compiled to generate $2^{20}$ OTs.
You can change the number of OTs generated (for QuietOT benchmarks only; not implemented for the BCMPR benchmarks) by running
```bash
make NUM_OTS=[log2 number of OTs]
```
For example, `make NUM_OTS=18` will generate $2^{18}$ OTs. 
Make sure to run `make clean` before recompiling. 
<br><br>
<b>Note:</b> trying to generate too many OTs (e.g., setting `NUM_OTS=25` will cause performance issues and may cause the benchmarks to stall or crash depending on how much memory you have on your hardware). 

### Running BIPSW with AVX512 

<b>Note:</b> requires AVX512 hardware support! (e.g., does not work on M1 Mac)
```bash
cd quiet-bipsw
make AVX=1 
make && ./bin/test 
```

### Benchmarking BCMPR (with BIPSW wPRF):

```bash
cd bcmpr-bipsw
make && ./bin/test
```

### Benchmarking BCMPR (with GAR wPRF) and OSY:

```bash
cd other
make && ./bin/bench
```

## Reproducing Table 2 of the paper
Simply run the benchmarks as described above on the respective hardware.
The output of each benchmark will look something like this: 
```
Took 871.88 ms to generate 1048576 OTs
PASS
...
Took 931.52 ms to generate 1048576 OTs
PASS

******************************************
SUMMARY
Avg. time: 8892.60 ms to generate 1048576 OTs
Performance: 117915.54 OTs/sec
Number of trials: 10
******************************************
```

<b>Notes:</b> 
- Default `NUM_OTS=20` produces the OTs/sec values in the table on the respective hardware. 
- Public key sizes in the table are derived in the [full version of the paper](https://eprint.iacr.org/2024/1079.pdf).
- Bits/OT are derived analytically in the paper by analizing the ring size.
  
## Future Improvements

- [ ] Implement the public-key setup for QuietOT 
- [ ] Find a way to use SIMD instructions for the GAR variant
- [ ] Implement [SIMD for ARM architectures](https://developer.arm.com/Architectures/Neon)
      

## Citation
```
@inproceedings{QuietOT,
  author       = {Geoffroy Couteau and
                  Lalita Devadas and
                  Srinivas Devadas and
                  Alexander Koch and
                  Sacha Servan-Schreiber},
  title        = {{QuietOT}: Lightweight ObliviousTransfer with a Public-Key Setup},
  note         = {\url{https://eprint.iacr.org/2024/1079}},
  url          = {https://eprint.iacr.org/2024/1079}
  editor       = {Kai-Min Chung and
                  Yu Sasaki},
  booktitle    = {Advances in Cryptology - {ASIACRYPT} 2024 - 30th
                  International Conference on the Theory and
                  Application of Cryptology and Information Security,
                  Kolkata, India, December 9-13, 2024
                  },
  publisher    = {Springer},
  year         = {2024},
}
```


## Acknowledgements
We use the super fast [Polymur](https://github.com/orlp/polymur-hash) hash for universal hashing. 
We thank [Maxime Bombar](https://github.com/mbombar) for reviewing and providing feedback on the code. 

## ⚠️ Important Warning

**This implementation is intended for _research purposes only_. The code has NOT been vetted by security experts.
As such, no portion of the code should be used in any real-world or production setting!**
