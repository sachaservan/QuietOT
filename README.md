# QuietOT Implementation

A prototype implementation of the [QuietOT](https://eprint.iacr.org/2024/1079.pdf) OT extension protocol in C. 

QuietOT is a lightweight oblivious transfer protocol with a public-key setup. 

## Organization


| **Directory**                    |                                                                |
| :------------------------------- | :------------------------------------------------------------- |
| [quiet-bipsw/](quiet-bipsw/)     | Implementation of QuietOT with the BIPSW wPRF.                 |
| [quiet-gar/](quiet-gar/)         | Implementation of QuietOT using the GAR wPRF.                  |
| [bcmpr-bipsw/](bcmpr-bipsw/)     | Implementation of the BCMPR PCF using the BIPSW wPRF           |
| [other/](other/)                 | Partial implementations of the BCMPR and OSY pseudorandom correlation functions for benchmarking purposes. |


## Dependencies

- OpenSSL
- GNU Make
- Cmake
- Clang

## Getting everything to run (tested on Ubuntu, CentOS, and MacOS)

| Install dependencies (Ubuntu):         | Install dependencies (CentOS):              |
| -------------------------------------- | ------------------------------------------- |
| `sudo apt-get install build-essential` | `sudo yum groupinstall 'Development Tools'` |
| `sudo apt-get install cmake`           | `sudo yum install cmake`                    |
| `sudo apt install libssl-dev`          | `sudo yum install openssl-devel`            |
| `sudo apt install clang`               | `sudo yum install clang`                    |

On MacOS, use [homebrew](https://brew.sh/) to install dependencies.
`cmake` and `clang` can be installed via `xcode-select --install`.
OpenSSL can be installed via `brew install openssl` or manually.



## Installation

Ubuntu: 
```
sudo apt-get update
sudo apt-get install build-essential cmake libssl-dev clang
```

CentOS
```
sudo yum groupinstall 'Development Tools'
sudo yum install cmake openssl-devel clang
```

MacOS
```
brew install openssl
xcode-select --install  # Installs cmake and clang
```

## Quick Start

```bash
git clone https://github.com/yourusername/QuietOT.git
cd QuietOT
cd quiet-bipsw
make && ./bin/test
```

## Running tests and benchmarks

Test and benchmark for QuietOT:

```
cd [quiet-bipsw | quiet-gar]
make && ./bin/test 
```
Running BIPSW with AVX512
```
make -AVX=1 
make && ./bin/test 
```

Benchmarking BCMPR (with BIPSW wPRF):

```
cd bcmpr-bipsw
make && ./bin/test
```

Benchmarking BCMPR (with GAR wPRF) and OSY:

```
cd other
make && ./bin/bench
```

## Citation
```
@misc{QuietOT,
      author = {Geoffroy Couteau and Lalita Devadas and Srinivas Devadas and Alexander Koch and Sacha Servan-Schreiber},
      title = {{QuietOT}: Lightweight Oblivious Transfer with a Public-Key Setup},
      howpublished = {Cryptology ePrint Archive, Paper 2024/1079},
      year = {2024},
      note = {\url{https://eprint.iacr.org/2024/1079}},
      url = {https://eprint.iacr.org/2024/1079}
}
```

## Acknowledgements
We use the super fast [Polymur](https://github.com/orlp/polymur-hash) hash for universal hashing. 

## ⚠️ Important Warning

<b>This implementation is intended for _research purposes only_. The code has NOT been vetted by security experts.
As such, no portion of the code should be used in any real-world or production setting!</b>
