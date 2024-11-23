# QuietOT Implementation 🤫

[QuietOT](https://eprint.iacr.org/2024/1079.pdf) (to appear at AsiaCrypt 2024) is a lightweight oblivious transfer extension protocol with a non-interactive public-key setup.
This implementation is intended to benchmark the performance of QuietOT, and can be used to reproduce the results reported in Table 2 of the evaluation section. 


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

<br><br>

## Getting everything to run (tested on Ubuntu, CentOS, and MacOS)

## Quick Start

To get QuietOT up and running quickly:

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
cd quiet-bipsw
make AVX=1 
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
We thank [Maxime Bombar](https://github.com/mbombar) for reviewing and providing feedback on the code. 

## ⚠️ Important Warning

**This implementation is intended for _research purposes only_. The code has NOT been vetted by security experts.
As such, no portion of the code should be used in any real-world or production setting!**
