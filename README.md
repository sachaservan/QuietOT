# QuietOT Implementation

A prototype implementation of the [QuietOT](https://eprint.iacr.org/2024/1079.pdf) OT extension protocol in C.

## Organization


| **Directory**                    |                                                                |
| :------------------------------- | :------------------------------------------------------------- |
| [quiet-bipsw/](quiet-bipsw/)     | Implementation of QuietOT with the BIPSW wPRF.                 |
| [quiet-gar/](quiet-gar/)         | Implementation of QuietOT using the GAR wPRF.                  |
| [bcmpr-bipsw/](bcmpr-bipsw/)     | Implementation of the BCMPR PCF using the BIPSW wPRF           |
| [other/](other/)                 | Partial benchmark implementations of the BCMPR and OSY pseudorandom correlation functions. |


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

## Running tests and benchmarks

Test and benchmark for QuietOT:

```
cd [bipsw | gar]
make && ./test 
```
Running BIPSW with AVX512
```
make -AVX=1 
make && ./test 
```

Benchmarking BCMPR and OSY:

```
cd other
make && ./bench
```

## Future development

## Citation
```
@misc{cryptoeprint:2024/1079,
      author = {Geoffroy Couteau and Lalita Devadas and Srinivas Devadas and Alexander Koch and Sacha Servan-Schreiber},
      title = {{QuietOT}: Lightweight Oblivious Transfer with a Public-Key Setup},
      howpublished = {Cryptology ePrint Archive, Paper 2024/1079},
      year = {2024},
      note = {\url{https://eprint.iacr.org/2024/1079}},
      url = {https://eprint.iacr.org/2024/1079}
}
```

## ⚠️ Important Warning

<b>This implementation is intended for _research purposes only_. The code has NOT been vetted by security experts.
As such, no portion of the code should be used in any real-world or production setting!</b>
