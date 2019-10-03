# In-tree fuzzing

The existing curl fuzzers are great! They
are however built of tree, meaning they can only
access curl as any libcurl user does.

By adding this directory from the curl repo, it is possible to get some benefits:

 - access to internal functions
 - faster test/debug cycle as the same source is
   used for both fuzzing and normal development
   build
 - cmake support, enabling common IDEs with code
   navigation and refactoring possible. QtCreator was used during
   development of the fuzzers.

## How it works
The curl cmake config optionally includes this
directory. Fuzzing specific source files are
in this directory, not in curl.

## Building
Check out curl and curl-fuzzers parallell (or provide a symlink)

```sh
mkdir ~/code/
cd ~/code/
git clone https://github.com/pauldreik/curl-fuzzer.git
cd curl-fuzzer
git checkout paul/localfuzz_public0
cd  ~/code/
git clone https://github.com/pauldreik/curl.git
cd curl
git checkout paul/localfuzz_public0
```

Install build dependencies. This shows how to do it on Debian/Ubuntu, which conveniently can download build dependencies. One can probably get by by installing a lot fewer things, skip this step if you like and see if the build passes anyway.
```
apt build-dep nghttp2-client
apt build-dep openssl
apt build-dep zlib
apt build-dep curl
apt install libboost-dev cmake clang-7
```

Then from inside the curl-fuzzer repo (Takes approximately five minutes to build on my machine):
```
cd ~/code/curl-fuzzer/
intree_fuzzer/scripts/build.sh
```
The build script can build variants of the fuzzer, with/without sanitizers etc.

## Running the existing network fuzzers
The existing fuzzers in the root dir of curl-fuzzer, written in 2017, are symlinked and compiled. They are also compiled in a version with a custom mutator, suffixed with _wcm, see the next section.

```
cd ~/code/curl/build-fuzz-clang7-asan-ubsan
mkdir -p out/http
tests/curl_fuzzer_http out/http/ ../../curl-fuzzer/corpora/curl_fuzzer_http
```
## Using the custom mutator
You can run the existing network fuzzers with the custom mutator. They use the same fuzz data format, so they can work independently of or in collaboration with the default mutator variant shown above.
```
cd ~/code/curl/build-fuzz-clang7-asan-ubsan
mkdir -p out/http
tests/curl_fuzzer_http_wcm out/http/ ../../curl-fuzzer/corpora/curl_fuzzer_http
```
## Running the internal fuzzers
```
cd ~/code/curl/build-fuzz-clang7-asan-ubsan
mkdir -p out/cookies
internalfuzzer_fuzz_cookies out/cookies/
```
## Measuring coverage
Build with coverage support
```
cd ~/code/curl-fuzzer/
intree_fuzzer/scripts/build.sh -t coverage
```

For now, the script for executing the coverage measurement uses path to
directories which were removed from git to avoid polluting the code
with lots of tiny files. So you will have to populate with input files as per the example below.
```
(somehow populate ~code/curl-fuzzer/intree_fuzzer/corpus/$FUZZER with data)
cd ~/code/curl/build-coverage-clang7-asan-ubsan
../../curl-fuzzer/intree_fuzzer/scripts/replay_corpus.sh
```
and then view the result with a browser (the script prints the path at the end)
