#!/bin/sh
#
# For building the intree fuzzers.
# Execute standing in the curl-fuzzer repo
#
# By Paul Dreik 2019

set -eu
me=$(basename $0)

CURLFUZZROOT=$(git -C $(dirname "$0") rev-parse --show-toplevel )
CURLROOT=$(readlink -f $CURLFUZZROOT/../curl)

echo $me: CURLROOT=$CURLROOT
echo $me: CURLFUZZROOT=$CURLFUZZROOT


#do not inherit anything from outside
unset CC CXX  LDFLAGS
export CFLAGS= CXXFLAGS=

#stuff left to do - enable ipv6 --with-random=/dev/null

commoncmakeflags="-GNinja -DCMAKE_BUILD_TYPE=Debug -DENABLE_CURLDEBUG=Off -DENABLE_DEBUG=On -DBUILD_SHARED_LIBS=Off -DCURL_HIDDEN_SYMBOLS=Off -USE_NGHTTP2=On -DENABLE_FUZZING=On -DBUILD_CURL_EXE=Off -DENABLE_MANUAL=Off -DENABLE_THREADED_RESOLVER=On -DFUZZING_SHORTCUT_NAME_RESOLUTION=On -DRANDOM_FILE=/dev/null"

#main task: fuzz, coverage or reproduce
task=fuzz
#task=coverage

#tool chain name
tcname=gcc5-plain
tcname=default
tcname=clang6-asan-ubsan
tcname=clang7-asan-ubsan
#tcname=clang6-plain
#tcname=clang7-plain

while getopts t:c: f
do
   case $f in
      c)  tcname=$OPTARG;;
      t)  task=$OPTARG;;
      \?|h) echo "usage: $me -t TASK -c toolchain" ;exit 1;;
   esac
done




echo "$me: toolchain=$tcname  task=$task"
case $tcname in
   gcc5-plain)
      # plain replay with gcc
      export CC=gcc-5 CXX=g++-5 CFLAGS="-std=c11"
      ;;
   gcc8-plain)
      export CC=gcc-8 CXX=g++-8 CFLAGS="-std=c11"
      ;;
   clang6-plain)
      export CC=clang-6.0 CXX=clang++-6.0
      ;;
   clang7-plain)
      export CC=clang-7 CXX=clang++-7
      ;;
   clang8-plain)
      export CC=clang-8 CXX=clang++-8
      ;;
   clang7-plain-O3)
      export CC=clang-7 CXX=clang++-7 CFLAGS="-O3" CXXFLAGS="-O3"
      ;;
   clang8-plain-O3)
      export CC=clang-8 CXX=clang++-8 CFLAGS="-O3" CXXFLAGS="-O3"
      ;;
   clang6-asan-ubsan)
      export CC=clang-6.0 CXX=clang++-6.0 CFLAGS="-fsanitize=address,undefined" CXXFLAGS="-fsanitize=address,undefined"
      ;;
   clang7-asan-ubsan)
      export CC=clang-7 CXX=clang++-7 CFLAGS="-fsanitize=address,undefined" CXXFLAGS="-fsanitize=address,undefined"
      ;;
   clang8-asan-ubsan)
      export CC=clang-8 CXX=clang++-8 CFLAGS="-fsanitize=address,undefined" CXXFLAGS="-fsanitize=address,undefined"
      ;;
   clang7-asan-ubsan-O3)
      export CC=clang-7 CXX=clang++-7 CFLAGS="-fsanitize=address,undefined -O3" CXXFLAGS="-fsanitize=address,undefined -O3"
      ;;
   clang8-asan-ubsan-O3)
      export CC=clang-8 CXX=clang++-8 CFLAGS="-fsanitize=address,undefined -O3" CXXFLAGS="-fsanitize=address,undefined -O3"
      ;;
   *)
      echo "$me: unkown tool chain $tcname"
      exit 1
esac

# always set the cpp version and debugging information
cppversion=-std=c++1z
CXXFLAGS="$CXXFLAGS $cppversion -g"
CFLAGS="$CFLAGS -g"

case $task in
   fuzz)
      CFLAGS="$CFLAGS -fsanitize=fuzzer-no-link"
      #CXXFLAGS="$CXXFLAGS -fsanitize=fuzzer-no-link"
      cmakeflags="$commoncmakeflags -DENABLE_COVERAGE=Off -DFUZZING_LINK_MAINRUNNER=Off"
      ;;
   coverage)
      cmakeflags="$commoncmakeflags  -DENABLE_COVERAGE=On -DFUZZING_LINK_MAINRUNNER=On"
      ;;
   reproduce)
      cmakeflags="$commoncmakeflags -DFUZZING_LINK_MAINRUNNER=On -DENABLE_COVERAGE=Off"
      ;;
   *)
      echo $me: unknown task $task
esac

buildroot=$CURLROOT/build-$task-$tcname
mkdir -p $buildroot

###############################################################################
# build nghttp2
nghttp2root=$buildroot/thirdparty/nghttp2
nghttp2src=$nghttp2root/source-$task-$tcname
nghttp2install=$nghttp2root/install-$task-$tcname
if [ ! -e "$nghttp2install/lib/libnghttp2.a" ]; then
   mkdir -p $nghttp2root $nghttp2src $nghttp2install
   if [ ! -e $nghttp2src/README.rst ] ; then
      git clone --branch v1.33.0 --depth 1 https://github.com/nghttp2/nghttp2 $nghttp2src
   fi
   cd $nghttp2src
   echo $me: running autoreconf
   autoreconf -i
   echo $me: running configure
   ./configure --prefix=$nghttp2install \
               --disable-shared --enable-static --disable-threads --disable-python-bindings
   make -j4
   make install
fi
cmakeflags="$cmakeflags -DNGHTTP2_LIBRARY=$nghttp2install/lib/libnghttp2.a"
cmakeflags="$cmakeflags -DNGHTTP2_INCLUDE_DIR=$nghttp2install/include"
cmakeflags="$cmakeflags -DUSE_NGHTTP2=On"
###############################################################################
# build zlib
zlibroot=$buildroot/thirdparty/zlib
zlibsrc=$zlibroot/source-$task-$tcname
zlibinstall=$zlibroot/install-$task-$tcname
if [ ! -e "$zlibinstall/lib/libz.a" ]; then
   mkdir -p $zlibroot $zlibinstall
   if [ ! -d $zlibsrc ] ; then
      downloaddir=$(mktemp -d)
      zlibversion=1.2.11
      wget https://www.zlib.net/zlib-$zlibversion.tar.gz -O $downloaddir/zlib-$zlibversion.tar.gz
      echo "c3e5e9fdd5004dcb542feda5ee4f0ff0744628baf8ed2dd5d66f8ca1197cb1a1  $downloaddir/zlib-$zlibversion.tar.gz" >SHA256SUM
      sha256sum -c SHA256SUM
      mkdir -p $downloaddir/tmp
      tar -xf $downloaddir/zlib-$zlibversion.tar.gz --directory $downloaddir/tmp
      echo $me: mv -v $downloaddir/tmp/zlib-$zlibversion $zlibsrc in $(pwd)
      mv $downloaddir/tmp/zlib-$zlibversion $zlibsrc
      rm -rf $downloaddir
   fi
   cd $zlibsrc
   echo $me: running configure
   ./configure --prefix=$zlibinstall \
               --static
   make -j4
   make install
fi
cmakeflags="$cmakeflags -DZLIB_LIBRARY=$zlibinstall/lib/libz.a"
cmakeflags="$cmakeflags -DZLIB_INCLUDE_DIR=$zlibinstall/include"
cmakeflags="$cmakeflags -DCURL_ZLIB=On"
###############################################################################
# build openssl
opensslroot=$buildroot/thirdparty/openssl
opensslsrc=$opensslroot/source-$task-$tcname
opensslinstall=$opensslroot/install-$task-$tcname
if [ ! -e "$opensslinstall/lib/libssl.a" ]; then
   mkdir -p $opensslroot $opensslsrc $opensslinstall
   if [ ! -e $opensslsrc/README ] ; then
      git clone --branch OpenSSL_1_0_2m --depth 1 https://github.com/openssl/openssl $opensslsrc
   fi
   cd $opensslsrc
   echo $me: running config in $(pwd)
   # For i386, set a specific crosscompile mode
   ARCHITECTURE=amd64
   SANITIZER=
   if [[ ${ARCHITECTURE} == "i386" ]]
   then
      ARCH_PROG="setarch i386"
      EC_FLAG=""
   else
      ARCH_PROG=""
      EC_FLAG="enable-ec_nistp_64_gcc_128"
   fi
   # For memory sanitizer, disable ASM.
   if [[ ${SANITIZER} == "memory" ]]
   then
      ASM_FLAG="no-asm"
   else
      ASM_FLAG=""
   fi
   OPENSSLFLAGS="-fno-sanitize=alignment"
   ${ARCH_PROG} ./config --prefix=$opensslinstall \
                --debug \
                enable-fuzz-libfuzzer \
                -DPEDANTIC \
                -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION \
                no-shared \
                ${ASM_FLAG} \
                enable-tls1_3 \
                enable-rc5 \
                enable-md2 \
                enable-ssl3 \
                ${EC_FLAG} \
                enable-ssl3-method \
                enable-nextprotoneg \
                enable-weak-ssl-ciphers \
                $CFLAGS \
                ${OPENSSLFLAGS}
   make -j4
   make install_sw # dont install man pages
fi
cmakeflags="$cmakeflags -DCMAKE_USE_OPENSSL=On"
cmakeflags="$cmakeflags -DOPENSSL_ROOT_DIR=$opensslinstall"
cmakeflags="$cmakeflags -DOPENSSL_LIBRARIES=$opensslinstall/lib/"
###############################################################################
cd $buildroot
cmake .. $cmakeflags \
      -DCMAKE_C_COMPILER="$CC" \
      -DCMAKE_CXX_COMPILER="$CXX" \
      -DCMAKE_C_FLAGS="$CFLAGS" \
      -DCMAKE_CXX_FLAGS="$CXXFLAGS"
ninja


# when running on ubuntu, set ASAN_SYMBOLIZER_PATH=/usr/lib/llvm-7/bin/llvm-symbolizer
# to get symbols working

