#!/bin/sh
#
# replays the corpus
#

set -e
me=$(basename $0)

CURLFUZZROOT=$(git -C $(dirname "$0") rev-parse --show-toplevel )
CURLROOT=$(readlink -f $CURLFUZZROOT/../curl)

echo $me: CURLROOT=$CURLROOT
echo $me: CURLFUZZROOT=$CURLFUZZROOT

# assume the fuzzers are here
BUILDROOT=$PWD
echo $me: BUILDROOT=$BUILDROOT

#the root of the corpus dir (expecting subdirs matching the individual fuzzers)
CORPUSROOT=$CURLFUZZROOT/intree_fuzzer/corpus/
echo $me: CORPUSROOT=$CORPUSROOT

networkfuzzers="all dict file ftp gopher http https imap ldap pop3 rtmp rtsp scp sftp smb smtp tftp"

internalfuzzers=$(ls $BUILDROOT/tests/internalfuzzer_fuzz_* |sort |cut -f3 -d_|xargs echo)

LLVMVERSION="-7"

dryrun=echo
dryrun="nice -n 19"

purpose=coverage
#purpose=replay
#purpose=minimize

scope=internal
scope=external
#scope="internal external"

# $1 - fuzzer binary
# $2 - replay data (directory)
# $3 - short name
executesingle() {
   exe=$1
   replaydata=$2
   shortname=$3
   case $purpose in
      coverage)
         echo "$me: running for coverage. exe=$exe"
         LPF=$shortname.profraw
         if [ ! -e $LPF ] ; then
            LLVM_PROFILE_FILE=$LPF $dryrun $exe $replaydata $extradata
            # $(find $replaydata -type f |head -n1000)
            $dryrun llvm-profdata$LLVMVERSION merge -sparse $LPF -o $shortname.profdata
         else
            echo "$me: $shortname.profdata already exists"
         fi
         ;;
      replay)
         $dryrun LLVM_PROFILE_FILE=$LPF $exe $replaydata $extradata
         ;;
      minimize)
         $dryrun mkdir -p $replaydata # ok if exists and has content
         echo "$me: removing $replaydata.cmintmp"
         if [ -d $replaydata.cmintmp ] ; then
            $dryrun rmdir $replaydata.cmintmp --ignore-fail-on-non-empty
         fi
         echo "$me: mkdir $replaydata.cmintmp"
         $dryrun mkdir $replaydata.cmintmp # fails if exists - good
         echo "$me: invoking $exe"
         $dryrun $exe -merge=1 $replaydata.cmintmp $replaydata $extradata
         $dryrun mv $replaydata $replaydata.old
         $dryrun mv $replaydata.cmintmp $replaydata
         ;;
      *)
         echo $me: unknown purpose $purpose
   esac
}
if echo $scope |grep -q "external" ; then
   for nf in $networkfuzzers; do
      echo $me: considering network fuzzer $nf
      exe=$BUILDROOT/tests/curl_fuzzer_$nf
      if [ ! -x $exe ] ; then
         echo $me: could not find $exe
         exit 1
      fi
      replaydata=$CORPUSROOT/$nf
      if [ ! -d $replaydata ] ; then
         echo "$me: could not find $replaydata"
         exit 1
      fi
      executesingle $exe $replaydata $nf
   done
else
   echo $me: scope is not external, skipping
fi

if echo $scope |grep -q "internal" ; then
   for intf in $internalfuzzers; do
      echo $me: considering $intf
      exe=$BUILDROOT/tests/internalfuzzer_fuzz_$intf
      if [ ! -x $exe ] ; then
         echo $me: could not find $exe $intf
         exit 1
      fi
      replaydata=$CORPUSROOT/$intf
      if [ ! -d $replaydata ] ; then
         echo "$me: could not find $replaydata, nevermind"
         #exit 1
      fi
      executesingle $exe $replaydata $intf
   done
else
   echo $me: scope is not internal
fi

case $purpose in
   coverage)
      # merge everything into one
      $dryrun llvm-profdata$LLVMVERSION merge -o allmerged *.profdata

      # make a html report
      $dryrun llvm-cov$LLVMVERSION  show -format=html -output-dir here --instr-profile allmerged \
              $BUILDROOT/tests/curl_fuzzer_*

      echo "$me: html is in here: "
      echo "file://$PWD/here/index.html"
      ;;
esac

