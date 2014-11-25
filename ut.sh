#!/bin/sh


USE_DMD="ona"
SHORT_TEST="ona"

while [ $# != 0 ]; do
  if [ "z$1" = "z--help" ]; then
    echo "usage: $0 [options]"
    echo "options:"
    echo "  --dmd   use DMD"
    echo "  --lite  lite tests"
    exit 1
  fi
  if [ "z$1" = "z--dmd" ]; then
    USE_DMD="tan"
  elif [ "z$1" = "z--lite" ]; then
    SHORT_TEST="tan"
  else
    echo "invalid arg: $1"
    exit 1
  fi
  shift
done


rm tweetNaCl tweetNaCl.o 2>/dev/null

if [ $USE_DMD = "tan" ]; then
  if [ $SHORT_TEST = "tan" ]; then
    tt=""
  else
    tt="-version=unittest_full"
  fi
  echo -n "DMD..."
  time dmd -version=tweetnacl_unittest -version=unittest_main $tt -unittest -O -inline -w -oftweetNaCl tweetNaCl.d
else
  if [ $SHORT_TEST = "tan" ]; then
    tt=""
  else
    tt="-fversion=unittest_full"
  fi
  echo -n "GDC..."
  time gdc -fversion=tweetnacl_unittest -fversion=unittest_main $tt -funittest -O3 -fwrapv -march=native -mtune=native -Wall -o tweetNaCl tweetNaCl.d
fi
if [ $? != 0 ]; then
  echo "FUCK!"
  rm tweetNaCl.o 2>/dev/null
  exit 1
fi
rm tweetNaCl.o 2>/dev/null

time ./tweetNaCl
