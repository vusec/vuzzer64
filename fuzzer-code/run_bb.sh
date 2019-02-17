#!/bin/bash
if [ -z "$BBOUT" ]; then
  echo "You need to specify \$BBOUT"
  exit 1
fi
if [ "$LIBS" = "#" ]; then
  $PIN_ROOT/pin -t ./obj-intel64/bbcounts2.so -o $BBOUT -libc 0 -- $@
else
  $PIN_ROOT/pin -t ./obj-intel64/bbcounts2.so -l $LIBS -o $BBOUT -libc 0 -- $@
fi