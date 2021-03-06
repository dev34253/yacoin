#!/bin/bash

echo ">>> Building yacoin ..."
date

./autogen.sh
./configure
make

mkdir debug
make release

echo ">>> Done building yacoin."
date
