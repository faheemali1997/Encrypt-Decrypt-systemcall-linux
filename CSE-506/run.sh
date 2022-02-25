#!/bin/sh
set -x
make clean
make all
sh install_module.sh
./xhw1