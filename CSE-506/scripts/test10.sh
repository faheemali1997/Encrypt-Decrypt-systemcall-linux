#!/bin/sh

# Test copy command when output filename is empty
set -x

echo dummy data - operating systems  > infile.test

/bin/rm -f outfile.test

echo  "" >> results
echo  "" >> log
echo Test File: test10.sh  >> results
echo Test File: test10.sh  >> log

echo Command: ./xhw1 -c  infile.test infile.test >> results
echo Command: ./xhw1 -c  infile.test infile.test >> log

../xhw1 -c  infile.test "" >> log

retval=$?
if test $retval != 0 ; then
	echo Result: xhw1 failed with error: $retval as output file name was string >> results
else
	echo Result: xhw1 program succeeded >> results
fi

/bin/rm -f infile.test
/bin/rm -f outfile.test

echo "------------------------------------------------------------------------------" >> results
echo "------------------------------------------------------------------------------" >> log
