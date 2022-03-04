#!/bin/sh

# Test copy command when output filename is empty
set -x

echo dummy data - operating systems  > infile.test

/bin/rm -f outfile.test

echo  "" >> results
echo  "" >> log
echo Test File: test10.sh  >> results
echo Test File: test10.sh  >> log

echo Command: ./test_cryptocopy -c  infile.test infile.test >> results
echo Command: ./test_cryptocopy -c  infile.test infile.test >> log

../test_cryptocopy -c  infile.test "" >> log

retval=$?
if test $retval != 0 ; then
	echo Result: test_cryptocopy failed with error: $retval as output file name was string >> results
else
	echo Result: test_cryptocopy program succeeded >> results
fi

/bin/rm -f infile.test
/bin/rm -f outfile.test

echo "------------------------------------------------------------------------------" >> results
echo "------------------------------------------------------------------------------" >> log
