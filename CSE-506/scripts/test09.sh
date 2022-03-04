#!/bin/sh

# Test copy command when input and output file are the same
set -x

echo dummy data - operating systems  > infile.test

/bin/rm -f outfile.test

echo  "" >> results
echo  "" >> log
echo Test File: test09.sh  >> results
echo Test File: test09.sh  >> log

echo Command: ./test_cryptocopy -c  infile.test infile.test >> results
echo Command: ./test_cryptocopy -c  infile.test infile.test >> log

../test_cryptocopy -c  infile.test infile.test >> log

retval=$?
if test $retval != 0 ; then
	echo Result: test_cryptocopy failed with error: $retval as input file was same as output file >> results
else
	echo Result: test_cryptocopy program succeeded >> results
fi

/bin/rm -f infile.test
/bin/rm -f outfile.test

echo "------------------------------------------------------------------------------" >> results
echo "------------------------------------------------------------------------------" >> log
