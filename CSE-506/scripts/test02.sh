#!/bin/sh

# Test copy command for xhw1 and to compare whether
# two files after copy are same or not by comparing the files.
# Inputs:
#		infile.test -> File with the input data
# 		outfile.test -> File with the copied data
# Outputs: Whether copying was successful or not.
set -x

echo dummy data - operating systems  > infile.test

/bin/rm -f outfile.test

echo  "" >> results
echo  "" >> log
echo Test File: test02.sh  >> results
echo Test File: test02.sh  >> log

echo Command: ./xhw1 -e -p password infile.test tempfile.test >> results
echo Command: ./xhw1 -e -p password infile.test tempfile.test >> log

../xhw1 -e -p password infile.test tempfile.test >> log

retval=$?
if test $retval != 0 ; then
	echo Result: [Encryption] xhw1 failed with error: $retval >> results
else
	echo Result: [Encryption] xhw1 program succeeded >> results
fi

echo Command: ./xhw1 -d -p password tempfile.test outfile.test >> results
echo Command: ./xhw1 -d -p password tempfile.test outfile.test >> log

../xhw1 -d -p password tempfile.test outfile.test >> log

retval=$?
if test $retval != 0 ; then
	echo Result: [Decryption] xhw1 failed with error: $retval >> results
else
	echo Result: [Decryption] xhw1 program succeeded >> results
fi

echo  "" >> results
echo  "" >> log

if cmp infile.test outfile.test ; then
	echo Comments: infile.test and outfile.test have SAME content >> results
else
	echo Comments: infile.test and outfile.test have DIFFERENT content >> results
fi

/bin/rm -f infile.test
/bin/rm -f outfile.test
/bin/rm -f tempfile.test

echo "------------------------------------------------------------------------------" >> results
echo "------------------------------------------------------------------------------" >> log
