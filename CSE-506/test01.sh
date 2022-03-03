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
echo Test File: test01.sh  >> results
echo Test File: test01.sh  >> log

echo Command: ./xhw1 -c  infile.test outfile.test >> results
echo Command: ./xhw1 -c  infile.test outfile.test >> log

./xhw1 -c  infile.test outfile.test >> log

retval=$?
if test $retval != 0 ; then
	echo Result: xhw1 failed with error: $retval >> results
else
	echo Result: xhw1 program succeeded >> results
fi

if cmp infile.test outfile.test ; then
	echo "Comments: infile.test and outfile.test have SAME content" >> results
else
	echo "Comments: infile.test and outfile.test have DIFFERENT content" >> results
fi

echo "------------------------------------------------------------------------------" >> results
echo "------------------------------------------------------------------------------" >> log
