#!/bin/sh

# Test copy command for xhw1 with missing arguments
# Inputs:
#		infile.test -> File with the input data
# 		outfile.test -> File with the copied data
# Outputs: Invalid arguments provided
set -x

echo dummy data - operating systems  > infile.test

/bin/rm -f outfile.test

echo  "" >> results
echo  "" >> log
echo Test File: test03.sh  >> results
echo Test File: test03.sh  >> log

echo Command: ./xhw1 -c  infile.test outfile.test >> results
echo Command: ./xhw1 -c  infile.test outfile.test >> log

../xhw1 -c infile.test >> log

retval=$?
if test $retval != 0 ; then
	echo Result: xhw1 failed with error: $retval >> results
    echo Comments: Successfully validated missing/extra arguments >> results
else
	echo Result: xhw1 program succeeded >> results
    echo Comments: Unsuccessfully validated missing/extra arguments >> results
fi

/bin/rm -f infile.test
/bin/rm -f outfile.test

echo "------------------------------------------------------------------------------" >> results
echo "------------------------------------------------------------------------------" >> log
