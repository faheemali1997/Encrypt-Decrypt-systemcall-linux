#!/bin/sh

# Test copy command when no arguments are given
set -x

echo dummy data - operating systems  > infile.test

/bin/rm -f outfile.test

echo  "" >> results
echo  "" >> log
echo Test File: test11.sh  >> results
echo Test File: test11.sh  >> log

echo Command: ./xhw1 >> results
echo Command: ./xhw1 >> log

../xhw1 >> log

retval=$?
if test $retval != 0 ; then
	echo Result: xhw1 failed with error: $retval as no arguments were given >> results
else
	echo Result: xhw1 program succeeded >> results
fi

/bin/rm -f infile.test
/bin/rm -f outfile.test

echo "------------------------------------------------------------------------------" >> results
echo "------------------------------------------------------------------------------" >> log
