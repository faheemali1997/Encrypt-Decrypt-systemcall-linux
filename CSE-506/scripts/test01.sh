#!/bin/sh

# Test copy command for test_cryptocopy and to compare whether
# two files after copy are same or not by comparing the files.
set -x

echo dummy data - operating systems  > infile.test

/bin/rm -f outfile.test

echo  "" >> results
echo  "" >> log
echo Test File: test01.sh  >> results
echo Test File: test01.sh  >> log

echo Command: ./test_cryptocopy -c  infile.test outfile.test >> results
echo Command: ./test_cryptocopy -c  infile.test outfile.test >> log

../test_cryptocopy -c  infile.test outfile.test >> log

retval=$?
if test $retval != 0 ; then
	echo Result: test_cryptocopy failed with error: $retval >> results
else
	echo Result: test_cryptocopy program succeeded >> results
fi

echo  "" >> results
echo  "" >> log

if cmp infile.test outfile.test ; then
	echo "Comments: [SUCCESS] infile.test and outfile.test have SAME content" >> results
else
	echo "Comments: infile.test and outfile.test have DIFFERENT content" >> results
fi

/bin/rm -f infile.test
/bin/rm -f outfile.test

echo "------------------------------------------------------------------------------" >> results
echo "------------------------------------------------------------------------------" >> log
