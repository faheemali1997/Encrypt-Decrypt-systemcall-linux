#!/bin/sh

# Test encrypt command for test_cryptocopy with missing passowrd for encryption
set -x

echo dummy data - operating systems  > infile.test

/bin/rm -f outfile.test

echo  "" >> results
echo  "" >> log
echo Test File: test04.sh  >> results
echo Test File: test04.sh  >> log

echo Command: ./test_cryptocopy -e  infile.test outfile.test >> results
echo Command: ./test_cryptocopy -e  infile.test outfile.test >> log

../test_cryptocopy -e infile.test outfile.test >> log

retval=$?
if test $retval != 0 ; then
	echo Result: test_cryptocopy failed with error: $retval >> results
    echo Comments: Successfully validated missing/extra arguments >> results
else
	echo Result: test_cryptocopy program succeeded >> results
    echo Comments: Unsuccessfully validated missing/extra arguments >> results
fi

/bin/rm -f infile.test
/bin/rm -f outfile.test

echo "------------------------------------------------------------------------------" >> results
echo "------------------------------------------------------------------------------" >> log
