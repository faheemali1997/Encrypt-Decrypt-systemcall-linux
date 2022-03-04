#!/bin/sh

# Test encrypt/decrypt command for test_cryptocopy and to compare whether
# two files after copy are same or not by comparing the files.
set -x

echo dummy data - operating systems  > infile.test

/bin/rm -f outfile.test

echo  "" >> results
echo  "" >> log
echo Test File: test02.sh  >> results
echo Test File: test02.sh  >> log

echo Command: ./test_cryptocopy -e -p password infile.test tempfile.test >> results
echo Command: ./test_cryptocopy -e -p password infile.test tempfile.test >> log

../test_cryptocopy -e -p password infile.test tempfile.test >> log

retval=$?
if test $retval != 0 ; then
	echo Result: [Encryption] test_cryptocopy failed with error: $retval >> results
else
	echo Result: [Encryption] test_cryptocopy program succeeded >> results
fi

echo Command: ./test_cryptocopy -d -p password tempfile.test outfile.test >> results
echo Command: ./test_cryptocopy -d -p password tempfile.test outfile.test >> log

../test_cryptocopy -d -p password tempfile.test outfile.test >> log

retval=$?
if test $retval != 0 ; then
	echo Result: [Decryption] test_cryptocopy failed with error: $retval >> results
else
	echo Result: [Decryption] test_cryptocopy program succeeded >> results
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
