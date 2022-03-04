#!/bin/sh

# Test decrypt command with wrong password
set -x

echo dummy data - operating systems  > infile.test

/bin/rm -f outfile.test

echo  "" >> results
echo  "" >> log
echo Test File: test05.sh  >> results
echo Test File: test05.sh  >> log

echo Command: ./xhw1 -e -p password infile.test tempfile.test >> results
echo Command: ./xhw1 -e -p password infile.test tempfile.test >> log

../xhw1 -e -p password infile.test tempfile.test >> log

retval=$?
if test $retval != 0 ; then
	echo Result: [Encryption] xhw1 failed with error: $retval >> results
else
	echo Result: [Encryption] xhw1 program succeeded >> results
fi

echo Command: ./xhw1 -d -p wrongpassword tempfile.test outfile.test >> results
echo Command: ./xhw1 -d -p wrongpassword tempfile.test outfile.test >> log

../xhw1 -d -p wrongpassword tempfile.test outfile.test >> log

retval=$?
if test $retval != 0 ; then
	echo Result: [Decryption] Successfully failed when wrong password was given: $retval >> results
else
	echo Result: [Decryption] Unssuccessful >> results
fi

/bin/rm -f infile.test
/bin/rm -f outfile.test
/bin/rm -f tempfile.test

echo "------------------------------------------------------------------------------" >> results
echo "------------------------------------------------------------------------------" >> log
