set -x

# Test command with wrong parameter given
echo dummy data - operating systems  > infile.test

/bin/rm -f outfile.test

echo  "" >> results
echo  "" >> log
echo Test File: test07.sh  >> results
echo Test File: test07.sh  >> log

echo Command: ./test_cryptocopy -q -p password  infile.test outfile.test >> results
echo Command: ./test_cryptocopy -q -p password  infile.test outfile.test >> log

../test_cryptocopy -q -p password infile.test outfile.test >> log

retval=$?
if test $retval != 0 ; then
	echo Result: test_cryptocopy failed with error: $retval >> results
    echo Comments: Successfully validated missing/extra/wrong arguments >> results
else
	echo Result: test_cryptocopy program succeeded >> results
    echo Comments: Unsuccessfully validated missing/extra/wrong arguments >> results
fi

/bin/rm -f infile.test
/bin/rm -f outfile.test

echo "------------------------------------------------------------------------------" >> results
echo "------------------------------------------------------------------------------" >> log
