set -x

# Test command with lots of additional extra parameters give
echo dummy data - operating systems  > infile.test

/bin/rm -f outfile.test

echo  "" >> results
echo  "" >> log
echo Test File: test08.sh  >> results
echo Test File: test08.sh  >> log

echo Command: ./test_cryptocopy -q -e -d -p password  infile.test outfile.test >> results
echo Command: ./test_cryptocopy -q -e -d -p password  infile.test outfile.test >> log

../test_cryptocopy -q -e -d -p password infile.test outfile.test >> log

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
