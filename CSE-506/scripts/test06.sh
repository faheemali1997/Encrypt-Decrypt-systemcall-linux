set -x

# Test copy command when password is also given
echo dummy data - operating systems  > infile.test

/bin/rm -f outfile.test

echo  "" >> results
echo  "" >> log
echo Test File: test06.sh  >> results
echo Test File: test06.sh  >> log

echo Command: ./xhw1 -c -p password  infile.test outfile.test >> results
echo Command: ./xhw1 -c -p password  infile.test outfile.test >> log

../xhw1 -c -p password infile.test outfile.test >> log

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
