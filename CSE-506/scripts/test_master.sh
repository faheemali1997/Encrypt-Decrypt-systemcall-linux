#!/bin/sh

#Run all the test files

/bin/rm -f log
/bin/rm -f results

touch log
touch results

sh ./test01.sh
sh ./test02.sh
sh ./test03.sh
sh ./test04.sh
sh ./test05.sh
sh ./test06.sh
sh ./test07.sh
sh ./test08.sh
sh ./test09.sh
sh ./test10.sh
sh ./test11.sh
sh ./test12.sh