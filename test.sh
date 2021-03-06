#!/bin/sh -e

verifyArchive() {
	echo "Verifying archive"
	YES_COUNT=$(./rosa debug testdata/archive.rosa|head|grep Yes|wc -l)
	ORPHANS_COUNT=$(./rosa debug testdata/archive.rosa|grep "refs: 0"|wc -l)
	if [ "$YES_COUNT" -ne "0" ]
	then
		echo "There is either journal or orphan nodes!"
		exit 1
	fi
	if [ "$ORPHANS_COUNT" -ne "0" ]
	then
		echo "There are orphans, even if header claims there should not be any!"
		exit 1
	fi
	if [ "$1" = "" ]
	then
		./rosa verify testdata/archive.rosa
	else
		./rosa verify testdata/archive.rosa -p $1
	fi
}

echo "Compiling"
make clean
cp Makefile Makefile.ORIGINAL
sed -i 's/-DNDEBUG/-Wall -Wpointer-arith -Werror -ansi -pedantic/g' Makefile
make
mv Makefile.ORIGINAL Makefile

echo "Obtaining test data"
rm -rf testdata
mkdir testdata
wget http://storage.henu.fi/rosa/testdata/mercurial-1.7.4.tar.gz -O testdata/1.tgz
wget http://storage.henu.fi/rosa/testdata/mercurial-2.1.2.tar.gz -O testdata/2.tgz
wget http://storage.henu.fi/rosa/testdata/mercurial-2.2.3.tar.gz -O testdata/3.tgz

echo "Extracting test data"
cd testdata
mkdir 1
cd 1
tar xf ../1.tgz
cd ..
mkdir 2
cd 2
tar xf ../2.tgz
cd ..
mkdir 3
cd 3
tar xf ../3.tgz
cd ..
cd ..

echo "Taking first snapshot"
./rosa snapshot testdata/archive.rosa yesterday testdata/1
verifyArchive

echo "Taking second snapshot"
./rosa snapshot testdata/archive.rosa today testdata/2
verifyArchive

echo "Taking third snapshot"
./rosa snapshot testdata/archive.rosa tomorrow testdata/3
verifyArchive

echo "Modifying archive"
./rosa remove testdata/archive.rosa today/2/mercurial-2.1.2/contrib /yesterday/1/mercurial-1.7.4/README
verifyArchive
./rosa mkdir testdata/archive.rosa today/2/lol /test_omg
verifyArchive

rm testdata/archive.rosa

echo "Taking first snapshot of encrypted archive"
./rosa -p test snapshot testdata/archive.rosa yesterday testdata/1
verifyArchive test

echo "Taking second snapshot of encrypted archive"
./rosa -p test snapshot testdata/archive.rosa today testdata/2
verifyArchive test

echo "Taking third snapshot of encrypted archive"
./rosa -p test snapshot testdata/archive.rosa tomorrow testdata/3
verifyArchive test

echo "Modifying encrypted archive"
./rosa -p test remove testdata/archive.rosa today/2/mercurial-2.1.2/contrib /yesterday/1/mercurial-1.7.4/README
verifyArchive test
./rosa -p test mkdir testdata/archive.rosa today/2/lol /test_omg
verifyArchive test

rm testdata/archive.rosa

echo "Interrupting snapshotting"
for i in $(seq 1 1 120)
do
	./rosa snapshot testdata/archive.rosa test testdata/1 &
	ROSA_PID=$!
	sleep 1
	kill -9 $ROSA_PID
done
./rosa snapshot testdata/archive.rosa test testdata/1
verifyArchive

echo "Cleaning"
rm -rf testdata

