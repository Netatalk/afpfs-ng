#!/bin/bash

server1=localhost
volume1=v2
user1=adevries
pass1=lollipop

server2=localhost
volume2=v4
user2=adevries
pass2=lollipop


basedir=/tmp/tests
tarballdir=/home/adevries/notebook/
tarball=linux-2.6.9.tar.bz2
mnt1=$basedir/mnt1
mnt2=$basedir/mnt2

voldir=tests

client="./afp_client"

mkdir -p $mnt1 $mnt2

# 1. mount both clients

$client mount -u $user1 -p $pass1 $server1:$volume1 $mnt1
if [ $? -ne 0 ] ; then echo "Could not mount $server1:$volume1"
	exit 1;
fi

$client mount -u $user2 -p $pass2 $server2:$volume2 $mnt2
if [ $? -ne 0 ] ; then echo "Could not mount $server2:$volume2"
	exit 1;
fi

rm -rf $mnt1/$voldir
rm -rf $mnt2/$voldir
mkdir -p $mnt1/$voldir $mnt2/$voldir

# 2. copy tarball to mnt1

cp $tarballdir/$tarball $mnt1/$voldir

# 3. untar it

cd $mnt2/$voldir/
tar -xjf $mnt1/$voldir/$tarball


rm -rf $mnt1/$voldir 
rm -rf $mnt2/$voldir 

