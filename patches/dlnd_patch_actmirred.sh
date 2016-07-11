#!/bin/bash

scriptdir=$(dirname $(readlink -f $0))
if [ ! -f $scriptdir/../config.mak ]; then
    echo "Please run ./configure in the root directory first."
    exit 1
fi
source $scriptdir/../config.mak

# Make a temp directory in build tree.
TMPDIR=$(mktemp -d config.XXXXXX)
trap 'status=$?; rm -rf $TMPDIR; exit $status' EXIT HUP INT QUIT TERM
ACT_MIRRED_URL="https://git.kernel.org/cgit/linux/kernel/git/stable/linux-stable.git/plain/net/sched/act_mirred.c?id=refs/tags/v"

get_actmirred_patch_version()
{
    #ACT_MIRRED_VERSION=$(uname -r | cut -d '.' -f1,2) 

    echo "act_mirred for kernel version: $ACT_MIRRED_VERSION"

    echo "Downloading $ACT_MIRRED_URL$ACT_MIRRED_VERSION"
    wget -q -O $TMPDIR/act_mirred.c $ACT_MIRRED_URL$ACT_MIRRED_VERSION

    echo -n "Computing file hash and identifying appropriate patch... "
    HASH=$(cat $TMPDIR/act_mirred.c | md5sum | cut -d' ' -f1)
    PATCH=$(grep $HASH $scriptdir/act_mirred.patch/patch_dictionary | cut -d' ' -f2)
    if [ -z $PATCH ]; then
        echo "invalid hash... patch not found..."
        exit 1
    fi

    echo "OK"
    echo "The following patch will be applied: $PATCH"
    patch $TMPDIR/act_mirred.c < $scriptdir/act_mirred.patch/$PATCH

    echo "Copying patched file to $scriptdir/../kernel/tc/act_mirred.c"
    cp $TMPDIR/act_mirred.c $scriptdir/../kernel/tc/act_mirred.c

    echo "done..."
    
}


get_actmirred_patch_version
