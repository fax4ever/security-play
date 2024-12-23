#!/usr/bin/env bash
set -e
openssl version

function checkTLS() {
    start=`date +%s%N`
    echo | openssl s_client -trace -debug -state -tls1_3 -connect $1:443 2>/dev/null
    end=`date +%s%N`
    runtime=$((end-start))
    echo "$1 => $runtime"
}

checkTLS facebook.com
checkTLS redhat.com



