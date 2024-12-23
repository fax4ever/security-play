#!/usr/bin/env bash
set -e
openssl version

function checkTLS() {
    start=`date +%s%N`
    echo | openssl s_client -connect $1:443 2>/dev/null
    end=`date +%s%N`
    runtime=$((end-start))
    echo "$1 => $runtime"
}

checkTLS google.com
checkTLS facebook.com
checkTLS redhat.com
checkTLS infinispan.org
checkTLS almaviva.it
checkTLS www.eng.it
checkTLS edenred.it
checkTLS esa.int
checkTLS theguardian.com
checkTLS repubblica.it
checkTLS huffingtonpost.it
checkTLS quotidianolavoce.it
checkTLS baraondanews.it
checkTLS mit.edu
checkTLS stanford.edu
checkTLS uniroma1.it
checkTLS unicusano.it
checkTLS chiaveorgonica.it
checkTLS diocesiportosantarufina.it
checkTLS hwpviewer.hbedu.co.kr



