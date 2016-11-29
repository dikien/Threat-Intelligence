#!/usr/bin/env bash

filename='iplist.txt'
while read p; do
#    python ./scan -s -v -ip $p -o -r 5
    python ./scan -s -g -url $p
    sleep 5s
done < $filename