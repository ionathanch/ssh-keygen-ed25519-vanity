#!/bin/bash

PUBKEY=""
KEYFILE="id_ed25519_vanity$2"
GREEN="\033[0;32m"
NC="\033[0m"

while [[ $PUBKEY != *$1* ]]
do
  ssh-keygen -qa 1 -t ed25519 -f ~/.ssh/$KEYFILE -N "" -C "" <<< y 1>/dev/null
  PUBKEY=$(cat ~/.ssh/$KEYFILE.pub)
done

echo -e "Found public key ($KEYFILE): ${PUBKEY//$1/$GREEN$1$NC}"
