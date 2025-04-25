#!/bin/bash

opt="$1"
target="$2"

if [[opt == 'sweep']]; then
  sudo nmap -sn $target
elif [[ opt == 'syn' ]]; then
  sudo nmap -sS $target
elif [[ opt == 'os' ]]; then
  sudo nmap -sO $target
elif [[ opt == 'vuln' ]]; then
  sudo nmap -sV --script vuln $target
fi
	
