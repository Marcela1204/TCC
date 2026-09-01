#!/bin/bash

for  file in "$1" ; do 
	./analise.py "$file" >> "$2"
done

