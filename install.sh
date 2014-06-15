#!/bin/bash
cd src/
gcc -v -o cniff cniff.c -lpcap
cp cniff /usr/bin/cniff
cd ..

echo "Quick and painless. Enjoy Cniff"

