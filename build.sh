#!/bin/bash
rm gackdoor
CGO_ENABLED=0 go build
mv gackdoor encryptor

cd encryptor
go run .

rm gackdoor
mv encGack ../stub

cd ../stub
CGO_ENABLED=0 go build

rm encGack
mv stub ../gackdoor
