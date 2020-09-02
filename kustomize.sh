#!/bin/sh
cat <&0 > all.yaml

kustomize build .