#!/bin/bash
rm -rf $UNQUOTED_DIR/*
eval $USER_INPUT
cp $1 /tmp/$2
