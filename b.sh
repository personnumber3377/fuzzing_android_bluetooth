#!/bin/sh
clang -DMUT_TESTING gatt_mutator.c -fsanitize=address -g0 -o mut_test
