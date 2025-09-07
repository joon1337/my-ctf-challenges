#!/bin/bash

python3 ../util/codegen.py ../util/prob.asm ../util/prob.bytecode
ld -r -b binary -o bytecode.o ../util/prob.bytecode
gcc vm.c bytecode.o -o vm
