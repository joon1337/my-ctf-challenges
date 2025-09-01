CC="/mnt/d/BoB/contest/ctf/Polaris-Obfuscator/src/build/bin/clang++"
$CC -mllvm -passes=fla,indcall,mba -o prob prob.cc -lncurses -lssl -lcrypto
