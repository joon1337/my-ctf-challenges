# https://github.com/bluesadi/Pluto
# -mllvm -passes=mba,sub,fla,gle

CC = /home/wonjoon/Pluto/build/llvm/bin/clang
CFLAG = -mllvm -passes=fla -lssl -lcrypto
OUT = prob

default:
        $(CC) $(CFLAG) prob.c -o $(OUT)
        strip $(OUT)

clean:
        rm prob