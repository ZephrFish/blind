BOFNAME := bofblind
CC_x64 := x86_64-w64-mingw32-gcc


all:
	$(CC_x64) -o ./dist/$(BOFNAME).x64.o -c ./src/bofblind.c -masm=intel

clean:
	rm -f ./dist/$(BOFNAME).x64.o
