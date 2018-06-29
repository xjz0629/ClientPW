test:test.o SM3.o
	gcc -o test test.o SM3.o
test.o:test.c SM3.c 
	gcc -c test.c SM3.c `pkg-config --cflags --libs gtk+-3.0` 
SM3.o:SM3.c SM3.h
	gcc -c SM3.c
 
