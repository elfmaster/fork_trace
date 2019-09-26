all:
	clang -DDEBUG inject.c -o inject
	clang testproc.c -o test
clean:
	rm -f test inject *.o

