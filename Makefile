all: build

build: my_av

my_av: my_av.c
	gcc -o my_av -g my_av.c -lm -DVARIATION

my_av_var: my_av.c
	gcc -o my_av my_av.c -lm

run:
	./my_av

pack:
	zip -9 -FSr my_av.zip my_av.c my_av.py Makefile README

clean:
	rm -f my_av
