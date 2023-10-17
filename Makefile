
CFLAGS=-DCB_TESTS -Wall -Wextra -pedantic -Wpedantic -ggdb -O1

all: cb
	@echo "Finish Building"
	@echo

cb: ./tests.c ./cb.h
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f ./cb
