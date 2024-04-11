CXX=clang++

CXXFLAGS=-Wall -Wextra -Wpedantic -std=c++11

TESTS_CASES=./tests/cb_path_test

all: cb

cb: cb.hpp
	${CXX} ${CXXFLAGS} ./cb.cpp -o cb

tests: ${TESTS_CASES}

./tests/%.o:./tests/%.cpp
	${CXX} -DCB_IMPLEMENTATION ${CXXFLAGS} -c $< -o $@

./tests/%:./tests/%.o
	${CXX} -DCB_IMPLEMENTATION ${CXXFLAGS} -o $@ $<
	$@

clean:
	rm -rf ./build
	rm -f  ./cb.o ./cb ./cb.old ${TESTS_CASES}
