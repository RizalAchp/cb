#define CATCH_CONFIG_MAIN
#include "../cb.hpp"
#include "catch.hpp"

using namespace cb;

TEST_CASE("Path Append", "[path_append]") {
    Str path = "/this/is/";
    path_append(path, "/path");
    REQUIRE(path == "/this/is/path");

    path_append(path, "other");
    REQUIRE(path == "/this/is/path/other");

    path_append(path, "../other");
    REQUIRE(path == "/this/is/path/other/../other");
}

TEST_CASE("Path extensions", "[path_extension]") {
    REQUIRE(path_extension("/path/file.cpp") == "cpp");
    REQUIRE(path_extension("/path/file.tar.gz") == "gz");
}

TEST_CASE("Path filename", "[filename]") {
    REQUIRE("bin" == path_filename("/usr/bin/"));
    REQUIRE("foo.txt" == path_filename("tmp/foo.txt"));
    REQUIRE("foo.txt" == path_filename("foo.txt/."));
    REQUIRE("foo.txt" == path_filename("foo.txt/.//"));
    REQUIRE("foo.txt" == path_filename("foo.txt/.."));
    REQUIRE("" == path_filename("/"));
}

TEST_CASE("Path with extensions", "[path_set_extension]") {
    Str path1 = "/path/file.cpp";
    path_set_extension(path1, "hpp");
    REQUIRE(path1 == "/path/file.hpp");

    Str path2 = "/path/file.tar.gz";
    path_set_extension(path2, "zip");
    REQUIRE(path2 == "/path/file.tar.zip");

    Str path3 = "/path/file.tar.gz";
    path_set_extension(path3, nullptr);
    REQUIRE(path3 == "/path/file.tar");
}
