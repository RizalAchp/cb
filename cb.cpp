#define CB_IMPLEMENTATION
#include "cb.hpp"

using namespace cb;

static cb::Status on_configure(cb::Cb &cb) {
    CB_INFO("ON CONFIGURE %s", __PRETTY_FUNCTION__);

    /// create static lib or dynamic lib
    /// auto lib_tests = cb.create_dynamic_lib("static_lib_tests");
    auto lib_tests = cb.create_static_lib("static_lib_tests");
    lib_tests->add_flags("-Wall -Wextra -pedantic");
    /// add includes dir
    lib_tests->add_includes("./libtests/include");
    /// add source by extension and recursive on dir `./libtests/src/`
    lib_tests->add_sources_with_ext("./libtests/src/", "c", true);

    /// using pkgconf (linux only)
    auto system_lib   = cb.create_target_pkgconf("x11");

    auto exec_testing = cb.create_exec("exec_testing");
    exec_testing->add_flags("-Wall -Wextra -pedantic");

    /// link with library
    exec_testing->link_library(lib_tests);
    exec_testing->link_library(system_lib);

    /// you can add source with variadic arguments
    exec_testing->add_sources("./main.c", "./etc.c", "./test.c");

    return cb::Status::OK;
}
static cb::Status on_tests(cb::Cb &cb) {
    CB_INFO("ON TESTS %s", __PRETTY_FUNCTION__);
    (void)cb;
    return cb::Status::OK;
}

CB_MAIN {
    cb::Cb cb("testing");
    cb.add_callback("tests", on_tests);
    cb.add_callback("config", on_configure);
    cb.run(argc, argv);
    return 0;
}
