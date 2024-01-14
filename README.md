# CB (Compiler Builder)
C/C++ builder using its owm language C++ it self, no need using make or CMake again.

## Quick Start 
- clone this repo or just download the `cb.h` file into your projects, because cb is header only library.
- create `cb.cpp` file and include the `cb.h`. example:

```cpp
#define CB_IMPLEMENTATION
#include "cb.hpp"

using namespace cb;

/// the default callbacks is ['build', 'config', 'clean', 'install']
/// but you can override it, using the function `add_callback` on `Cb`
/// - see in `CB_MAIN`
static Status on_configure(Cb &cb) {
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

    return Status::OK;
}

/// custom callbacks that can call in program arguments(argv)
/// - see in `CB_MAIN` on `add_callback`
static Status on_tests(Cb &cb) {
    CB_INFO("ON TESTS %s", __PRETTY_FUNCTION__);
    (void)cb;
    return Status::OK;
}

/// abstraction function to main, for configuring self build on change
/// you can use use direnct main too
/// example:
/// // int main(int argc, char **argv) {
/// //      if (!cb::rebuild_self(argc, argv, __FILE__)) return 1;
/// //      ...
/// //      return 0;
/// // }
/// //
CB_MAIN {
    /// create `Cb` object with spesified name for the main project name
    cb::Cb cb("testing");
    cb.add_callback("tests", on_tests);
    cb.add_callback("config", on_configure);
    cb.run(argc, argv);
    return 0;
}
```

- then compile it with your standard c++ compiler and run the program

```console
$ cc -o cb ./cb.cpp
$ ./cb <args>
```

- it will create build directory `./build` with generated config file inside
- the config file is not required to change, you should change the behavior of config using
  commandline or directly in the c++ source `cb.cpp` because it automaticaly check if the config is
  changed.

## List Default Sub Commands
- build
    - checks if source for spesific target is changed, if changed it will rebuild
- config
    - for initialize the config if not yet initialize
    - refreshes config file
- clean
    - for cleaning build objects artifacts
- install
    - install the binary to spesified `install_prefix` from config (default to /usr/bin)
      for changing the `install_prefix`, use `cb.cfg.set_install_prefix(...)`
    - it respect binary and library file to spesific locaton from install_prefix 
      (currently implemented just for linux)

NOTE: Default sub commands can be override by function `cb.add_callback(name, function)`
      `function` is callback with type `cb::Status (*callbacks_cb_t)(cb::Cb &cb)`
