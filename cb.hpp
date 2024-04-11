#pragma once

#ifndef __CB_H__
#    define __CB_H__

#    define CB_ASSERT(PRED, ...)             \
        if (!(PRED)) {                       \
            CB_ERROR(                        \
                "assertion: "                \
                "(" #PRED "):" __VA_ARGS__); \
            exit(1);                         \
        }
#    define CB_ASSERT_ALLOC(PTR)  CB_ASSERT((PTR != nullptr), "Buy more RAM lol")

#    define CONCAT_INTERNAL(x, y) x##y
#    define CONCAT(x, y)          CONCAT_INTERNAL(x, y)

#    include <algorithm>
#    include <array>
#    include <cstdio>
#    include <cstdlib>
#    include <cstring>
#    include <fstream>
#    include <functional>
#    include <iostream>
#    include <map>
#    include <memory>
#    include <sstream>
#    include <string>
#    include <system_error>
#    include <vector>

#    if defined(unix) || defined(__unix) || defined(__unix__)
#        define CB_UNIX
#        include <dirent.h>
#        include <fcntl.h>
#        include <pwd.h>
#        include <sys/stat.h>
#        include <sys/types.h>
#        include <sys/wait.h>
#        include <unistd.h>

#        define CB_DIR_SEPARATOR      "/"
#        define CB_DIR_SEPARATOR_CHAR '/'
#        define CB_LINE_END           "\n"
#        define CB_PATH_SEPARATOR     ':'
#        define CB_INVALID_PROC       (-1)
#    endif
#    if defined(__linux__) && defined(__linux)
#        define CB_LINUX
#        define CB_DEFAULT_PLATFORM Platform::UNIX
#        define MAX_PATH            PATH_MAX
#    elif defined(__APPLE__) || defined(__MACH__)
#        define CB_MACOS
#        define CB_DEFAULT_PLATFORM Platform::MACOS
#        define MAX_PATH            PATH_MAX
#    elif defined(_WIN32) || defined(WIN32) || defined(_WIN64) || defined(__CYGWIN__) || \
        defined(__MINGW32__)
#        define CB_WINDOWS
#        define CB_DEFAULT_PLATFORM Platform::WINDOWS
#        define WIN32_LEAN_AND_MEAN
#        include <direct.h>
#        include <shellapi.h>
#        include <windows.h>

#        define getcwd(buff, size)    GetCurrentDirectory(size, buff)
#        define CB_PATH_SEPARATOR     ';'
#        define CB_DIR_SEPARATOR      "\\\\"
#        define CB_DIR_SEPARATOR_CHAR '\\'
#        define CB_LINE_END           "\r\n"
#        define CB_INVALID_PROC       INVALID_HANDLE_VALUE
struct dirent {
    char d_name[MAX_PATH + 1];
};
typedef struct DIR DIR;
DIR               *opendir(const char *dirpath);
struct dirent     *readdir(DIR *dirp);
int                closedir(DIR *dirp);

#    else
#        error "Platform: Unknown Platform, not supported Platform"
#    endif

#    if defined(__GNUC__)
#        define CB_DEFAULT_COMPILER Compiler::GNU
#    elif defined(__clang__)
#        define CB_DEFAULT_COMPILER Compiler::CLANG
#    elif defined(_MSC_VER)
#        error "msvc not supported"
#    endif

#    ifndef CB_FNDEF
#        define CB_FNDEF
#    endif
// clang-format off

// TODO: add MinGW support
#    ifndef CB_REBUILD_ARGS
#        if defined(__clang__)
#            define CB_REBUILD_ARGS(binary_path, source_path) "clang++", "-Wall", "-Wextra", "-Wpedantic", "-std=c++11", "-O1", "-o", binary_path, source_path
#        elif defined(__GNUC__)
#            define CB_REBUILD_ARGS(binary_path, source_path) "g++", "-Wall", "-Wextra", "-Wpedantic", "-std=c++11", "-O1", "-o", binary_path, source_path
#        elif defined(_MSC_VER)
#            define CB_REBUILD_ARGS(binary_path, source_path) "cl.exe", source_path
#        endif
#    endif
#    define CB_REBUILD_SELF(argc, argv) cb::rebuild_self(argc, argv, __FILE__)

#define CB_MAIN  \
    static inline int __start(int argc, char *argv[]); \
    int main(int argc, char *argv[]) { \
        if (!cb::rebuild_self(argc, argv, __FILE__)) return 1;\
        return __start(argc, argv); \
    } \
    int __start(int argc, char *argv[])

// clang-format on

namespace cb {
#    if defined(CB_LINUX)
    typedef int proc_t;
#    elif defined(CB_WINDOWS)
    typedef HANDLE proc_t;
#    endif
    using Str   = std::string;
    using Cmd   = std::vector<const char *>;
    using Procs = std::vector<proc_t>;
    template <typename T, size_t N>
    using Arr = std::array<T, N>;
    template <typename T>
    using Vec = std::vector<T>;

    template <typename Key, typename Value>
    using Map = std::map<Key, Value>;

    struct Config;
    struct Cb;

    bool case_cmp(const Str &a, const Str &b);

    template <typename T, typename... Targs>
    CB_FNDEF void format_helper(std::ostream &oss, Str &str, const T &value, const Targs &...rest);

    template <typename... Targs>
    CB_FNDEF Str format(Str fmt, const Targs &...args);
    template <typename... Targs>
    CB_FNDEF std::ostream &sprint(std::ostream &oss, Str fmt, const Targs &...args);

    template <typename... Targs>
    CB_FNDEF void log(const char *level, const char *tag, Str fmt, const Targs &...args);

    CB_FNDEF Str &ltrim(Str &s);
    CB_FNDEF Str &rtrim(Str &s);
    CB_FNDEF Str &trim(Str &s);
    // trim from both ends (copying)
    CB_FNDEF Str trim_copy(Str s);
    CB_FNDEF Vec<Str> split(Str s, Str delimiter);
    template <size_t N>
    CB_FNDEF Arr<Str, N> split_n(Str s, Str delimiter);

    // clang-format off
    enum class Status     : uint8_t { ERR = 0, OK = 1                                    };
    enum class LogLevel   : size_t  { NONE = 0, INFO, WARNING, ERROR, FATAL, MAX         };
    enum class Build      : size_t  { DEBUG = 0, RELEASE, RELEASEDEBUG, MAX              };
    enum class Platform   : size_t  { UNKNOWN = 0, WINDOWS, MACOS, UNIX, MAX             };
    enum class Arch       : size_t  { UNKNOWN = 0, X64, X86, ARM64, ARM32, MAX           };
    enum class Compiler   : size_t  { UNKNOWN = 0, CLANG, GNU, MSVC, MAX                 };
    enum class Program    : size_t  { UNKNOWN = 0, C, CPP, MAX                           };
    enum class TargetType : size_t  { EXEC = 0, STATIC_LIB, DYNAMIC_LIB, SYSTEM_LIB, MAX };

    using callbacks_cb_t = std::function<Status(Cb *)>;
    constexpr inline const char *program_ext(Program p) { return (p == Program::C) ? "c" : "cpp"; }

    extern LogLevel g_log_level;

#    define CB_LOG(level, tag, ...) if (g_log_level <= level) log(LOG_LEVEL_DISPLAY[level], tag, __VA_ARGS__)
#    define CB_FATAL(...)           CB_LOG(LogLevel::FATAL, __FUNCTION__, __VA_ARGS__)
#    define CB_ERROR(...)           CB_LOG(LogLevel::ERROR, __FUNCTION__, __VA_ARGS__)
#    define CB_WARNING(...)         CB_LOG(LogLevel::WARNING, __FUNCTION__, __VA_ARGS__)
#    define CB_INFO(...)            CB_LOG(LogLevel::INFO, __FUNCTION__, __VA_ARGS__)

#    define CB_BAIL_ERROR(RET, ...) { CB_ERROR(__VA_ARGS__);  return RET; }
#    define NOT_IMPLEMENTED(DESC)   CB_ERROR("Not Implemented: {}", DESC), exit(1)
#    define UNREACHABLE(DESC)       CB_ERROR("Unreachable: {}", DESC), exit(1)


    template <class T, const size_t SIZE = static_cast<size_t>(T::MAX)>
    struct EnumDisplay {
        Arr<const char *, SIZE> displays;
        constexpr EnumDisplay(Arr<const char *, SIZE> dp) : displays(dp) {}
        T parse(const Str &needle) const {
            for (size_t idx = 0; idx < displays.size(); idx++)
                if (case_cmp(needle, displays[idx]) && (idx < SIZE)) return static_cast<T>(idx);
            return T(0);
        }
        const char *operator[](T idx) const { return displays[static_cast<size_t>(idx)]; }
    };

    const EnumDisplay<Build>      BUILD_TYPE_DISPLAY  ({"DEBUG", "RELEASE", "REDEBUG"                        });
    const EnumDisplay<Platform>   PLATFORM_DISPLAY    ({"N/A", "WINDOWS", "MACOS", "UNIX"                    });
    const EnumDisplay<Arch>       ARCH_DISPLAY        ({"N/A", "X64", "X86", "ARM64", "ARM32"                });
    const EnumDisplay<Compiler>   COMPILER_DISPLAY    ({"N/A", "CLANG", "GNU", "MSVC"                        });
    const EnumDisplay<Program>    PROGRAM_DISPLAY     ({"N/A", "C", "CPP"                                    });
    const EnumDisplay<TargetType> TARGET_TYPE_DISPLAY ({"executable", "staticlib", "dynamiclib", "systemlib" });
    const EnumDisplay<LogLevel>   LOG_LEVEL_DISPLAY   ({"N/A", "[INFO] ", "[WARN] ", "[ERROR]", "[FATAL]"    });
    // clang-format on

    CB_FNDEF bool file_rename(const Str &old_path, const Str &new_path);
    CB_FNDEF bool file_exists(const Str &file_path);
    CB_FNDEF bool file_copy(const Str &dst_path, const Str &src_path, bool overide = false);

    CB_FNDEF bool rebuild_self(int argc, char *argv[], const char *source_path);
    CB_FNDEF bool mkdir_if_not_exists(const Str &path, bool recursive = true);
    CB_FNDEF bool remove_file(const Str &dirpath);
    CB_FNDEF bool remove_dir(const Str &dirpath);
    CB_FNDEF bool remove_dir_rec(const Str &dirpath);

    enum class FileType { Error, Regular, Directory, SymLink, Other };
    CB_FNDEF FileType file_type(const Str &path);
    /// run command in shell and get output from stdout into `stdout_content`
    CB_FNDEF bool current_path(Str &out_path, const char *optional_append_path = nullptr);
    CB_FNDEF bool home_dir(Str &out_path, const char *optional_append_path = nullptr);
    CB_FNDEF bool set_permissions(const Str &file, mode_t permissions);

    CB_FNDEF bool path_to_absolute(Str &path);
    CB_FNDEF Str  path_filename(const Str &path);
    CB_FNDEF Str  path_extension(const Str &path);
    CB_FNDEF void path_set_extension(Str &path, const char *ext);
    CB_FNDEF void path_append(Str &path, const Str &to_append);

    using WalkdirCallback = std::function<bool(const Str &, FileType)>;
    CB_FNDEF bool walkdir(const Str &parent, bool recursive, WalkdirCallback callback);

    // Wait until the process has finished
    CB_FNDEF bool procs_wait(const Procs &procs);
    CB_FNDEF bool proc_wait(proc_t proc);

    /// run cmd_t asynchronously, returned handle of proc_t
    /// wait the process using function `proc_wait`
    CB_FNDEF proc_t cmd_run_async(Cmd &cmd);
    /// run cmd_t and wait until finish (sync)
    CB_FNDEF bool   cmd_run(Cmd &cmd);
    CB_FNDEF Status popen_stdout(Cmd &cmd, Str &stdout_content);

    template <typename T>
    struct ExitScope {
        T lambda;
        ExitScope(T lambda) : lambda(lambda) {}
        ~ExitScope() { lambda(); }

       private:
        ExitScope &operator=(const ExitScope &);
    };
    struct ExitScopeHelp {
        template <typename T>
        ExitScope<T> operator+(T t) {
            return ExitScope<T>(t);
        }
    };

#    define defer \
        const __attribute__((unused)) auto &CONCAT(__defer__, __LINE__) = ExitScopeHelp() + [&]()

    struct SerializeDeserialize {
        SerializeDeserialize() noexcept                          = default;
        virtual ~SerializeDeserialize()                          = default;
        virtual bool serialize(std::ostream &outstream)          = 0;
        virtual bool deserialize_key_value(Str &key, Str &value) = 0;
        virtual bool deserialize(std::istream &instream);
    };

    enum class NrStatus : int {
        ERR = -1,
        NO  = 0,
        YES,
    };
    // RETURNS:
    //  0 - does not to be needs rebuild
    //  1 - does needs rebuild
    // -1 - error. The error is logged
    template <size_t N>
    CB_FNDEF NrStatus needs_rebuild(const char *output_path, Arr<const char *, N> input_paths) {
#    ifdef CB_WINDOWS
        BOOL   bSuccess;
        HANDLE output_path_fd = CreateFile(output_path, GENERIC_READ, 0, NULL, OPEN_EXISTING,
                                           FILE_ATTRIBUTE_READONLY, NULL);
        if (output_path_fd == INVALID_HANDLE_VALUE) {
            // NOTE: if output does not exist it 100% must be rebuilt
            if (GetLastError() == ERROR_FILE_NOT_FOUND) return NrStatus::YES;
            CB_BAIL_ERROR(NrStatus::ERR, "Could not open file {}: {}", output_path, GetLastError());
        }
        FILETIME output_path_time;
        bSuccess = GetFileTime(output_path_fd, NULL, NULL, &output_path_time);
        CloseHandle(output_path_fd);
        if (!bSuccess)
            CB_BAIL_ERROR(NrStatus::ERR, "Could not get time of {}: {}", output_path,
                          GetLastError());

        for (const auto &input_path : input_paths) {
            HANDLE input_path_fd = CreateFile(input_path, GENERIC_READ, 0, NULL, OPEN_EXISTING,
                                              FILE_ATTRIBUTE_READONLY, NULL);
            // NOTE: non-existing input is an error cause it is needed for
            // building in the first place
            if (input_path_fd == INVALID_HANDLE_VALUE)
                CB_BAIL_ERROR(NrStatus::ERR, "Could not open file {}: {}", input_path,
                              GetLastError());
            FILETIME input_path_time;
            bSuccess = GetFileTime(input_path_fd, NULL, NULL, &input_path_time);
            CloseHandle(input_path_fd);
            if (!bSuccess)
                CB_BAIL_ERROR(NrStatus::ERR, "Could not get time of {}: {}", input_path,
                              GetLastError());
            // NOTE: if even a single input_path is fresher than output_path
            // that's 100% rebuild
            if (CompareFileTime(&input_path_time, &output_path_time) == 1) return NrStatus::YES;
        }
#    else
        struct stat sb;
        memset(&sb, 0, sizeof(sb));

        if (stat(output_path, &sb) < 0) {
            // NOTE: if output does not exist it 100% must be rebuilt
            if (errno == ENOENT) return NrStatus::YES;
            CB_BAIL_ERROR(NrStatus::ERR, "could not stat {}: {}", output_path, strerror(errno));
        }
        int output_path_time = sb.st_mtime;
        for (const auto &input_path : input_paths) {
            if (stat(input_path, &sb) < 0)
                CB_BAIL_ERROR(NrStatus::ERR, "could not stat {}: {}", input_path, strerror(errno));
            int input_path_time = sb.st_mtime;
            // NOTE: if even a single input_path is fresher than output_path
            // that's 100% rebuild
            if (input_path_time > output_path_time) return NrStatus::YES;
        }
#    endif
        return NrStatus::NO;
    }
    /// config_t /////////////////////////////////////////////
    struct Config : public SerializeDeserialize {
        Build         build_type;
        Platform      platform_kind;
        Arch          arch_kind;
        Compiler      compiler_type;
        Program       program_type;
        bool          dump_compile_command;

        Str           subcmd;
        Str           project_name;
        Str           project_path;
        Str           build_path;
        Str           build_artifact_path;
        Str           compiler_path;
        Str           config_path;
        Str           targets_path;

        Str           install_prefix;
        Str           bin_install_dir;
        Str           lib_install_dir;

        static Config create(const Str &name);

        constexpr bool inline is_debug() const {
            return (build_type == Build::DEBUG || build_type == Build::RELEASEDEBUG);
        }
        constexpr bool inline is_release() const {
            return (build_type == Build::RELEASE || build_type == Build::RELEASEDEBUG);
        }
        constexpr bool inline is_compiler_gnu() const { return (compiler_type == Compiler::GNU); }
        constexpr bool inline is_compiler_clang() const {
            return (compiler_type == Compiler::CLANG);
        }
        constexpr bool inline is_windows() const { return (platform_kind == Platform::WINDOWS); }

        void set_install_prefix(const Str &prefix);
        void set_build_path(const Str &path);
        void set_compiler(const Str &cpath, Compiler ctype = Compiler::UNKNOWN);

        bool parse_from_args(const Vec<Str> args, const Map<Str, callbacks_cb_t> &callbacks);

        virtual bool serialize(std::ostream &outstream) override;
        virtual bool deserialize_key_value(Str &key, Str &value) override;
        Status       save(const Str &path);
        Status       load(const Str &path);

        /// get extension str by *target_type_t*
        const char *get_ext(TargetType type) const noexcept {
            switch (type) {
                case TargetType::STATIC_LIB: return "a";
                case TargetType::DYNAMIC_LIB:
                    return (platform_kind == Platform::WINDOWS) ? "dll" : "so";
                case TargetType::EXEC: return (platform_kind == Platform::WINDOWS) ? "exe" : "";
                default: return "";
            }
        }

        size_t hash() const;
        bool   is_changed() const;

        virtual ~Config() override = default;
        Config(Config &&)          = default;

       private:
        Config(const Config &)            = delete;
        Config &operator=(const Config &) = delete;
        Config &operator=(Config &&)      = delete;
        Config()
            : SerializeDeserialize()
            , build_type(Build::DEBUG)
            , platform_kind(CB_DEFAULT_PLATFORM)
            , arch_kind(Arch::X64)
            , compiler_type(CB_DEFAULT_COMPILER)
            , program_type(Program::C)
            , subcmd("") {}
        size_t __hash;
    };

    /// target_t /////////////////////////////////////////////
    struct Source {
        Str src;
        Str out;

        Source() = default;
        Source(const Str &dir, const Str &str);

        inline bool need_rebuild() const {
            return needs_rebuild<1>(out.c_str(), {src.c_str()}) == NrStatus::YES;
        }
    };

    struct Target : public SerializeDeserialize {
        TargetType  type;
        Str         name;
        Source      file;
        Str         output_dir;

        Vec<Str>    flags;
        Vec<Str>    ldflags;
        Vec<Source> sources;

        virtual ~Target() override{};

        Target() = default;
        Target(Str name, TargetType type, const Config &cfg);
        Status        add_sources_with_ext(const Str &dir, const char *ext, bool recursive);
        virtual bool  serialize(std::ostream &out) override;
        virtual bool  deserialize_key_value(Str &key, Str &value) override;

        inline Status add_main_source(Str src) {
            std::error_code ec;
            file.src = src;
            if (!path_to_absolute(file.src))
                CB_BAIL_ERROR(Status::ERR, "Failed to get absolute path from {}", src);
            return Status::OK;
        }

        template <typename... Types>
        inline void add_sources(Types... types) {
            for (const auto &t : {types...}) sources.push_back(Source(output_dir, t));
        }

        template <typename... Types>
        inline void add_flags(Types... types) {
            flags.insert(flags.end(), {types...});
        }
        template <typename... Types>
        inline void add_includes(const Str &p, const Types &...paths) {
            flags.push_back(format("-I{}", p));
            Arr<Str, sizeof...(paths)> arrs{paths...};
            for (auto tp : arrs) flags.push_back(format("-I{}", tp));
        }

        template <typename... Types>
        inline void add_defines(const Str &def, Types... types) {
            flags.push_back(format("-D{}", def));
            Arr<Str, sizeof...(types)> arrs{types...};
            for (auto tp : arrs) flags.push_back(format("-D{}", tp));
        }

        template <typename... Types>
        inline void add_ldflags(Types... types) {
            ldflags.insert(ldflags.end(), {types...});
        }

        Status link_library(const Target &tgt);
        template <typename... Types>
        inline Status link_libraries(const Types... types) {
            Status res = Status::OK;
            for (const auto &t : {types...})
                if (link_library(t) == Status::ERR) return Status::ERR;
            return res;
        }

        Cmd         into_cmd(const Config &cfg);
        Status      run(const Config &cfg);

        Status      install(Str install_dir);

        inline bool need_rebuild() const {
            if (!file_exists(file.out)) return true;
            return any_of(sources.begin(), sources.end(),
                          [](const Source &s) { return s.need_rebuild(); });
        }

        size_t hash();

       private:
        size_t __hash;
    };
    typedef Target &TargetRef;

    struct target_hash {
        size_t operator()(const Target &tg) const noexcept;
    };

    /// cb_t /////////////////////////////////////////////
    struct Cb {
        Config                   cfg;
        Vec<Target>              targets;
        Map<Str, callbacks_cb_t> callbacks;

        Cb(const char *name);

        Status  run(int argc, char **argv);

        Target &create_target(Str name, TargetType type, const Str &source = "");
        Target &create_target_pkgconf(Str name);

        /// helper of function [cb_t::create_target] for each TargetType
        inline Target &create_exec(Str name, const Str &source = "") {
            return create_target(name, TargetType::EXEC, source);
        }
        inline Target &create_static_lib(Str name) {
            return create_target(name, TargetType::STATIC_LIB);
        }
        inline Target &create_dynamic_lib(Str name) {
            return create_target(name, TargetType::DYNAMIC_LIB);
        }

        inline void set_log_level(LogLevel lvl) const { g_log_level = lvl; }
        inline void dump_compile_commands(bool dump) { this->cfg.dump_compile_command = dump; }

        /// add callbacks for operation
        /// operation = [ "build", "config", "install", "clean" ]
        ///
        /// (is optional, if the callback for operation above is not set, it
        /// will defaulted to the static function in cb_t class to call)
        void add_callback(const Str on, callbacks_cb_t cb) {
            CB_INFO("adding callback for event '{}'", on);
            auto f = callbacks.find(on);
            if (f != callbacks.end()) {
                f->second = cb;
            } else {
                callbacks.insert({on, cb});
            }
        }

        Status save_targets();
        Status load_targets();

        void   targets_display();

        bool   is_builded() const;
        bool   is_configured() const;
        bool   is_targets_changed() const;

        size_t source_hash() const;

       private:
        Status        m_build_target();
        Status        m_config_target();
        Status        m_install_target();
        Status        m_clean_target();

        static Status m_on_build_target(Cb *cb);
        static Status m_on_config_target(Cb *cb);
        static Status m_on_install_target(Cb *cb);
        static Status m_on_clean_target(Cb *cb);

        size_t        __source_hashes;
    };

}  // namespace cb
#endif  // __CB_H__

////////////////////////////////////////////////////////////////////////////////
#ifdef CB_IMPLEMENTATION
namespace cb {
#    ifdef CB_WINDOWS
    struct DIR {
        HANDLE          hFind;
        WIN32_FIND_DATA data;
        struct dirent  *dirent;
    };
#    endif

#    define ARRLEN(ARR) (sizeof((ARR)) / sizeof((ARR)[0]))

    Str           program_name;
    static bool   g_display_config = false;
    LogLevel      g_log_level      = LogLevel::INFO;

    static Status which_exec(const Str &exec, Str &out);
    static Status find_compiler(Str &compiler_path, const Config &cfg);
    static void   compile_commands(Cb *cb);

    //////////////////////////////////////////////////////////
    static inline char *shift_args(int *argc, char ***argv) {
        if (*argc == 0) return nullptr;
        char *result = **argv;
        (*argv) += 1;
        (*argc) -= 1;
        return result;
    }

    template <typename T, typename Hasher = std::hash<T>>
    static inline void hash_combine(size_t &seed, const T &v) {
        seed ^= Hasher{}(v) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
    }
    template <typename... Targs>
    static inline void hash_combine(size_t &seed, const Targs &...vargs) {
        for (auto v : {vargs...}) hash_combine<decltype(v)>(seed, v);
    }

    static Status &operator&=(Status &lhs, const Status rhs) {
        lhs = (Status)(static_cast<uint8_t>(lhs) & static_cast<uint8_t>(rhs));
        return lhs;
    }

    bool case_cmp(char a, char b) { return toupper(a) == toupper(b); }
    bool case_cmp(const Str &a, const Str &b) {
        const auto pred = [](char a, char b) { return case_cmp(a, b); };
        return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin(), pred);
    }

    static void format_helper(std::ostream &oss, Str &str) { oss << str; }
    template <typename T, typename... Targs>
    void format_helper(std::ostream &oss, Str &str, const T &value, const Targs &...rest) {
        size_t open = str.find('{');
        if (open == Str::npos) return;
        size_t close = str.find('}', open + 1);
        if (close == Str::npos) return;

        oss << str.substr(0, open);
        oss << value;
        str = str.substr(close + 1);

        format_helper(oss, str, rest...);
    }

    template <>
    CB_FNDEF Str format(Str fmt) {
        return fmt;
    }
    template <typename... Targs>
    CB_FNDEF Str format(Str fmt, const Targs &...args) {
        std::ostringstream oss;
        format_helper(oss, fmt, args...);
        return oss.str();
    }
    template <typename... Targs>
    CB_FNDEF std::ostream &sprint(std::ostream &oss, Str fmt, const Targs &...args) {
        format_helper(oss, fmt, args...);
        return oss;
    }

    template <>
    CB_FNDEF void log(const char *level, const char *tag, Str fmt) {
        Str tags(tag);
        tags.resize(20, ' ');
        sprint(std::cerr, "{}: {} - {}", level, tags, fmt);
        std::cerr << std::endl;
    }
    template <typename... Targs>
    CB_FNDEF void log(const char *level, const char *tag, Str fmt, const Targs &...args) {
        Str tags(tag);
        tags.resize(20, ' ');
        sprint(std::cerr, "{}: {} - {}", level, tags, format(fmt, args...));
        std::cerr << std::endl;
    }

    Str &ltrim(Str &s) {
        s.erase(s.begin(), find_if_not(s.begin(), s.end(), ::isspace));
        return s;
    }
    Str &rtrim(Str &s) {
        s.erase(find_if_not(s.rbegin(), s.rend(), ::isspace).base(), s.end());
        return s;
    }
    Str     &trim(Str &s) { return ltrim(rtrim(s)); }
    Str      trim_copy(Str s) { return trim(s); }

    Vec<Str> split(const Str s, Str delim) {
        size_t   pos_start = 0, pos_end, delim_len = delim.length();
        Str      token;
        Vec<Str> res;

        while ((pos_end = s.find(delim, pos_start)) != Str::npos) {
            token     = s.substr(pos_start, pos_end - pos_start);
            pos_start = pos_end + delim_len;
            res.push_back(token);
        }
        res.push_back(s.substr(pos_start));
        return res;
    }

    bool file_rename(const Str &old_path, const Str &new_path) {
        CB_INFO("Renaming {} -> {}", old_path, new_path);
#    ifdef CB_WINDOWS
        bool failed = !MoveFileEx(old_path.c_str(), new_path.c_str(), MOVEFILE_REPLACE_EXISTING);
#    else
        bool failed = rename(old_path.c_str(), new_path.c_str()) < 0;
#    endif  // CB_WINDOWS
        if (failed)
            CB_BAIL_ERROR(false, "failed rename {} to {}: {}", old_path, new_path, strerror(errno));
        return true;
    }

    bool file_exists(const Str &file_path) {
#    if CB_WINDOWS
        DWORD dwAttrib = GetFileAttributesA(file_path.c_str());
        return dwAttrib != INVALID_FILE_ATTRIBUTES;
#    else
        struct stat sb;
        return stat(file_path.c_str(), &sb) == 0;
#    endif
    }

    bool file_copy(const Str &dst_path, const Str &src_path, bool override) {
        CB_INFO("copying file from: {} => {}", src_path, dst_path);
        bool result = true;
#    ifdef CB_WINDOWS
        if (!CopyFileA(src_path, dst_path, (overide) ? TRUE : FALSE))
            CB_BAIL_ERROR(false, "Could not copy file: {}", GetLastError());
#    else
        struct stat src_stat;

        int         src_fd = open(src_path.c_str(), O_RDONLY);
        if (src_fd < 0)
            CB_BAIL_ERROR(false, "could not open file {}: {}", src_path, strerror(errno));
        defer { close(src_fd); };

        if (fstat(src_fd, &src_stat) < 0)
            CB_BAIL_ERROR(false, "could not stat file {}: {}", src_path, strerror(errno));

        size_t buf_size = 32 << 10;  // 32kb
        if (buf_size > (size_t)src_stat.st_size) buf_size = src_stat.st_size;
        std::unique_ptr<char[]> buf(new char[buf_size]);

        int                     dst_fd_flag = O_CREAT | O_WRONLY;
        if (override) dst_fd_flag |= O_TRUNC;
        int dst_fd = open(dst_path.c_str(), dst_fd_flag, src_stat.st_mode);
        if (dst_fd < 0)
            CB_BAIL_ERROR(false, "Could not create file {}: {}", dst_path, strerror(errno));
        defer { close(dst_fd); };

        for (;;) {
            ssize_t n = read(src_fd, buf.get(), buf_size);
            if (n == 0) break;
            if (n < 0)
                CB_BAIL_ERROR(false, "Could not read from file {}: {}", src_path, strerror(errno));

            char *buf2 = buf.get();
            while (n > 0) {
                ssize_t m = write(dst_fd, buf2, n);
                if (m < 0)
                    CB_BAIL_ERROR(false, "Could not write to file {}: {}", dst_path,
                                  strerror(errno));
                n -= m;
                buf2 += m;
            }
        }
#    endif
        return result;
    }

    bool rebuild_self(int argc, char *argv[], const char *source_path) {
        CB_ASSERT(argc >= 1, "argc should be more than 1");
        const char *binary_path   = argv[0];
        NrStatus    return_status = needs_rebuild<2>(binary_path, {source_path, __FILE__});

        if (return_status == NrStatus::ERR) return false;
        if (return_status == NrStatus::YES) {
            auto binary_path_renamed = Str(binary_path) + ".old";
            if (!file_rename(binary_path, binary_path_renamed)) return false;
            Cmd  rebuild({CB_REBUILD_ARGS(binary_path, source_path)});
            bool rebuild_succeeded = cmd_run(rebuild);

            if (!rebuild_succeeded) {
                file_rename(binary_path_renamed, binary_path);
                return false;
            }

            Cmd cmd(&argv[0], argv + argc);
            if (!cmd_run(cmd)) return false;
            exit(0);
        }
        return true;
    }

    static bool mkdir_if_not_exists_impl(const char *path) {
#    ifdef CB_WINDOWS
        if (CreateDirectoryA(path, NULL) == 0) {
            // if dir already exist, return true
            DWORD err = GetLastError();
            if (err == ERROR_ALREADY_EXISTS) return true;
            CB_BAIL_ERROR(false, "Failed to create directory: {} - (error code: {})", path, err);
        }
#    else
        if (mkdir(path, 0755) < 0) {
            if (EEXIST == errno || errno == ENOENT) return true;
            CB_BAIL_ERROR(false, "Failed to create directory: {} - {}", path, strerror(errno));
        }
#    endif
        CB_INFO("Created directory `{}`", path);
        return true;
    }
    /// impl os operation /////////////////////////////////////////////
    bool mkdir_if_not_exists(const Str &path, bool recursive) {
        if (recursive) {
            Str::size_type pos = 0;
            do {
                pos = path.find_first_of("\\/", pos + 1);
                if (!mkdir_if_not_exists_impl(path.substr(0, pos).c_str())) return false;
            } while (pos != Str::npos);
            return true;
        }
        return mkdir_if_not_exists_impl(path.c_str());
    }

    bool remove_file(const Str &filepath) {
#    ifdef CB_WINDOWS
        if (DeleteFileA(filepath.c_str()) == 0)
            CB_BAIL_ERROR(false, "Can`t remove a file: {} - {}\n", filepath, GetLastError());
#    else
        if (unlink(filepath.c_str()) == -1)
            CB_BAIL_ERROR(false, "Can`t remove a file: {} - {}\n", filepath, strerror(errno));
#    endif
        CB_INFO("Removed a file: {}", filepath);
        return true;
    }
    bool remove_dir(const Str &dirpath) {
#    ifdef CB_WINDOWS
        if (RemoveDirectoryA(dirpath.c_str()) == 0)
            CB_BAIL_ERROR(false, "Can`t remove a directory: {} - {}\n", dirpath, GetLastError());
#    else
        if (rmdir(dirpath.c_str()) == -1)
            CB_BAIL_ERROR(false, "Can`t remove a directory: {} - {}\n", dirpath, strerror(errno));
#    endif
        CB_INFO("Removed a directory: {}", dirpath);
        return true;
    }
    bool remove_dir_rec(const Str &dirpath) {
        bool     result = true;
        FileType d_type;
        Str      path;
        DIR     *dir = NULL;
        if ((dir = opendir(dirpath.c_str())) == NULL)
            CB_BAIL_ERROR(false, "Could not open directory {}: {}", dirpath, strerror(errno));

        struct dirent *ent = NULL;
        while (((ent = readdir(dir)) != NULL) && result) {
            if (ent->d_name[0] == '.') continue;

            path   = format("{}" CB_DIR_SEPARATOR "{}", dirpath, ent->d_name);
            d_type = file_type(path);
            if (d_type == FileType::Error) continue;
            result = (d_type == FileType::Directory) ? remove_dir_rec(path) : remove_file(path);
        }
        if (dir) closedir(dir);
        return remove_dir(dirpath.c_str());
    }

    FileType file_type(const Str &path) {
#    ifdef CB_WINDOWS
        DWORD attr = GetFileAttributesA(path);
        if (attr == INVALID_FILE_ATTRIBUTES)
            CB_BAIL_ERROR(FileType::Error, "Could not get file attributes of {}: {}", path,
                          GetLastError());
        if (attr & FILE_ATTRIBUTE_DIRECTORY) return FileType::Directory;
        return FileType::Regular;
#    else  // CB_WINDOWS
        struct stat statbuf;
        if (stat(path.c_str(), &statbuf) < 0)
            CB_BAIL_ERROR(FileType::Error, "Could not get stat of {}: {}", path, strerror(errno));
        switch (statbuf.st_mode & S_IFMT) {
            case S_IFDIR: return FileType::Directory;
            case S_IFREG: return FileType::Regular;
            case S_IFLNK: return FileType::SymLink;
            default: return FileType::Other;
        }
#    endif
    }

    bool current_path(Str &out_path, const char *optional_append_path) {
        char *tmp = new char[MAX_PATH];
        memset(tmp, 0, MAX_PATH);

        if (getcwd(tmp, MAX_PATH) == NULL)
            CB_BAIL_ERROR(false, "current_path: failed - {}", strerror(errno));
        out_path = tmp;

        if (optional_append_path) path_append(out_path, optional_append_path);
        return true;
    }

    bool home_dir(Str &out_path, const char *optional_append_path) {
        char *home = nullptr;
#    ifdef CB_WINDOWS
        if ((home = getenv("USERPROFILE")) == nullptr) {
            char *drive = getenv("HOMEDRIVE");
            char *path  = getenv("HOMEPATH");
            if ((drive == nullptr) || (path == nullptr))
                CB_BAIL_ERROR(false, "Failed to get Home directory!");
            out_path = drive;
            path_append(out_path, path);
        }
#    else
        if ((home = getenv("HOME")) == nullptr) {
            home = getpwuid(getuid())->pw_dir;
            if (home == nullptr) CB_BAIL_ERROR(false, "Failed to get Home directory!");
        }
        out_path = home;
#    endif
        if (optional_append_path) path_append(out_path, optional_append_path);
        return true;
    }

    bool set_permissions(const Str &file, mode_t permissions) {
#    ifdef CB_LINUX
        if (chmod(file.c_str(), permissions) < 0)
            CB_BAIL_ERROR(false, "failed on path: {} - {}", file, strerror(errno));
#    else
        (void)file, (void)permissions;
#    endif
        return true;
    }

    bool path_to_absolute(Str &path) {
        char *tmp = new char[MAX_PATH];
        defer { delete[] tmp; };
        if (realpath(path.c_str(), tmp) == NULL)
            CB_BAIL_ERROR(false, "path_to_absolute: Failed from path '{}'", path);
        path = tmp;
        return true;
    }

    Str path_filename(const Str &path) {
        Str out_path = path;
        while (!out_path.empty()) {
            Str::size_type len  = out_path.length();
            char           back = out_path.back();
            if (back == CB_DIR_SEPARATOR_CHAR) {
                out_path.resize(len - (sizeof(CB_DIR_SEPARATOR) - 1));
                continue;
            } else if (back == '.') {
                out_path.resize(len - 1);
                continue;
            } else {
                Str::size_type pos = out_path.find_last_of("\\/");
                if (pos != Str::npos) return out_path.substr(pos + 1, out_path.size() - pos - 1);
                break;
            }
        }
        return out_path;
    }

    Str path_extension(const Str &path) {
        size_t dot = path.find_last_of(".");
        return (dot != Str::npos) ? path.substr(dot + 1, path.size() - dot) : "";
    }
    void path_set_extension(Str &path, const char *ext) {
        size_t dot = path.find_last_of(".");
        if (dot != Str::npos) path.resize(dot);
        if (ext) {
            if (ext[0] != '.') path.push_back('.');
            path.append(ext);
        }
    }

    void path_append(Str &path, const Str &to_append) {
        if (path.back() != CB_DIR_SEPARATOR_CHAR) {
            path.append(CB_DIR_SEPARATOR);
        }
        if (to_append.front() == CB_DIR_SEPARATOR_CHAR) {
            path.append(to_append.substr(sizeof(CB_DIR_SEPARATOR) - 1));
        } else {
            path.append(to_append);
        }
    }

    bool walkdir(const Str &parent, bool recursive, WalkdirCallback callback) {
        bool     result = true;
        FileType ft     = FileType::Error;

        DIR     *dir    = NULL;
        if ((dir = opendir(parent.c_str())) == NULL)
            CB_BAIL_ERROR(false, "Could not open directory {}: {}", parent, strerror(errno));
        defer { closedir(dir); };

        Str            path;
        struct dirent *ent = nullptr;
        while ((ent = readdir(dir)) != nullptr) {
            if (ent->d_name[0] == '.') continue;

            path = parent;
            path_append(path, ent->d_name);
            ft = file_type(path);
            if (ft == FileType::Directory) {
                if (recursive) result &= walkdir(path, recursive, callback);
            } else {
                if (!callback(path, ft)) {
                    result = false;
                    break;
                }
            }
        }
        return result;
    }

    /// impl proc_t | cb_procs_t /////////////////////////////////////////////
    bool procs_wait(const Procs &procs) {
        return std::all_of(procs.begin(), procs.end(), proc_wait);
    }
    bool proc_wait(proc_t proc) {
        if (proc == CB_INVALID_PROC) return false;
#    ifdef CB_WINDOWS
        defer { CloseHandle(proc); };
        DWORD result = WaitForSingleObject(proc, INFINITE);
        if (result == WAIT_FAILED)
            CB_BAIL_ERROR(false, "could not wait on child process: {}", GetLastError());
        DWORD exit_status;
        if (!GetExitCodeProcess(proc, &exit_status))
            CB_BAIL_ERROR(false, "could not get process exit code: {}", GetLastError());
        if (exit_status != 0) CB_BAIL_ERROR(false, "command exited with exit code {}", exit_status);
#    else
        for (;;) {
            int wstatus = 0;
            if (waitpid(proc, &wstatus, 0) < 0)
                CB_BAIL_ERROR(false, "could not wait on command (pid {}): {}", proc,
                              strerror(errno));
            if (WIFEXITED(wstatus)) {
                int exit_status = WEXITSTATUS(wstatus);
                if (exit_status != 0)
                    CB_BAIL_ERROR(false, "command exited with exit code {}", exit_status);
                break;
            }
            if (WIFSIGNALED(wstatus))
                CB_BAIL_ERROR(false, "command process was terminated by {}",
                              strsignal(WTERMSIG(wstatus)));
        }
        return true;
#    endif
    }
    /// impl cb_cmd_t /////////////////////////////////////////////
    proc_t cmd_run_async(Cmd &cmd) {
        if (cmd.size() < 1) CB_BAIL_ERROR(CB_INVALID_PROC, "Could not run empty command");

        {
            Str dpy;
            for (size_t i = 0; i < cmd.size(); ++i) {
                const char *arg = cmd[i];
                if (arg == nullptr) break;
                if (i > 0) dpy += " ";
                if (!strchr(arg, ' ')) {
                    dpy += arg;
                } else {
                    dpy += '\'';
                    dpy += arg;
                    dpy += '\'';
                }
            }
            CB_INFO("{}", dpy);
        }

#    ifdef CB_WINDOWS
        // https://docs.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output

        STARTUPINFO siStartInfo;
        ZeroMemory(&siStartInfo, sizeof(siStartInfo));
        siStartInfo.cb         = sizeof(STARTUPINFO);
        // NOTE: theoretically setting nullptr to std handles should not be a
        // problem
        // https://docs.microsoft.com/en-us/windows/console/getstdhandle?redirectedfrom=MSDN#attachdetach-behavior
        // TODO: check for errors in GetStdHandle
        siStartInfo.hStdError  = GetStdHandle(STD_ERROR_HANDLE);
        siStartInfo.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
        siStartInfo.hStdInput  = GetStdHandle(STD_INPUT_HANDLE);
        siStartInfo.dwFlags |= STARTF_USESTDHANDLES;

        PROCESS_INFORMATION piProcInfo;
        ZeroMemory(&piProcInfo, sizeof(PROCESS_INFORMATION));
        defer { CloseHandle(piProcInfo.hThread); };

        Str sb;
        std::for_each(cmd.begin(), cmd.end(), [&](const char *&piece) {
            sb += piece;
            sb += " ";
        });
        BOOL bSuccess = CreateProcessA(nullptr, sb.c_str(), nullptr, nullptr, TRUE, 0, nullptr,
                                       nullptr, &siStartInfo, &piProcInfo);

        if (!bSuccess)
            CB_BAIL_ERROR(CB_INVALID_PROC, "Could not create child process: %lu", GetLastError());
        return piProcInfo.hProcess;
#    else
        pid_t cpid = fork();
        if (cpid < 0)
            CB_BAIL_ERROR(CB_INVALID_PROC, "Could not fork child process: %s", strerror(errno));
        if (cpid == 0) {
            cmd.push_back(nullptr);
            if (execvp(cmd[0], (char *const *)cmd.data()) < 0) {
                CB_ERROR("Could not exec child process: %s", strerror(errno));
                exit(1);
            }
            exit(0);
        }
        return cpid;
#    endif
    }

    bool cmd_run(Cmd &cmd) {
        proc_t p = cmd_run_async(cmd);
        if (p == CB_INVALID_PROC) return false;
        return proc_wait(p);
    }

    Status popen_stdout(Cmd &cmd, Str &stdout_content) {
        char buffer[1 << 10] = {0};
#    ifdef CB_WINDOWS
        HANDLE              stdout_read_;
        HANDLE              stdout_write_;
        STARTUPINFO         si;
        PROCESS_INFORMATION pi_info;
        defer {
            CloseHandle(stdout_read_);
            CloseHandle(stdout_write_);
            CloseHandle(pi_info.hProcess);
            CloseHandle(pi_info.hThread);
        };

        // Create pipes for stdout
        SECURITY_ATTRIBUTES sa = {sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
        if (!CreatePipe(&stdout_read_, &stdout_write_, &sa, 0))
            CB_BAIL_ERROR(status::ERR, "Error creating pipes on Windows");

        ZeroMemory(&si, sizeof(STARTUPINFO));
        si.cb         = sizeof(STARTUPINFO);
        si.hStdError  = GetStdHandle(STD_ERROR_HANDLE);
        si.hStdOutput = stdout_write_;
        si.hStdInput  = GetStdHandle(STD_INPUT_HANDLE);
        si.dwFlags |= STARTF_USESTDHANDLES;

        ZeroMemory(&pi_info, sizeof(PROCESS_INFORMATION));

        Str sb;
        std::for_each(cmd.begin(), cmd.end(), [&](const char *&piece) {
            sb += piece;
            sb += " ";
        });
        if (!CreateProcessA(nullptr, sb.c_str(), nullptr, nullptr, TRUE, 0, nullptr, nullptr, &si,
                            &pi_info))
            CB_BAIL_ERROR(status::ERR, "Could not create child process: {}", GetLastError());

        DWORD bytesRead = 0;
        while (ReadFile(stdout_read_, buffer, 1 << 10, &bytesRead, nullptr) && bytesRead > 0)
            stdout_content.append(buffer, bytesRead);
#    else
        cmd.push_back(NULL);
        int   stdout_pipe[2];
        pid_t pid_proc;
        if (pipe(stdout_pipe) == -1) CB_BAIL_ERROR(Status::ERR, "Error creating pipes on Linux")
        if ((pid_proc = fork()) < 0) CB_BAIL_ERROR(Status::ERR, "Error forking process on Linux");

        if (pid_proc == 0) {
            dup2(stdout_pipe[1], STDOUT_FILENO);
            // Close unused pipe ends
            close(stdout_pipe[0]);
            close(stdout_pipe[1]);

            if (execvp(cmd[0], (char *const *)cmd.data()) < 0) {
                CB_ERROR("Could not exec child process: {}", strerror(errno));
                exit(EXIT_FAILURE);
            }
            exit(EXIT_SUCCESS);
        } else {  // Parent process
            close(stdout_pipe[1]);
        }
        defer {
            close(stdout_pipe[0]);
            if (pid_proc > 0) waitpid(pid_proc, nullptr, 0);
        };
        ssize_t bytes_read = 0;
        while ((bytes_read = read(stdout_pipe[0], buffer, 1 << 10)) > 0)
            stdout_content.append(buffer, bytes_read);

#    endif  // CB_WINDOWS
        return Status::OK;
    }

    static inline void print_help(const Map<Str, callbacks_cb_t> &callbacks) {
        fprintf(stderr, "USAGE: %s <SUBCOMMAND> [OPTIONS]" CB_LINE_END, program_name.c_str());
        for (const auto &cb : callbacks)
            fprintf(stderr, "   %s %s" CB_LINE_END, program_name.c_str(), cb.first.c_str());
        fprintf(stderr, CB_LINE_END "OPTIONS: " CB_LINE_END);
        fprintf(stderr,
                "   -ct, --compiler_type    set Compiler type   [clang, gnu, "
                "msvc] (defualt same as `cb.h` compiles "
                "to)" CB_LINE_END);
        fprintf(stderr,
                "   -c, --compiler          set Compiler        "
                "[path_to_compiler] (default will search Compiler "
                "type)" CB_LINE_END);
        fprintf(stderr,
                "   -b,  --build            set build type      [debug, "
                "release, relwithdebinfo]  (default to "
                "'debug')" CB_LINE_END);
        fprintf(stderr,
                "   -p,  --program          set program type    [C, CPP] "
                "(default to 'C')" CB_LINE_END);
        fprintf(stderr,
                "   -t,  --target           set target OS type  [windows, "
                "macos, unix] (default to current run "
                "OS)" CB_LINE_END);
        fprintf(stderr,
                "   -a,  --arch             set architecture    [X64, X86, "
                "ARM64, ARM32] (default to current run "
                "arch)" CB_LINE_END);
        fprintf(stderr, "   -h,  --help             print this help text" CB_LINE_END);
        fprintf(stderr, "   -q,  --quite            set output to quite" CB_LINE_END);
        fprintf(stderr,
                "   -d,  --display          display config  and target, will "
                "not start process" CB_LINE_END);
        fprintf(stderr, "        --release          set build type to release" CB_LINE_END);
        fprintf(stderr, "        --debug            set build type to debug" CB_LINE_END);
    }
    // clang-format on
    bool SerializeDeserialize::deserialize(std::istream &instream) {
        Str linebuf;
        while (getline(instream, linebuf)) {
            if (trim(linebuf).empty()) continue;
            if (linebuf.front() == '#') continue;
            Str::size_type eq_delim;
            if ((eq_delim = linebuf.find_first_of('=')) != Str::npos) {
                auto key   = linebuf.substr(0, eq_delim);
                auto value = linebuf.substr(eq_delim + 1);
                if (!deserialize_key_value(trim(key), trim(value))) {
                    CB_ERROR("Failed to deserialize key: `{}`, value: `{}`", key, value);
                    return false;
                }
            }
        }
        return true;
    }

#    define opt(l)     (arg == l)
#    define opts(s, l) ((arg == s) || (arg == l))

    Config Config::create(const Str &name) {
        Config cfg;
        cfg.project_name = name;
        if (!current_path(cfg.project_path)) {
            cfg.project_path = "./";
        };
        cfg.build_path = cfg.project_path;
        path_append(cfg.build_path, "build");

        cfg.build_artifact_path = cfg.build_path;
        path_append(cfg.build_artifact_path, ((cfg.is_release()) ? "release" : "debug"));

        cfg.config_path = cfg.build_path;
        path_append(cfg.config_path, "config.cb");

        cfg.targets_path = cfg.build_path;
        path_append(cfg.targets_path, "targets.cb");

        cfg.set_install_prefix(cfg.is_windows() ? "c:\\Program Files\\${PROJECT_NAME}" : "/usr");
        return cfg;
    }

    void Config::set_install_prefix(const Str &prefix) {
        install_prefix  = prefix;
        bin_install_dir = install_prefix;
        path_append(bin_install_dir, "bin");
        lib_install_dir = install_prefix;
        path_append(lib_install_dir, "lib");
    }
    void Config::set_build_path(const Str &path) {
        this->build_path          = path;
        this->build_artifact_path = build_path;
        path_append(this->build_artifact_path, ((is_release()) ? "release" : "debug"));
    }
    void Config::set_compiler(const Str &cpath, Compiler ctype) {
        this->compiler_type = ctype;
        this->compiler_path = cpath;
    }

    bool Config::parse_from_args(const Vec<Str> args, const Map<Str, callbacks_cb_t> &callbacks) {
        program_name = args.front();

        __hash       = hash();
        if (file_exists(config_path)) {
            if (load(config_path) == Status::ERR) return false;
            CB_INFO("Success load config from '{}'", config_path);
        }

        Compiler last_ct = compiler_type;
        for (auto it = args.begin() + 1; it != args.end(); it++) {
            auto arg = *it;
            if (arg[0] != '-') {
                subcmd = arg;
                continue;
            }
            // clang-format off
            if      opt ("--release"        ) build_type       = Build::RELEASE;
            else if opt ("--debug"          ) build_type       = Build::DEBUG;
            else if opts ("-d", "--display" ) g_display_config = true;
            else if opts ("-q", "--quite"   ) g_log_level      = LogLevel::ERROR;
            else if opts ("-h", "--help"    ) {
                print_help(callbacks);
                return true;
            }
            else if opts ("-db", "--compile-commands"   ) dump_compile_command = true;
            else if ((it+1) != args.end()) {
                auto arg_next = *(++it);
                if      opts ("-c", "--compiler"            ) compiler_path = arg_next;
                else if opts ("-ct", "--compiler_type"      ) compiler_type = COMPILER_DISPLAY.parse(arg_next);
                else if opts ("-", "--build"                ) build_type    = BUILD_TYPE_DISPLAY.parse(arg_next);
                else if opts ("-p", "--program"             ) program_type  = PROGRAM_DISPLAY.parse(arg_next);
                else if opts ("-t", "--target"              ) platform_kind = PLATFORM_DISPLAY.parse(arg_next);
                else if opts ("-a", "--arch"                ) arch_kind     = ARCH_DISPLAY.parse(arg_next);
                else {
                    CB_ERROR("unknown arguments: '{}' <{}>", arg, arg_next);
                    print_help(callbacks);
                    return false;
                }
            } else {
                CB_ERROR("unknown arguments: '{}'", arg); 
                print_help(callbacks);
                return false;
            }
            // clang-format on
        }

        mkdir_if_not_exists(build_path);
        mkdir_if_not_exists(build_artifact_path);
        if (compiler_path.empty() || last_ct != compiler_type) find_compiler(compiler_path, *this);
        if (is_changed()) {
            CB_INFO("Configuration changed, saving config to '{}'", config_path);
            return save(config_path) == Status::OK;
        }
        return true;
    }

    bool Config::serialize(std::ostream &out) {
        out << "build_type          = " << BUILD_TYPE_DISPLAY[build_type] << std::endl;
        out << "platform            = " << PLATFORM_DISPLAY[platform_kind] << std::endl;
        out << "arch                = " << ARCH_DISPLAY[arch_kind] << std::endl;
        out << "compiler_type       = " << COMPILER_DISPLAY[compiler_type] << std::endl;
        out << "program_type        = " << PROGRAM_DISPLAY[program_type] << std::endl;
        out << "dump_compile_command= " << (dump_compile_command ? "true" : "false") << std::endl;
        out << "project_name        = " << project_name << std::endl;
        out << "project_path        = " << project_path << std::endl;
        out << "build_path          = " << build_path << std::endl;
        out << "build_artifact_path = " << build_artifact_path << std::endl;
        out << "compiler_path       = " << compiler_path << std::endl;
        out << "config_path         = " << config_path << std::endl;
        out << "targets_path        = " << targets_path << std::endl;
        out << "install_prefix      = " << install_prefix << std::endl;
        out << "bin_install_dir     = " << bin_install_dir << std::endl;
        out << "lib_install_dir     = " << lib_install_dir << std::endl;
        return out.good();
    }
    // clang-format off
    bool Config::deserialize_key_value(Str &key, Str &v) {
        if      (key == "build_type")           build_type      = BUILD_TYPE_DISPLAY.parse(v);
        else if (key == "platform")             platform_kind   = PLATFORM_DISPLAY.parse(v);
        else if (key == "arch")                 arch_kind       = ARCH_DISPLAY.parse(v);
        else if (key == "compiler_type")        compiler_type   = COMPILER_DISPLAY.parse(v);
        else if (key == "program_type")         program_type    = PROGRAM_DISPLAY.parse(v);
        else if (key == "dump_compile_command") dump_compile_command = v == "true";
        else if (key == "project_name")         project_name    = v;
        else if (key == "project_path")         project_path    = v;
        else if (key == "build_path")           build_path      = v;
        else if (key == "build_artifact_path")  build_artifact_path = v;
        else if (key == "compiler_path")        compiler_path   = v;
        else if (key == "config_path")          config_path     = v;
        else if (key == "targets_path")         targets_path    = v;
        else if (key == "install_prefix")       install_prefix  = v;
        else if (key == "bin_install_dir")      bin_install_dir = v;
        else if (key == "lib_install_dir")      lib_install_dir = v;
        else {
            CB_WARNING("Unknown key '{}' on configuration file", key);
            return false;
        }
        return true;
    }
    // clang-format on

    Status Config::save(const Str &path) {
        try {
            std::ofstream out(path);
            if (!out) {
                CB_ERROR("Failed to open config file '{}'", path);
                return Status::ERR;
            }
            if (!this->serialize(out)) {
                CB_ERROR("Failed to write config file '{}'", path);
                return Status::ERR;
            }
            __hash = hash();
        } catch (const std::exception &e) {
            CB_ERROR("Failed to open file config '{}' - {}", path, e.what());
            return Status::ERR;
        }
        return Status::OK;
    }
    Status Config::load(const Str &path) {
        if (!file_exists(path)) CB_BAIL_ERROR(Status::ERR, "File config '{}' is not exists", path);
        try {
            std::ifstream in(path);
            if (!in) {
                CB_ERROR("Failed to open config file '{}'", path);
                return Status::ERR;
            }
            if (!this->deserialize(in)) {
                CB_ERROR("Failed to deserialize file '{}'", path);
                return Status::ERR;
            }
            __hash = hash();
        } catch (const std::exception &e) {
            CB_ERROR("Failed to open file config '{}' - {}", path, e.what());
            return Status::ERR;
        }
        return Status::OK;
    }

    size_t Config::hash() const {
        size_t seed = 0;
        hash_combine<uint8_t>(seed, (uint8_t)build_type, (uint8_t)platform_kind, (uint8_t)arch_kind,
                              (uint8_t)compiler_type, (uint8_t)program_type,
                              (uint8_t)dump_compile_command);
        hash_combine(seed, project_name, project_path, build_path, build_artifact_path,
                     compiler_path, config_path, targets_path, install_prefix, bin_install_dir,
                     lib_install_dir);
        return seed;
    }
    bool Config::is_changed() const { return hash() != __hash; }

    Source::Source(const Str &dir, const Str &s) : src(s), out(dir) {
        path_to_absolute(src);
        path_append(out, path_filename(src));
        path_set_extension(out, "o");
    }

    Target::Target(Str name, TargetType ty, const Config &cfg)
        : SerializeDeserialize(), type(ty), name(name), flags(), ldflags(), sources() {
        output_dir = cfg.build_artifact_path;
        path_append(output_dir, name);
        file.out        = output_dir;

        const char *ext = cfg.get_ext(type);
        if (TargetType::STATIC_LIB == type || type == TargetType::DYNAMIC_LIB) {
            path_append(file.out, Str("lib") + name.data());
            path_set_extension(file.out, ext);
        } else if (type == TargetType::EXEC) {
            path_append(file.out, name);
        }
    }

    Status Target::add_sources_with_ext(const Str &dir, const char *ext, bool recursive) {
        auto ret =
            walkdir(dir, recursive, [this, ext](const Str &p, __attribute__((unused)) FileType ft) {
                if (case_cmp(path_extension(p), ext)) this->add_sources(p);
                return true;
            });
        return ret ? Status::OK : Status::ERR;
    }

    inline void serialize_vec_source(std::ostream &out, const char *name, const Vec<Source> &vecs) {
        out << name;
        for (size_t i = 0; i < vecs.size(); i++) {
            const auto &s = vecs[i];
            out << '{' << (s.src.empty() ? "" : s.src) << ',';
            out << (s.out.empty() ? "" : s.out) << '}';
            if (i < vecs.size() - 1) {
                out << ',';
            }
        }
        out << std::endl;
    }
    inline void serialize_vec_str(std::ostream &out, const char *name, const Vec<Str> &vecs) {
        out << name;
        for (size_t i = 0; i < vecs.size(); i++) {
            out << (vecs[i].empty() ? "" : vecs[i]);
            if (i < vecs.size() - 1) {
                out << ',';
            }
        }
        out << std::endl;
    }
    inline void deserialize_vec_source(const Str &v, Vec<Source> &out) {
        size_t open  = v.find('{');
        size_t close = 0;
        while (open != Str::npos && close != Str::npos) {
            close                 = v.find('}', open + 1);
            auto           inside = v.substr(open + 1, close - open - 1);
            Str::size_type comma  = Str::npos;
            if ((comma = trim(inside).find_first_of(',')) != Str::npos) {
                Source src;
                src.src = trim_copy(inside.substr(0, comma));
                src.out = trim_copy(inside.substr(comma + 1));
                out.push_back(src);
            }
            open = v.find('{', close);
        }
    }
    inline void deserialize_vec_str(const Str &v, Vec<Str> &out) {
        size_t start = 0;
        size_t end;
        while ((end = v.find(',', start)) != Str::npos) {
            auto s = v.substr(start, end - start);
            out.push_back(trim(s));
            start = end + 1;  // Move to the next character after the comma
        }
        // Add the last substring (or the only substring if there are no commas)
        out.push_back(v.substr(start));
    }

    bool Target::serialize(std::ostream &out) {
        auto ty_dpy = TARGET_TYPE_DISPLAY[type];
        out << "target.type=" << ty_dpy << std::endl;
        out << "target.name=" << (name.empty() ? "" : name) << std::endl;
        out << "target.output_dir=" << (output_dir.empty() ? "" : output_dir) << std::endl;
        out << "target.output=" << (file.out.empty() ? "" : file.out) << std::endl;
        out << "target.source=" << (file.src.empty() ? "" : file.src) << std::endl;
        serialize_vec_str(out, "target.flags=", this->flags);
        serialize_vec_str(out, "target.ldflags=", this->ldflags);
        serialize_vec_source(out, "target.sources=", this->sources);

        return out.good();
    }
    bool Target::deserialize_key_value(Str &key, Str &value) {
        if (key == "target.type") this->type = TARGET_TYPE_DISPLAY.parse(value);
        if (key == "target.name") this->name = value;
        if (key == "target.output_dir") this->output_dir = value;
        if (key == "target.output") this->file.out = value;
        if (key == "target.source") this->file.src = value;
        if (key == "target.flags") deserialize_vec_str(value, this->flags);
        if (key == "target.ldflags") deserialize_vec_str(value, this->ldflags);
        if (key == "target.sources") deserialize_vec_source(value, this->sources);
        return true;
    }

    Status Target::link_library(const Target &tgt) {
        CB_INFO("name: {}, type: {}", tgt.name, TARGET_TYPE_DISPLAY[tgt.type]);
        switch (tgt.type) {
            case TargetType::SYSTEM_LIB: {
                for (const auto &ld : tgt.ldflags) {
                    if (ld.compare(0, 2, "-I") == 0) {
                        flags.push_back(ld);
                    } else {
                        ldflags.push_back(ld);
                    }
                }
            } break;
            case TargetType::STATIC_LIB: {
                ldflags.push_back("-static");  // fall through
                ldflags.insert(ldflags.end(), tgt.ldflags.begin(), tgt.ldflags.end());
                ldflags.insert(flags.end(), tgt.flags.begin(), tgt.flags.end());
                add_flags(Str(Str("-L") + tgt.name.data()), Str(Str("-l") + tgt.file.out));
            } break;
            case TargetType::DYNAMIC_LIB: {
                ldflags.insert(ldflags.end(), tgt.ldflags.begin(), tgt.ldflags.end());
                ldflags.insert(flags.end(), tgt.flags.begin(), tgt.flags.end());
                add_flags(Str(Str("-L") + tgt.name.data()), Str(Str("-l") + tgt.file.out));
            } break;
            default: CB_ERROR("lib->type not equal to library type: (name: {})", tgt.name); break;
        }
        return Status::OK;
    }

    Cmd Target::into_cmd(const Config &cfg) {
        Cmd c;
        c.push_back(cfg.compiler_path.c_str());
        auto str_inserter = [&](const Str &s) { c.push_back(s.c_str()); };
        std::for_each(flags.begin(), flags.end(), str_inserter);
        if (!file.src.empty()) c.push_back(file.src.c_str());

        c.push_back("-o");
        c.push_back(file.out.c_str());

        std::for_each(sources.begin(), sources.end(),
                      [&](const Source &s) { c.push_back(s.out.c_str()); });
        std::for_each(ldflags.begin(), ldflags.end(), str_inserter);

        return c;
    }

    Status Target::run(const Config &cfg) {
        if (!this->need_rebuild()) return Status::OK;
        CB_INFO("Target Run", "Running target {}", name);
        Status result = Status::OK;

        Cmd    cmd{cfg.compiler_path.c_str()};
        Procs  procs;

        auto   str_inserter = [&](const Str &s) { cmd.push_back(s.c_str()); };
        std::for_each(flags.begin(), flags.end(), str_inserter);
        size_t save_idx = cmd.size();

        for (const auto &s : sources) {
            if (!s.need_rebuild()) continue;
            cmd.insert(cmd.end(), {"-o", s.out.c_str(), "-c", s.src.c_str()});
            proc_t p = cmd_run_async(cmd);
            if (p == CB_INVALID_PROC) {
                CB_ERROR("returned invalid proc");
                result = Status::ERR;
            } else {
                procs.push_back(p);
            }
            cmd.resize(save_idx);
        }
        if (!procs_wait(procs))
            CB_BAIL_ERROR(Status::ERR, "Target Run", "Failed to wait process of procs_t");
        if (result == Status::ERR) return result;

        cmd = this->into_cmd(cfg);
        if (!cmd_run(cmd)) CB_BAIL_ERROR(Status::ERR, "Target Run", "Failed to run sync cmd");
        return result;
    }

    Status Target::install(Str install_path) {
        if (file.out.empty() || !file_exists(file.out)) {
            CB_ERROR("File output is empty or not exists for target '{}'", name);
            CB_ERROR("build it first before installing!");
            return Status::ERR;
        }
        path_append(install_path, this->name);
        if (!cb::file_copy(install_path, file.out)) return Status::ERR;
        if (type == TargetType::EXEC) set_permissions(install_path, 0755);
        return Status::OK;
    }

    size_t target_hash::operator()(const Target &tg) const noexcept {
        size_t seed = 0;
        hash_combine(seed, tg.type);
        hash_combine(seed, tg.name);
        hash_combine(seed, tg.output_dir);
        hash_combine(seed, tg.file.out);
        hash_combine(seed, tg.file.src);
        for (const auto &flag : tg.flags) hash_combine(seed, flag);
        for (const auto &ldflag : tg.ldflags) hash_combine(seed, ldflag);
        for (const auto &src : tg.sources) hash_combine(seed, src.src, src.out);
        return seed;
    }

    Cb::Cb(const char *name)
        : cfg(Config::create(name))
        , targets()
        , callbacks({{"build", m_on_build_target},
                     {"config", m_on_config_target},
                     {"clean", m_on_clean_target},
                     {"install", m_on_install_target}}) {}

    Target &Cb::create_target(Str name, TargetType type, const Str &source) {
        targets.emplace_back(name, type, cfg);
        auto &tgt = targets.back();
        if (!source.empty()) {
            if (tgt.add_main_source(source) == Status::ERR)
                CB_ERROR("Failed to add main source: {}", source);
        }
        return tgt;
    }

    Target &Cb::create_target_pkgconf(Str name) {
#    ifdef CB_WINDOWS
        CB_ERROR("cb_create_target_pkgconf is not supported in windows");
        return nullptr;
#    else
        CB_INFO("find library of name '{}' using pkgconf", name);
        targets.emplace_back(name, TargetType::SYSTEM_LIB, cfg);
        auto &tgt = targets.back();

        Str   contents_buff;
        contents_buff.reserve(2 << 10);
        Cmd cmd{"pkg-config", "--cflags", "--libs", name.c_str()};
        if (popen_stdout(cmd, contents_buff) != Status::OK)
            CB_BAIL_ERROR(tgt, "Failed to procecss open");

        char *data  = &contents_buff[0];
        char *token = nullptr;
        token       = strtok(data, " \n\t");
        while (token != nullptr) {
            if (!(token[0] == '\n' || token[0] == '\t' || token[0] == ' ')) {
                tgt.ldflags.push_back(token);
            }
            token = strtok(nullptr, " ");
        }

        targets.push_back(tgt);
        return tgt;
#    endif
    }

    Status Cb::save_targets() {
        try {
            std::ofstream out(cfg.targets_path);
            if (!out) {
                CB_ERROR("Failed to open targets file '{}'", cfg.targets_path);
                return Status::ERR;
            }
            out << "target_count=" << targets.size() << std::endl;
            for (size_t i = 0; (i < targets.size()) && out.good(); ++i) {
                if (!targets[i].serialize(out)) break;
                if (i != targets.size() - 1) {
                    out << "----";
                }
                out << std::endl;
            }
            if (!out.good()) out.exceptions(out.rdstate());
            __source_hashes = source_hash();
        } catch (const std::ios_base::failure &e) {
            CB_ERROR("Failed to save target '{}' - [({}): {}]", cfg.targets_path, e.code(),
                     e.what());
            return Status::ERR;
        } catch (const std::exception &e) {
            CB_ERROR("Failed to save target '{}' - [{}]", cfg.targets_path, e.what());
            return Status::ERR;
        }
        return Status::OK;
    }
    static Str read_to_string(std::ifstream &ifs, const Str &file) {
        try {
            ifs.seekg(0, std::ios::end);
            std::ifstream::pos_type sz = ifs.tellg();
            ifs.seekg(0, std::ios::beg);
            Str bytes(sz, '\0');
            ifs.read(&bytes[0], sz);

            if (!ifs.good()) ifs.exceptions(ifs.rdstate());
            return bytes;
        } catch (const std::exception &e) {
            CB_ERROR("Failed to load target configuration '{}' - {}", file, e.what());
            return "";
        }
    }

    Status Cb::load_targets() {
        if (!file_exists(cfg.targets_path))
            CB_BAIL_ERROR(Status::ERR, "load_target",
                          "no targets available, use command 'config' as "
                          "subcommand to initiate project configuration");
        try {
            std::ifstream ifs(cfg.targets_path);
            Str           content         = read_to_string(ifs, cfg.targets_path);
            Vec<Str>      targets_content = split(content, "----");

            for (const auto &tg : targets_content) {
                if (tg.empty()) continue;
                Target target;
                for (const auto &line : split(tg, "\n")) {
                    if (line.empty() || line.front() == '#') continue;
                    Str::size_type eq_delim = Str::npos;
                    if ((eq_delim = line.find_first_of('=')) != Str::npos) {
                        Str key{line.substr(0, eq_delim)};
                        Str value{line.substr(eq_delim + 1)};
                        if (key == "target_count") {
                            this->targets.reserve(std::atol(value.c_str()));
                            continue;
                        }
                        target.deserialize_key_value(key, value);
                    }
                }
                this->targets.push_back(target);
            }

            __source_hashes = source_hash();
        } catch (const std::exception &e) {
            CB_ERROR("Failed to load target configuration '{}' - {}", cfg.targets_path, e.what());
            return Status::ERR;
        }
        return Status::OK;
    }

    template <typename V>
    static inline void display_vec(const char *name, const Vec<V> values,
                                   std::function<void(const V &)> on_values) {
        printf("cb.targets.%s    = [", name);
        for (size_t fl = 0; fl < values.size(); fl++) {
            on_values(values[fl]);
            if (fl != values.size() - 1) printf(", ");
        }
        printf("]" CB_LINE_END);
    }

    void Cb::targets_display() {
        printf(CB_LINE_END);
        printf("cb.targets.count    = %zu" CB_LINE_END, targets.size());
        for (const auto &t : targets) {
            printf(
                "===================================================="
                "=" CB_LINE_END);
            Str type = TARGET_TYPE_DISPLAY[t.type];
            printf("cb.targets.type       = %s" CB_LINE_END, type.c_str());
            printf("cb.targets.name       = %s" CB_LINE_END, t.name.c_str());
            if (t.type != TargetType::SYSTEM_LIB) {
                printf("cb.targets.output_dir = '%s'" CB_LINE_END, t.output_dir.c_str());
                printf("cb.targets.output     = '%s'" CB_LINE_END, t.file.out.c_str());
                printf("cb.targets.source     = '%s'" CB_LINE_END, t.file.src.c_str());
            }
            display_vec<Str>("flags", t.flags, [](const Str &v) { printf("%s", v.c_str()); });
            display_vec<Str>("ldflags", t.ldflags, [](const Str &v) { printf("%s", v.c_str()); });
            if (t.type != TargetType::SYSTEM_LIB) {
                display_vec<Source>("includes", t.sources, [](const Source &v) {
                    printf("{src: %s, out: %s}", v.src.c_str(), v.out.c_str());
                });
            }
            printf(CB_LINE_END);
        }
        printf(CB_LINE_END);
    }

    bool Cb::is_builded() const {
        return !std::all_of(targets.begin(), targets.end(),
                            [](const Target &t) { return t.need_rebuild(); });
    }
    bool Cb::is_configured() const {
        if (cfg.config_path.empty() || cfg.targets_path.empty()) return false;
        return file_exists(cfg.config_path) && file_exists(cfg.targets_path);
    }
    bool   Cb::is_targets_changed() const { return source_hash() != __source_hashes; }
    size_t Cb::source_hash() const {
        size_t seed = 0;
        for (const auto &tg : targets) hash_combine<Target, target_hash>(seed, tg);
        return seed;
    }

    Status Cb::m_build_target() {
        if (!is_configured())
            if (m_config_target() == Status::ERR) return Status::ERR;
        if (load_targets() == Status::ERR) return Status::ERR;
        CB_INFO("Running Build");

        auto c = callbacks.find("build");
        if (c != callbacks.end() && c->second != nullptr)
            if (c->second(this) == Status::ERR) return Status::ERR;

        CB_INFO("Finish Build");
        return Status::OK;
    }
    Status Cb::m_config_target() {
        CB_INFO("=== Running Configure ===");
        auto c = callbacks.find("config");
        if (c != callbacks.end() && c->second != nullptr)
            if (c->second(this) == Status::ERR) return Status::ERR;

        if (cfg.is_changed()) {
            if (cfg.save(cfg.config_path) == Status::ERR)
                CB_BAIL_ERROR(Status::ERR, "Failed to save config");
            CB_INFO("Saving Configuration to '{}'", cfg.config_path);
        }
        if (is_targets_changed()) {
            if (save_targets() == Status::ERR) return Status::ERR;
            CB_INFO("Saving Targets Information to '{}'", cfg.targets_path);
        }

        if (cfg.dump_compile_command) compile_commands(this);

        CB_INFO("=== Success Configuring, run `build` or `tests` to build and run tests ===");
        return Status::OK;
    }
    Status Cb::m_clean_target() {
        auto c = callbacks.find("clean");
        if (c != callbacks.end() && c->second != nullptr)
            if (c->second(this) == Status::ERR) return Status::ERR;
        return Status::OK;
    }
    Status Cb::m_install_target() {
        CB_INFO("Running Install");
        cfg.build_type = Build::RELEASE;

        if (!is_configured())
            if (m_config_target() == Status::ERR) return Status::ERR;
        if (!is_builded())
            if (m_build_target() == Status::ERR) return Status::ERR;

        auto c = callbacks.find("install");
        if (c != callbacks.end() && c->second != nullptr)
            if (c->second(this) == Status::ERR) return Status::ERR;

        CB_INFO("Success Running Install");
        return Status::OK;
    }

    Status Cb::m_on_build_target(Cb *cb) {
        for (auto &tg : cb->targets) {
            if (tg.type == TargetType::SYSTEM_LIB || tg.type == TargetType::EXEC) continue;
            mkdir_if_not_exists(tg.output_dir);
            if (tg.run(cb->cfg) == Status::ERR)
                CB_BAIL_ERROR(Status::ERR, "failed to run target: '{}'", tg.name);
        }

        for (auto &tg : cb->targets) {
            if (tg.type == TargetType::EXEC) {
                mkdir_if_not_exists(tg.output_dir);
                if (tg.run(cb->cfg) == Status::ERR)
                    CB_BAIL_ERROR(Status::ERR, "failed to run target: '{}'", tg.name);
            }
        }

        return Status::OK;
    }

    Status Cb::m_on_config_target(Cb *cb) {
        Str def_source_path = cb->cfg.project_path;
        path_append(def_source_path, "src");
        Str def_include_path = cb->cfg.project_path;
        path_append(def_include_path, "include");

        auto exec = cb->create_exec(cb->cfg.project_name);
        exec.add_sources_with_ext(cb->cfg.project_path, program_ext(cb->cfg.program_type), true);
        exec.add_includes(def_include_path);
        exec.add_flags("-Wall", "-Wextra", "-Werror", "-pedantic");

        return Status::OK;
    }

    Status Cb::m_on_install_target(Cb *cb) {
        if (cb->cfg.install_prefix.empty()) {
            CB_BAIL_ERROR(Status::ERR,
                          "cfg.install_prefix should set to install, set the prefix with "
                          "`cb_config_set_install_prefix` function");
        }
#    ifdef CB_LINUX
        if (cb->cfg.install_prefix.front() == CB_DIR_SEPARATOR_CHAR)
            if (getuid() != 0)
                CB_BAIL_ERROR(Status::ERR, "Command install requires Admin Privilages!");
#    endif

        bool result;
        result = mkdir_if_not_exists(cb->cfg.bin_install_dir);
        result = mkdir_if_not_exists(cb->cfg.lib_install_dir);
        if (!result) return Status::ERR;

        Status sts = Status::OK;
        for (auto &tg : cb->targets) {
            if (tg.type == TargetType::SYSTEM_LIB) continue;
            sts &= tg.install(cb->cfg.bin_install_dir);
        }
        return sts;
    }
    Status Cb::m_on_clean_target(Cb *cb) {
        bool is_ok = remove_dir_rec(cb->cfg.build_artifact_path);
        if (!is_ok) CB_BAIL_ERROR(Status::ERR, "Failed to remove directory");
        return Status::OK;
    }

    Status Cb::run(int argc, char **argv) {
        cfg.parse_from_args({argv, argv + argc}, this->callbacks);

        Status result = Status::OK;
        if (cfg.subcmd == "build") {
            result = m_build_target();
        } else if (cfg.subcmd == "config") {
            result = m_config_target();
        } else if (cfg.subcmd == "clean") {
            result = m_clean_target();
        } else if (cfg.subcmd == "install") {
            result = m_install_target();
        } else {
            auto callback = callbacks.find(cfg.subcmd);
            if (callback != callbacks.end()) {
                if (callback->second)
                    result = callback->second(this);
                else {
                    CB_ERROR("no callback for subcommand {}", cfg.subcmd);
                    result = Status::ERR;
                }
            } else {
                if (!cfg.subcmd.empty()) {
                    CB_ERROR("Invalid Subcommand {}", cfg.subcmd);
                    result = Status::ERR;
                }
            }
        }
        if (g_display_config) {
            cfg.serialize(std::cerr);
            targets_display();
        }
        return result;
    }

#    ifdef CB_WINDOWS
    struct Find_Result {
        int      windows_sdk_version;  // Zero if no Windows SDK found.

        wchar_t *windows_sdk_root              = nullptr;
        wchar_t *windows_sdk_um_library_path   = nullptr;
        wchar_t *windows_sdk_ucrt_library_path = nullptr;

        wchar_t *vs_exe_path                   = nullptr;
        wchar_t *vs_library_path               = nullptr;
    };

    static Find_Result find_visual_studio_and_windows_sdk();

    static void        free_resources(Find_Result *result) {
        free(result->windows_sdk_root);
        free(result->windows_sdk_um_library_path);
        free(result->windows_sdk_ucrt_library_path);
        free(result->vs_exe_path);
        free(result->vs_library_path);
    }

    DIR *opendir(const char *dirpath) {
        assert(dirpath);
        char buffer[MAX_PATH];
        snprintf(buffer, MAX_PATH, "%s\\*", dirpath);
        DIR *dir   = (DIR *)calloc(1, sizeof(DIR));
        dir->hFind = FindFirstFile(buffer, &dir->data);
        if (dir->hFind == INVALID_HANDLE_VALUE) {
            errno = ENOSYS;
            goto fail;
        }
        return dir;

    fail:
        if (dir) CB_FREE(dir);
        return nullptr;
    }

    struct dirent *readdir(DIR *dirp) {
        assert(dirp);
        if (dirp->dirent == nullptr) {
            dirp->dirent = (struct dirent *)calloc(1, sizeof(struct dirent));
        } else {
            if (!FindNextFile(dirp->hFind, &dirp->data)) {
                if (GetLastError() != ERROR_NO_MORE_FILES) {
                    errno = ENOSYS;
                }
                return nullptr;
            }
        }
        memset(dirp->dirent->d_name, 0, sizeof(dirp->dirent->d_name));
        strncpy(dirp->dirent->d_name, dirp->data.cFileName, sizeof(dirp->dirent->d_name) - 1);
        return dirp->dirent;
    }

    int closedir(DIR *dirp) {
        assert(dirp);
        if (!FindClose(dirp->hFind)) {
            errno = ENOSYS;
            return -1;
        }
        if (dirp->dirent) CB_FREE(dirp->dirent);
        CB_FREE(dirp);
        return 0;
    }

    // COM objects for the ridiculous Microsoft craziness.

    struct DECLSPEC_UUID("B41463C3-8866-43B5-BC33-2B0676F7F42E") DECLSPEC_NOVTABLE ISetupInstance
        : public IUnknown {
        STDMETHOD(GetInstanceId)(_Out_ BSTR *pbstrInstanceId)             = 0;
        STDMETHOD(GetInstallDate)(_Out_ LPFILETIME pInstallDate)          = 0;
        STDMETHOD(GetInstallationName)(_Out_ BSTR *pbstrInstallationName) = 0;
        STDMETHOD(GetInstallationPath)(_Out_ BSTR *pbstrInstallationPath) = 0;
        STDMETHOD(GetInstallationVersion)
        (_Out_ BSTR *pbstrInstallationVersion) = 0;
        STDMETHOD(GetDisplayName)
        (_In_ LCID lcid, _Out_ BSTR *pbstrDisplayName) = 0;
        STDMETHOD(GetDescription)
        (_In_ LCID lcid, _Out_ BSTR *pbstrDescription) = 0;
        STDMETHOD(ResolvePath)
        (_In_opt_z_ LPCOLESTR pwszRelativePath, _Out_ BSTR *pbstrAbsolutePath) = 0;
    };

    struct DECLSPEC_UUID("6380BCFF-41D3-4B2E-8B2E-BF8A6810C848")
        DECLSPEC_NOVTABLE IEnumSetupInstances : public IUnknown {
        STDMETHOD(Next)
        (_In_ ULONG celt, _Out_writes_to_(celt, *pceltFetched) ISetupInstance **rgelt,
         _Out_opt_ _Deref_out_range_(0, celt) ULONG *pceltFetched)     = 0;
        STDMETHOD(Skip)(_In_ ULONG celt)                               = 0;
        STDMETHOD(Reset)(void)                                         = 0;
        STDMETHOD(Clone)(_Deref_out_opt_ IEnumSetupInstances **ppenum) = 0;
    };

    struct DECLSPEC_UUID("42843719-DB4C-46C2-8E7C-64F1816EFD5B")
        DECLSPEC_NOVTABLE ISetupConfiguration : public IUnknown {
        STDMETHOD(EnumInstances)
        (_Out_ IEnumSetupInstances **ppEnumInstances) = 0;
        STDMETHOD(GetInstanceForCurrentProcess)
        (_Out_ ISetupInstance **ppInstance) = 0;
        STDMETHOD(GetInstanceForPath)
        (_In_z_ LPCWSTR wzPath, _Out_ ISetupInstance **ppInstance) = 0;
    };

    struct Version_Data {
        int32_t  best_version[4];
        wchar_t *best_name;
    };

    static bool os_file_exists(wchar_t *name) {
        auto attrib = GetFileAttributesW(name);
        if (attrib == INVALID_FILE_ATTRIBUTES) return false;
        if (attrib & FILE_ATTRIBUTE_DIRECTORY) return false;

        return true;
    }

    static wchar_t *concat(wchar_t *a, wchar_t *b, wchar_t *c = nullptr, wchar_t *d = nullptr) {
        auto len_a = wcslen(a);
        auto len_b = wcslen(b);

        auto len_c = 0;
        if (c) len_c = wcslen(c);

        auto len_d = 0;
        if (d) len_d = wcslen(d);

        wchar_t *result = (wchar_t *)malloc((len_a + len_b + len_c + len_d + 1) * 2);
        memcpy(result, a, len_a * 2);
        memcpy(result + len_a, b, len_b * 2);

        if (c) memcpy(result + len_a + len_b, c, len_c * 2);
        if (d) memcpy(result + len_a + len_b + len_c, d, len_d * 2);

        result[len_a + len_b + len_c + len_d] = 0;

        return result;
    }

    typedef void (*Visit_Proc_W)(wchar_t *short_name, wchar_t *full_name, Version_Data *data);
    static bool  visit_files_w(wchar_t *dir_name, Version_Data *data, Visit_Proc_W proc) {
        auto wildcard_name = concat(dir_name, L"\\*");
        defer { free(wildcard_name); };

        WIN32_FIND_DATAW find_data;
        auto             handle = FindFirstFileW(wildcard_name, &find_data);
        if (handle == INVALID_HANDLE_VALUE) return false;

        while (true) {
            if ((find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
                (find_data.cFileName[0] != '.')) {
                auto full_name = concat(dir_name, L"\\", find_data.cFileName);
                defer { free(full_name); };

                proc(find_data.cFileName, full_name, data);
            }

            auto success = FindNextFileW(handle, &find_data);
            if (!success) break;
        }

        FindClose(handle);

        return true;
    }

    static wchar_t *read_from_the_registry(HKEY key, wchar_t *value_name) {
        DWORD required_length;
        auto  rc = RegQueryValueExW(key, value_name, nullptr, nullptr, nullptr, &required_length);
        if (rc != 0) return nullptr;

        wchar_t *value;
        DWORD    length;
        while (1) {
            length = required_length + 2;
            value  = (wchar_t *)malloc(length + 2);
            if (!value) return nullptr;

            DWORD type;
            rc = RegQueryValueExW(key, value_name, nullptr, &type, (LPBYTE)value, &length);
            if (rc == ERROR_MORE_DATA) {
                free(value);
                required_length = length;
                continue;
            }

            if ((rc != 0) || (type != REG_SZ)) {
                // REG_SZ because we only accept strings here!
                free(value);
                return nullptr;
            }

            break;
        }

        auto num_wchars   = length / 2;
        value[num_wchars] = 0;
        return value;
    }

    static void win10_best(wchar_t *short_name, wchar_t *full_name, Version_Data *data) {
        int  i0, i1, i2, i3;
        auto success = swscanf_s(short_name, L"%d.%d.%d.%d", &i0, &i1, &i2, &i3);
        if (success < 4) return;

        if (i0 < data->best_version[0])
            return;
        else if (i0 == data->best_version[0]) {
            if (i1 < data->best_version[1])
                return;
            else if (i1 == data->best_version[1]) {
                if (i2 < data->best_version[2])
                    return;
                else if (i2 == data->best_version[2]) {
                    if (i3 < data->best_version[3]) return;
                }
            }
        }

        if (data->best_name) free(data->best_name);
        data->best_name = _wcsdup(full_name);

        if (data->best_name) {
            data->best_version[0] = i0;
            data->best_version[1] = i1;
            data->best_version[2] = i2;
            data->best_version[3] = i3;
        }
    }

    static void win8_best(wchar_t *short_name, wchar_t *full_name, Version_Data *data) {
        // Find the Windows 8 subdirectory with the highest version number.

        int  i0, i1;
        auto success = swscanf_s(short_name, L"winv%d.%d", &i0, &i1);
        if (success < 2) return;

        if (i0 < data->best_version[0])
            return;
        else if (i0 == data->best_version[0]) {
            if (i1 < data->best_version[1]) return;
        }

        if (data->best_name) free(data->best_name);
        data->best_name = _wcsdup(full_name);

        if (data->best_name) {
            data->best_version[0] = i0;
            data->best_version[1] = i1;
        }
    }

    static void find_windows_kit_root(Find_Result *result) {
        HKEY main_key;

        auto rc =
            RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows Kits\\Installed Roots",
                          0, KEY_QUERY_VALUE | KEY_WOW64_32KEY | KEY_ENUMERATE_SUB_KEYS, &main_key);
        if (rc != S_OK) return;
        defer { RegCloseKey(main_key); };

        // Look for a Windows 10 entry.
        auto windows10_root = read_from_the_registry(main_key, L"KitsRoot10");
        if (windows10_root) {
            defer { free(windows10_root); };
            Version_Data data          = {0};
            auto         windows10_lib = concat(windows10_root, L"Lib");
            defer { free(windows10_lib); };

            visit_files_w(windows10_lib, &data, win10_best);
            if (data.best_name) {
                result->windows_sdk_version = 10;
                result->windows_sdk_root    = data.best_name;
                return;
            }
        }

        // Look for a Windows 8 entry.
        auto windows8_root = read_from_the_registry(main_key, L"KitsRoot81");

        if (windows8_root) {
            defer { free(windows8_root); };

            auto windows8_lib = concat(windows8_root, L"Lib");
            defer { free(windows8_lib); };

            Version_Data data = {0};
            visit_files_w(windows8_lib, &data, win8_best);
            if (data.best_name) {
                result->windows_sdk_version = 8;
                result->windows_sdk_root    = data.best_name;
                return;
            }
        }

        // If we get here, we failed to find anything.
    }

    static bool find_visual_studio_2017_by_fighting_through_microsoft_craziness(
        Find_Result *result) {
        auto rc     = CoInitializeEx(nullptr, COINIT_MULTITHREADED);

        GUID my_uid = {
            0x42843719, 0xDB4C, 0x46C2, {0x8E, 0x7C, 0x64, 0xF1, 0x81, 0x6E, 0xFD, 0x5B}};
        GUID CLSID_SetupConfiguration = {
            0x177F0C4A, 0x1CD3, 0x4DE7, {0xA3, 0x2C, 0x71, 0xDB, 0xBB, 0x9F, 0xA3, 0x6D}};

        ISetupConfiguration *config = nullptr;
        auto hr = CoCreateInstance(CLSID_SetupConfiguration, nullptr, CLSCTX_INPROC_SERVER, my_uid,
                                   (void **)&config);
        if (hr != 0) return false;
        defer { config->Release(); };

        IEnumSetupInstances *instances = nullptr;
        hr                             = config->EnumInstances(&instances);
        if (hr != 0) return false;
        if (!instances) return false;
        defer { instances->Release(); };

        while (1) {
            ULONG           found    = 0;
            ISetupInstance *instance = nullptr;
            auto            hr       = instances->Next(1, &instance, &found);
            if (hr != S_OK) break;

            defer { instance->Release(); };

            BSTR bstr_inst_path;
            hr = instance->GetInstallationPath(&bstr_inst_path);
            if (hr != S_OK) continue;
            defer { SysFreeString(bstr_inst_path); };

            auto tools_filename = concat(bstr_inst_path,
                                         L"\\VC\\Auxiliary\\Build\\Microsoft."
                                         L"VCToolsVersion.default.txt");
            defer { free(tools_filename); };

            FILE *f           = nullptr;
            auto  open_result = _wfopen_s(&f, tools_filename, L"rt");
            if (open_result != 0) continue;
            if (!f) continue;
            defer { fclose(f); };

            LARGE_INTEGER tools_file_size;
            auto          file_handle = (HANDLE)_get_osfhandle(_fileno(f));
            BOOL          success     = GetFileSizeEx(file_handle, &tools_file_size);
            if (!success) continue;

            auto     version_bytes = (tools_file_size.QuadPart + 1) * 2;
            wchar_t *version       = (wchar_t *)malloc(version_bytes);
            defer { free(version); };

            auto read_result = fgetws(version, version_bytes, f);
            if (!read_result) continue;

            auto version_tail = wcschr(version, '\n');
            if (version_tail) *version_tail = 0;

            auto library_path =
                concat(bstr_inst_path, L"\\VC\\Tools\\MSVC\\", version, L"\\lib\\x64");
            auto library_file = concat(library_path, L"\\vcruntime.lib");

            if (os_file_exists(library_file)) {
                auto link_exe_path =
                    concat(bstr_inst_path, L"\\VC\\Tools\\MSVC\\", version, L"\\bin\\Hostx64\\x64");
                result->vs_exe_path     = link_exe_path;
                result->vs_library_path = library_path;
                return true;
            }
        }

        return false;
    }

    static void find_visual_studio_by_fighting_through_microsoft_craziness(Find_Result *result) {
        bool found_visual_studio_2017 =
            find_visual_studio_2017_by_fighting_through_microsoft_craziness(result);
        if (found_visual_studio_2017) return;

        HKEY vs7_key;
        auto rc = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\VisualStudio\\SxS\\VS7",
                                0, KEY_QUERY_VALUE | KEY_WOW64_32KEY, &vs7_key);

        if (rc != S_OK) return;
        defer { RegCloseKey(vs7_key); };

        wchar_t  *versions[]   = {L"14.0", L"12.0", L"11.0", L"10.0"};
        const int NUM_VERSIONS = sizeof(versions) / sizeof(versions[0]);

        for (int i = 0; i < NUM_VERSIONS; i++) {
            auto v      = versions[i];

            auto buffer = read_from_the_registry(vs7_key, v);
            if (!buffer) continue;

            defer { free(buffer); };

            auto lib_path           = concat(buffer, L"VC\\Lib\\amd64");

            // Check to see whether a vcruntime.lib actually exists here.
            auto vcruntime_filename = concat(lib_path, L"\\vcruntime.lib");
            defer { free(vcruntime_filename); };

            if (os_file_exists(vcruntime_filename)) {
                result->vs_exe_path     = concat(buffer, L"VC\\bin\\amd64");
                result->vs_library_path = lib_path;
                return;
            }

            free(lib_path);
        }
    }

    Find_Result find_visual_studio_and_windows_sdk() {
        Find_Result result;

        find_windows_kit_root(&result);

        if (result.windows_sdk_root) {
            result.windows_sdk_um_library_path   = concat(result.windows_sdk_root, L"\\um\\x64");
            result.windows_sdk_ucrt_library_path = concat(result.windows_sdk_root, L"\\ucrt\\x64");
        }

        find_visual_studio_by_fighting_through_microsoft_craziness(&result);

        return result;
    }
#    else
    struct Find_Result {
        int      sdk_version           = 0;  // Zero if no Windows SDK found.
        wchar_t *sdk_root              = nullptr;
        wchar_t *sdk_um_library_path   = nullptr;
        wchar_t *sdk_ucrt_library_path = nullptr;

        wchar_t *exe_path              = nullptr;
        wchar_t *library_path          = nullptr;
    };

    static Find_Result find_visual_studio_and_windows_sdk() { return Find_Result(); }
    static void        free_resources(Find_Result *result) { (void)result; }

#    endif  // CB_WINDOWS

    Status which_exec(const Str &exec, Str &out) {
        CB_INFO("Searching full path of executable: `{}`", exec);
        out.clear();

        char *paths = getenv("PATH");
        if (paths == nullptr) CB_BAIL_ERROR(Status::ERR, "$PATH environment variable not set.\n");

        const char *token;
        while ((token = strsep(&paths, ":")) != nullptr) {
            walkdir(token, false, [&](const Str &path, __attribute__((unused)) FileType ft) {
                if (exec == path_filename(path)) {
                    CB_INFO("Found which path: {}", path);
                    out = path;
                    return false;
                }
                return true;
            });
            if (!out.empty()) {
                CB_INFO("Found Program `{}` in $PATH: `{}`", exec, out);
                return Status::OK;
            }
        }

        CB_ERROR("Program in $PATH for: `{}` is NotFound", exec);
        return Status::ERR;
    }

#    define CB_WHICH_COMPILER(P, CC, CXX)                                                        \
        do {                                                                                     \
            switch (cfg.program_type) {                                                          \
                case Program::C: result = which_exec(CC, P); break;                              \
                case Program::CPP: result = which_exec(CXX, P); break;                           \
                default: CB_ERROR("Program is Unknown, should be c or c++"); return Status::ERR; \
            }                                                                                    \
        } while (0)

    Status find_compiler(Str &compiler_path, const Config &cfg) {
        Status result = Status::OK;
        switch (cfg.compiler_type) {
            case Compiler::MSVC: {
                Find_Result msvc_find_result = find_visual_studio_and_windows_sdk();
                defer { free_resources(&msvc_find_result); };

                if (msvc_find_result.sdk_version > 0 && msvc_find_result.exe_path != nullptr) {
                    auto len = std::wstring::traits_type::length(msvc_find_result.exe_path);
                    compiler_path.assign(&msvc_find_result.exe_path[0],
                                         msvc_find_result.exe_path + len);
                } else {
                    result = which_exec("cl", compiler_path);
                }
                if (!compiler_path.empty() && result == Status::OK) break;
            }
                // fallthrough
            case Compiler::CLANG: {
                CB_WHICH_COMPILER(compiler_path, "clang", "clang++");
                if (!compiler_path.empty()) break;
            }
                // fallthrough
            case Compiler::GNU: CB_WHICH_COMPILER(compiler_path, "gcc", "g++"); break;
            default: break;
        }
        if (result == Status::ERR || compiler_path.empty()) {
            CB_INFO("Failed to get program path for: Compiler `{}`",
                    COMPILER_DISPLAY[cfg.compiler_type]);
            CB_INFO("Trying to get Compiler path from environment variable `PATH`=`CC`");
            char *compiler = getenv("CC");
            if (compiler == nullptr) {
                CB_INFO("There is no Compiler path from environment variable `PATH`=`CC`");
                return Status::ERR;
            }
            compiler_path = compiler;
        }

        return Status::OK;
    }

    static inline Str quoted(const Str &str) { return '\"' + str + '\"'; }
    static void source_compile_commands(std::ostream &oss, const Str &dir, const Str &compiler,
                                        const Source &src, const Vec<Str> &flags,
                                        size_t spaces = 2) {
        oss << Str(spaces, ' ') << '{' << std::endl;
        {
            oss << Str(spaces * 2, ' ') << "\"arguments\": [" << std::endl;
            oss << Str(spaces * 3, ' ') << quoted(compiler) << ',' << std::endl;
            for (const auto &flag : flags)
                oss << Str(spaces * 3, ' ') << quoted(flag) << ',' << std::endl;
            oss << Str(spaces * 3, ' ') << quoted("-c") << ',' << std::endl;
            oss << Str(spaces * 3, ' ') << quoted("-o") << ',' << std::endl;
            oss << Str(spaces * 3, ' ') << quoted(src.out) << ',' << std::endl;
            oss << Str(spaces * 3, ' ') << quoted(src.src) << ',' << std::endl;
            oss << Str(spaces * 2, ' ') << "]," << std::endl;
        }

        oss << Str(spaces * 2, ' ') << "\"directory\": " << quoted(dir) << ',' << std::endl;
        oss << Str(spaces * 2, ' ') << "\"file\": " << quoted(src.src) << ',' << std::endl;
        oss << Str(spaces * 2, ' ') << "\"output\": " << quoted(src.out) << std::endl;
        oss << Str(spaces, ' ') << '}';
    }

    void compile_commands(Cb *cb) {
        const Str &project_dir   = cb->cfg.project_path;
        const Str &compiler_path = cb->cfg.compiler_path;
        try {
            Str cmpath = cb->cfg.build_path;
            path_append(cmpath, "compile_commands.json");
            CB_INFO("Generating Compile Database: {}", cmpath);
            std::ofstream out(cmpath);
            out << '[' << std::endl;
            for (size_t t = 0; t < cb->targets.size(); t++) {
                const auto &target = cb->targets[t];
                if (target.type == TargetType::EXEC || !target.file.src.empty()) {
                    source_compile_commands(out, project_dir, compiler_path, target.file,
                                            target.flags);
                }
                if (!target.sources.empty()) {
                    out << ',' << std::endl;
                    for (size_t i = 0; i < target.sources.size(); i++) {
                        source_compile_commands(out, project_dir, compiler_path, target.sources[i],
                                                target.flags);
                        if (i != (target.sources.size() - 1)) out << ',';
                        out << std::endl;
                    }
                }
                if (t != (cb->targets.size() - 1)) out << ',';
                out << std::endl;
            }
            out << ']';

        } catch (const std::exception &e) {
            CB_ERROR("Failed on genereating compile_commands.json");
        }
    }
}  // namespace cb

////////////////////////////////////////////////////////////////////////////////
#endif  // CB_IMPLEMENTATION
