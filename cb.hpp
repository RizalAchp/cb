#pragma once

#include <iomanip>
#include <stack>
#include <type_traits>
#define CB_IMPLEMENTATION

#ifndef __CB_H__
#    define __CB_H__

#    define CB_ASSERT(PRED, ...) \
        if (!(PRED)) CB_BAIL_ERROR(exit(1), "ASSERTION ERROR: (" #PRED "):" __VA_ARGS__)
#    define CB_ASSERT_ALLOC(PTR) CB_ASSERT((PTR != nullptr), "Buy more RAM lol")

#    include <algorithm>
#    include <array>
#    include <cstdarg>
#    include <cstdio>
#    include <cstdlib>
#    include <cstring>
#    include <filesystem>
#    include <fstream>
#    include <functional>
#    include <iostream>
#    include <memory>
#    include <optional>
#    include <string>
#    include <string_view>
#    include <system_error>
#    include <unordered_map>
#    include <vector>

#    if defined(__APPLE__) || defined(__MACH__)
#        define CB_MACOS
#        define CB_DEFAULT_PLATFORM Platform::MACOS
#        define CB_PATH_SEPARATOR   ':'
#        define CB_DIR_SEPARATOR    '/'
#        define CB_LINE_END         "\n"
#    elif defined(_WIN32) || defined(WIN32) || defined(_WIN64) || defined(__CYGWIN__) || defined(__MINGW32__)
#        define CB_WINDOWS
#        define CB_DEFAULT_PLATFORM Platform::WINDOWS
#        define WIN32_LEAN_AND_MEAN
#        include <direct.h>
#        include <shellapi.h>
#        include <windows.h>
#        define getcwd(buff, size) GetCurrentDirectory(size, buff)
#        define access             _access
#        define F_OK               0
#        define CB_PATH_SEPARATOR  ';'
#        define CB_DIR_SEPARATOR   '\\'
#        define CB_LINE_END        "\r\n"
typedef HANDLE cb_proc_t;
#        define CB_INVALID_PROC    INVALID_HANDLE_VALUE
struct dirent {
    char d_name[MAX_PATH + 1];
};
typedef struct DIR DIR;
DIR               *opendir(const char *dirpath);
struct dirent     *readdir(DIR *dirp);
int                closedir(DIR *dirp);
#    elif defined(__linux__) && defined(__unix__)
#        define CB_UNIX
#        define CB_DEFAULT_PLATFORM Platform::UNIX
#        include <dirent.h>
#        include <fcntl.h>
#        include <pwd.h>
#        include <sys/stat.h>
#        include <sys/types.h>
#        include <sys/wait.h>
#        include <unistd.h>
#        define MAX_PATH          PATH_MAX
#        define CB_PATH_SEPARATOR ':'
#        define CB_DIR_SEPARATOR  '/'
#        define CB_LINE_END       "\n"
typedef int proc_t;
#        define CB_INVALID_PROC   (-1)
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
#        if defined(__GNUC__)
#            define CB_REBUILD_ARGS(binary_path, source_path) "g++", "-Wall", "-Wextra", "-pedantic", "-O2", "-o", binary_path, source_path
#        elif defined(__clang__)
#            define CB_REBUILD_ARGS(binary_path, source_path) "clang++", "-Wall", "-Wextra", "-pedantic", "-O2", "-o", binary_path, source_path
#        elif defined(_MSC_VER)
#            define CB_REBUILD_ARGS(binary_path, source_path) "cl.exe", source_path
#        endif
#    endif
#    define CB_REBUILD_SELF(argc, argv) cb::rebuild_self(argc, argv, __FILE__)

#define CB_MAIN  \
    static inline int __start(int argc, char *argv[]); \
    int main(int argc, char *argv[]) { \
        cb::rebuild_self(argc, argv, __FILE__);\
        return __start(argc, argv); \
    } \
    int __start(int argc, char *argv[])

// clang-format on
#    define SVFmt     "%*s"
#    define SVArg(sv) (int)sv.size(), sv.data()

namespace cb {
    namespace fs  = std::filesystem;
    using StrView = std::string_view;
    using Str     = std::string;
    using Cmd     = std::vector<const char *>;
    using Procs   = std::vector<proc_t>;
    template <typename T, size_t N>
    using Arr = std::array<T, N>;
    template <typename T>
    using Vec = std::vector<T>;
    template <typename T>
    using Option = std::optional<T>;

    template <typename Key, typename Value>
    using Map = std::unordered_map<Key, Value>;

    struct Config;
    struct Cb;

    enum class Status : uint8_t { ERR = 0, OK = 1 };
    enum class LogLevel : size_t { NONE = 0, INFO, WARNING, ERROR, FATAL, MAX };

    enum class Build : size_t { DEBUG = 0, RELEASE, RELEASEDEBUG, MAX };
    enum class Platform : size_t { UNKNOWN = 0, WINDOWS, MACOS, UNIX, MAX };
    enum class Arch : size_t { UNKNOWN = 0, X64, X86, ARM64, ARM32, MAX };
    enum class Compiler : size_t { UNKNOWN = 0, CLANG, GNU, MSVC, MAX };
    enum class Program : size_t { UNKNOWN = 0, C, CPP, MAX };
    enum class TargetType : size_t { EXEC = 0, STATIC_LIB, DYNAMIC_LIB, SYSTEM_LIB, MAX };

    using callbacks_cb_t = std::function<Status(Cb *)>;
    constexpr inline const char *program_ext(Program p) { return (p == Program::C) ? "c" : "cpp"; }

#    define CB_FATAL(...) log(LogLevel::FATAL, __FILE__, __LINE__, format_str(__VA_ARGS__))
#    define CB_ERROR(...) \
        if (g_log_level <= LogLevel::ERROR) log(LogLevel::ERROR, __FILE__, __LINE__, format_str(__VA_ARGS__))
#    define CB_WARNING(...) \
        if (g_log_level <= LogLevel::WARNING) log(LogLevel::WARNING, __FILE__, __LINE__, format_str(__VA_ARGS__))
#    define CB_INFO(...) \
        if (g_log_level <= LogLevel::INFO) log(LogLevel::INFO, __FILE__, __LINE__, format_str(__VA_ARGS__))
#    define CB_BAIL_ERROR(RET, ...) \
        {                           \
            CB_ERROR(__VA_ARGS__);  \
            RET;                    \
        }

#    define cb_return_defer(value) \
        {                          \
            result = (value);      \
            goto defer;            \
        }

#    define NOT_IMPLEMENTED(DESC) CB_BAIL_ERROR(exit(1), "Not Implemented: %s", DESC)
#    define UNREACHABLE(DESC)     CB_BAIL_ERROR(exit(1), "Unreachable: %s", DESC)

    CB_FNDEF Str  format_str(const char *fmt, ...) __attribute__((__format__(__printf__, 1, 2)));
    CB_FNDEF void log(LogLevel level, const char *file, int line, Str msg);
    CB_FNDEF bool on_errc_impl(std::error_code &ec, Str msg);
#    define on_errc(ec, ...) on_errc_impl(ec, format_str(__VA_ARGS__))

    CB_FNDEF Str &ltrim(Str &s);
    CB_FNDEF Str &rtrim(Str &s);
    CB_FNDEF Str &trim(Str &s);
    // trim from both ends (copying)
    CB_FNDEF Str trim_copy(Str s);
    CB_FNDEF Vec<StrView> split(StrView s, StrView delimiter);

    CB_FNDEF bool         file_rename(const Str old_path, const Str new_path);
    CB_FNDEF bool         file_exists(const fs::path &file_path);

    CB_FNDEF bool         rebuild_self(int argc, char *argv[], const char *source_path);
    CB_FNDEF bool         mkdir_if_not_exists(const fs::path &path);
    CB_FNDEF bool         remove_dir_if_exists(const fs::path &dirpath);
    CB_FNDEF bool         copy_file(const Str &dst_path, const Str &src_path);
    /// run command in shell and get output from stdout into `stdout_content`
    CB_FNDEF bool current_path(fs::path &out_path, const char *optional_append_path = nullptr);
    CB_FNDEF fs::path path_to_absolute(const fs::path &path);
    CB_FNDEF bool     home_dir(fs::path &out_path, const char *optional_append_path = nullptr);
    CB_FNDEF bool     set_permissions(const fs::path &file, fs::perms permissions);

    using WalkdirCallback = std::function<bool(const fs::path &)>;
    CB_FNDEF bool walkdir(const fs::path &parent, bool recursive, WalkdirCallback callback);

    // Wait until the process has finished
    CB_FNDEF bool procs_wait(const Procs &procs);
    CB_FNDEF bool proc_wait(proc_t proc);

    /// run cmd_t asynchronously, returned handle of proc_t
    /// wait the process using function `proc_wait`
    CB_FNDEF proc_t cmd_run_async(Cmd &cmd);
    /// run cmd_t and wait until finish (sync)
    CB_FNDEF bool   cmd_run(Cmd &cmd);
    CB_FNDEF Status popen_stdout(const Str &cmd, Str &stdout_content);

    extern LogLevel g_log_level;

#    define CONCAT_INTERNAL(x, y) x##y
#    define CONCAT(x, y)          CONCAT_INTERNAL(x, y)

    template <typename T>
    struct ExitScope {
        T lambda;
        ExitScope(T lambda) : lambda(lambda) {}
        ~ExitScope() { lambda(); }
        ExitScope(const ExitScope &);

       private:
        ExitScope &operator=(const ExitScope &);
    };

    class ExitScopeHelp {
       public:
        template <typename T>
        ExitScope<T> operator+(T t) {
            return t;
        }
    };

#    define defer const auto &CONCAT(defer__, __LINE__) = ExitScopeHelp() + [&]()

    struct SerializeDeserialize {
        SerializeDeserialize() noexcept                          = default;
        virtual ~SerializeDeserialize()                          = default;
        virtual bool serialize(std::ostream &outstream)          = 0;
        virtual bool deserialize_key_value(Str &key, Str &value) = 0;
        virtual bool deserialize(std::istream &instream) {
            Str linebuf;
            while (getline(instream, linebuf)) {
                if (trim(linebuf).empty()) continue;
                if (linebuf.front() == '#') continue;
                if (auto eq_delim = linebuf.find_first_of('='); eq_delim != Str::npos) {
                    auto key   = linebuf.substr(0, eq_delim);
                    auto value = linebuf.substr(eq_delim + 1);
                    if (!deserialize_key_value(trim(key), trim(value))) {
                        CB_ERROR("Failed to deserialize key: `%s`, value: `%s`", key.c_str(), value.c_str());
                        return false;
                    }
                }
            }
            return true;
        }
    };

    enum class nr_status : int {
        ERR = -1,
        NO  = 0,
        YES,
    };
    // RETURNS:
    //  0 - does not to be needs rebuild
    //  1 - does needs rebuild
    // -1 - error. The error is logged
    template <size_t N>
    CB_FNDEF nr_status needs_rebuild(const char *output_path, Arr<const char *, N> input_paths) {
        if (!file_exists(output_path)) return nr_status::YES;
        std::error_code ec;
        auto            output_path_time = fs::last_write_time(output_path, ec);
        if (!on_errc(ec, "Failed to get last_write_time for file '%s'", output_path)) return nr_status::ERR;
        for (const auto &input_path : input_paths) {
            auto input_path_time = fs::last_write_time(input_path, ec);
            if (!on_errc(ec, "Failed to get last_write_time for file '%s'", input_path)) return nr_status::ERR;
            // NOTE: if even a single input_path is fresher than output_path that's
            // 100% rebuild
            if (input_path_time > output_path_time) return nr_status::YES;
        }
        return nr_status::NO;
    }
    /// config_t /////////////////////////////////////////////
    struct Config : public SerializeDeserialize {
        Build         build_type;
        Platform      platform_kind;
        Arch          arch_kind;
        Compiler      compiler_type;
        Program       program_type;
        bool          dump_compile_command;

        StrView       subcmd;
        Str           project_name;
        fs::path      project_path;
        fs::path      build_path;
        fs::path      build_artifact_path;
        fs::path      compiler_path;
        fs::path      config_path;
        fs::path      targets_path;

        fs::path      install_prefix;
        fs::path      bin_install_dir;
        fs::path      lib_install_dir;

        static Config create(const Str &name);

        constexpr bool inline is_debug() const { return (build_type == Build::DEBUG || build_type == Build::RELEASEDEBUG); }
        constexpr bool inline is_release() const { return (build_type == Build::RELEASE || build_type == Build::RELEASEDEBUG); }
        constexpr bool inline is_compiler_gnu() const { return (compiler_type == Compiler::GNU); }
        constexpr bool inline is_compiler_clang() const { return (compiler_type == Compiler::CLANG); }
        constexpr bool inline is_windows() const { return (platform_kind == Platform::WINDOWS); }

        void         set_install_prefix(const fs::path &prefix);
        void         set_build_path(const fs::path &path);
        void         set_compiler(const fs::path &cpath, Compiler ctype = Compiler::UNKNOWN);

        bool         parse_from_args(const Vec<StrView> args, const Map<StrView, callbacks_cb_t> &callbacks);

        virtual bool serialize(std::ostream &outstream) override;
        virtual bool deserialize_key_value(Str &key, Str &value) override;
        Status       save(const fs::path &path);
        Status       load(const fs::path &path);

        /// get extension str by *target_type_t*
        constexpr const char *get_ext(TargetType type) const noexcept {
            switch (type) {
                case TargetType::STATIC_LIB: return "a";
                case TargetType::DYNAMIC_LIB: return (platform_kind == Platform::WINDOWS) ? "dll" : "so";
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
        fs::path src;
        fs::path out;

        Source() = default;
        Source(const fs::path &dir, const fs::path &str);

        inline bool need_rebuild() const { return needs_rebuild<1>(out.c_str(), {src.c_str()}) == nr_status::YES; }
    };

    struct Target : public SerializeDeserialize {
        TargetType  type;
        Str         name;
        Source      file;
        fs::path    output_dir;

        Vec<Str>    flags;
        Vec<Str>    ldflags;
        Vec<Source> sources;

        virtual ~Target() override{};

        Target() = default;
        Target(Str name, TargetType type, const Config &cfg);
        Status        add_sources_with_ext(const fs::path &dir, const char *ext, bool recursive);
        virtual bool  serialize(std::ostream &out) override;
        virtual bool  deserialize_key_value(Str &key, Str &value) override;

        inline Status add_main_source(fs::path src) {
            std::error_code ec;
            file.src = fs::absolute(src, ec);
            return on_errc(ec, "Failed to get absolute path from %s", src.c_str()) ? Status::OK : Status::ERR;
        }

        inline Status add_source(fs::path src) {
            sources.emplace_back(output_dir, src);
            return Status::OK;
        }
        template <typename... Types>
        inline Status add_sources(Types... types) {
            Status res = Status::OK;
            for (const auto &t : {types...}) res &= add_source(t);
            return res;
        }
        template <typename... Types>
        inline Status add_flags(Types... types) {
            flags.insert(flags.end(), {types...});
            return Status::OK;
        }
        template <typename... Types>
        inline Status add_includes(const fs::path &p, const Types &...paths) {
            flags.push_back(format_str("-I%s", p.c_str()));
            Arr<Str, sizeof...(paths)> arrs{paths...};
            for (auto tp : arrs) flags.push_back(format_str("-I%s", tp.c_str()));
            return Status::OK;
        }

        template <typename... Types>
        inline Status add_defines(const Str &def, Types... types) {
            flags.push_back(format_str("-D%s", def.c_str()));
            Arr<Str, sizeof...(types)> arrs{types...};
            for (auto tp : arrs) flags.push_back(format_str("-D%s", tp.c_str()));
            return Status::OK;
        }

        template <typename... Types>
        inline Status add_ldflags(Types... types) {
            ldflags.insert(ldflags.end(), {types...});
            return Status::OK;
        }

        Status link_library(const std::shared_ptr<Target> tgt);
        template <typename... Types>
        inline Status link_libraries(const Types... types) {
            Status res = Status::OK;
            for (const auto &t : {types...})
                if (link_library(t) == Status::ERR) return Status::ERR;
            return res;
        }

        Cmd         into_cmd(const Config &cfg);
        Status      run(const Config &cfg);

        Status      install(fs::path install_dir);

        inline bool need_rebuild() const {
            if (!file_exists(file.out)) return true;
            return any_of(sources.begin(), sources.end(), [](const Source &s) { return s.need_rebuild(); });
        }

        size_t hash();

       private:
        size_t __hash;
    };

    struct target_hash {
        size_t operator()(const Target &tg) const noexcept;
    };

    /// cb_t /////////////////////////////////////////////
    struct Cb {
        Config                       cfg;
        Vec<std::shared_ptr<Target>> targets;
        Map<StrView, callbacks_cb_t> callbacks;

        Cb(const char *name);

        Status                  run(int argc, char **argv);

        std::shared_ptr<Target> create_target(Str name, TargetType type, const fs::path &source = "");
        std::shared_ptr<Target> create_target_pkgconf(Str name);

        /// helper of function [cb_t::create_target] for each TargetType
        inline std::shared_ptr<Target> create_exec(Str name, const fs::path &source = "") { return create_target(name, TargetType::EXEC, source); }
        inline std::shared_ptr<Target> create_static_lib(Str name) { return create_target(name, TargetType::STATIC_LIB); }
        inline std::shared_ptr<Target> create_dynamic_lib(Str name) { return create_target(name, TargetType::DYNAMIC_LIB); }

        inline void                    set_log_level(LogLevel lvl) const { g_log_level = lvl; }
        inline void                    dump_compile_commands(bool dump) { this->cfg.dump_compile_command = dump; }

        /// add callbacks for operation
        /// operation = [ "build", "config", "install", "clean" ]
        ///
        /// (is optional, if the callback for operation above is not set, it will defaulted to the
        /// static function in cb_t class to call)
        void add_callback(const StrView on, callbacks_cb_t cb) {
            CB_INFO("adding callback for event '%*s'", (int)on.size(), on.data());
            callbacks.insert_or_assign(on, cb);
        }

        Status save_targets();
        Status load_targets();

        void   targets_display();

        bool   is_builded() const;
        bool   is_configured() const;
        bool   is_targets_changed() const;

        size_t source_hash() const;

       private:
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

    static StrView     program_name     = __FILE__;
    static bool        g_display_config = false;
    LogLevel           g_log_level      = LogLevel::INFO;

    static inline bool case_cmp(char a, char b) { return toupper(a) == toupper(b); }
    static inline bool case_cmp(const StrView a, const StrView b) {
        return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin(), b.end(), [](char a, char b) { return case_cmp(a, b); });
    }

    template <typename T>
    struct EnumDisplay {
        Arr<StrView, static_cast<size_t>(T::MAX)> displays;

        template <typename... Targs>
        constexpr EnumDisplay(Targs... targs) : displays({targs...}) {
            static_assert(sizeof...(targs) == static_cast<size_t>(T::MAX), "size of enum is not equal to size of displays");
        }

        T parse(const StrView &needle) const {
            for (size_t idx = 0; idx < displays.size(); idx++) {
                if (case_cmp(needle, displays[idx]) && (idx < static_cast<size_t>(T::MAX))) {
                    return static_cast<T>(idx);
                }
            }
            CB_WARNING("Display parse is failed, defaulted to 0");
            return T(0);
        }
        Str operator[](T idx) const {
            auto d = displays[static_cast<size_t>(idx)];
            return Str{d.data(), d.size()};
        }
    };

    constexpr EnumDisplay<Build>      BUILD_TYPE_DISPLAY{"DEBUG", "RELEASE", "REDEBUG"};
    constexpr EnumDisplay<Platform>   PLATFORM_DISPLAY{"N/A", "WINDOWS", "MACOS", "UNIX"};
    constexpr EnumDisplay<Arch>       ARCH_DISPLAY{"N/A", "X64", "X86", "ARM64", "ARM32"};
    constexpr EnumDisplay<Compiler>   COMPILER_DISPLAY{"N/A", "CLANG", "GNU", "MSVC"};
    constexpr EnumDisplay<Program>    PROGRAM_DISPLAY{"N/A", "C", "CPP"};
    constexpr EnumDisplay<TargetType> TARGET_TYPE_DISPLAY{"executable", "staticlib", "dynamiclib", "systemlib"};
    constexpr EnumDisplay<LogLevel>   LOG_LEVEL_DISPLAY{"N/A", "INFO", "WARN", "ERROR", "FATAL"};

    static Status                     which_exec(const Str &exec, fs::path &out);
    static Status                     find_compiler(fs::path &compiler_path, const Config &cfg);
    static void                       compile_commands(Cb *cb);

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

    Status &operator&=(Status &lhs, const Status rhs) {
        lhs = (Status)(static_cast<uint8_t>(lhs) & static_cast<uint8_t>(rhs));
        return lhs;
    }

    Str format_str(const char *fmt, ...) {
        va_list args;
        va_start(args, fmt);

        va_list args_copy;
        va_copy(args_copy, args);
        const int len = vsnprintf(nullptr, 0, fmt, args_copy);
        va_end(args_copy);

        // return a formatted string without risking memory mismanagement
        // and without assuming any Compiler or Platform specific behavior
        Vec<char> zc(len + 1);
        vsnprintf(zc.data(), zc.size(), fmt, args);
        va_end(args);
        return Str(zc.data(), len);
    }

    void log(LogLevel level, const char *file, int line, Str msg) {
        std::cerr << LOG_LEVEL_DISPLAY[level] << ": ";
        std::cerr << file << ":" << line << ": " << msg << std::endl;
    }

    bool on_errc_impl(std::error_code &ec, Str msg) {
        if (ec.value() != 0) {
            std::cerr << "ERROR: " << msg << "- (" << ec.value() << ")"
                      << "Reason: " << ec.category().name() << " - " << ec.message() << std::endl;
            ec.clear();
            return false;
        }
        return true;
    }

    Str &ltrim(std::string &s) {
        s.erase(s.begin(), find_if_not(s.begin(), s.end(), ::isspace));
        return s;
    }
    Str &rtrim(std::string &s) {
        s.erase(find_if_not(s.rbegin(), s.rend(), ::isspace).base(), s.end());
        return s;
    }
    Str &trim(std::string &s) { return ltrim(rtrim(s)); }
    // trim from both ends (copying)
    std::string  trim_copy(std::string s) { return trim(s); }

    Vec<StrView> split(const StrView s, StrView delim) {
        size_t       pos_start = 0, pos_end, delim_len = delim.length();
        StrView      token;
        Vec<StrView> res;

        while ((pos_end = s.find(delim, pos_start)) != StrView::npos) {
            token     = s.substr(pos_start, pos_end - pos_start);
            pos_start = pos_end + delim_len;
            res.push_back(token);
        }
        res.push_back(s.substr(pos_start));
        return res;
    }

    bool file_rename(const Str old_path, const Str new_path) {
        CB_INFO("renaming %s -> %s", old_path.c_str(), new_path.c_str());
        std::error_code ec;
        fs::rename(old_path, new_path, ec);
        return on_errc(ec, "Failed to rename file %s to %s", old_path.c_str(), new_path.c_str());
    }

    bool file_exists(const fs::path &file_path) {
        std::error_code ec;
        auto            exists = fs::exists(file_path, ec);
        return exists && on_errc(ec, "Failed to check if file: '%s' is exists", file_path.c_str());
    }

    bool rebuild_self(int argc, char *argv[], const char *source_path) {
        CB_ASSERT(argc >= 1, "argc should be more than 1");
        const char *binary_path   = argv[0];
        nr_status   return_status = needs_rebuild<2>(binary_path, {source_path, __FILE__});

        if (return_status == nr_status::ERR) return false;
        if (return_status == nr_status::YES) {
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

    /// impl os operation /////////////////////////////////////////////
    bool mkdir_if_not_exists(const fs::path &path) {
        if (file_exists(path)) return true;

        CB_INFO("Creating directory '%s'", path.c_str());
        std::error_code ec;
        fs::create_directories(path, ec);
        return on_errc(ec, "Failed to create directory '%s'", path.c_str());
    }

    bool remove_dir_if_exists(const fs::path &dirpath) {
        CB_INFO("Removing directory '%s'", dirpath.c_str());
        std::error_code ec;
        fs::remove_all(dirpath, ec);
        return on_errc(ec, "Failed to remove directory '%s'", dirpath.c_str());
    }

    bool copy_file(const Str &dst_path, const Str &src_path) {
        using fs::copy_options;
        CB_INFO("Copying file from: %s => %s", src_path.c_str(), dst_path.c_str());
        std::error_code ec;
        auto            options = copy_options::update_existing | copy_options::overwrite_existing;
        fs::copy_file(src_path, dst_path, options, ec);
        return on_errc(ec, "Failed to copy file from '%s' => '%s'", src_path.c_str(), dst_path.c_str());
    }

    bool current_path(fs::path &out_path, const char *optional_append_path) {
        std::error_code ec;
        out_path = fs::current_path(ec);
        if (optional_append_path) out_path.append(optional_append_path);
        return on_errc(ec, "Failed to get current path");
    }
    fs::path path_to_absolute(const fs::path &path) {
        std::error_code ec;
        auto            out = fs::absolute(path, ec);
        on_errc(ec, "Failed to get abosulte path for '%s'", path.c_str());
        return out;
    }

    bool home_dir(fs::path &out_path, const char *optional_append_path) {
        char *home = nullptr;
#    if !defined(CB_WINDOWS)
        if ((home = getenv("HOME")) == nullptr) {
            home = getpwuid(getuid())->pw_dir;
            if (home == nullptr) CB_BAIL_ERROR(return false, "Failed to get Home directory!");
        }
        out_path = home;
#    else
        if ((home = getenv("USERPROFILE")) == nullptr) {
            CB_ERROR(
                "Failed to get env `USERPROFILE` try to get env `HOMEDRIVE` and "
                "`HOMEPATH`");
            char *drive = getenv("HOMEDRIVE");
            char *path  = getenv("HOMEPATH");
            if ((drive == nullptr) || (path == nullptr))
                CB_BAIL_ERROR(return false,
                                     "Failed to get env `HOMEDRIVE` or `HOMEPATH` "
                                     "to get fullpath to home directory");
            out_path = drive;
            out_path.append(path);
        }
#    endif  // CB_WINDOWS
        if (optional_append_path) out_path.append(optional_append_path);
        return true;
    }

    bool set_permissions(const fs::path &file, fs::perms permissions) {
        std::error_code ec;
        fs::permissions(file, permissions, ec);
        return on_errc(ec, "Failed to set permission for file '%s'", file.c_str());
    }

    bool walkdir(const fs::path &parent, bool recursive, WalkdirCallback callback) {
        bool result = true;
        DIR *dir    = opendir(parent.c_str());
        if (dir == nullptr) CB_BAIL_ERROR(return false, "Could not open directory %s: %s", parent.c_str(), strerror(errno));
        defer { closedir(dir); };

        fs::path       path;
        struct dirent *ent = nullptr;
        while ((ent = readdir(dir)) != nullptr) {
            if (ent->d_name[0] == '.') continue;
            if ((strcmp(ent->d_name, ".") == 0) || (strcmp(ent->d_name, "..") == 0)) continue;
            path = parent;
            path.append(ent->d_name);

            if (!callback(path)) {
                result = false;
                break;
            }
            if (fs::is_directory(path) && (recursive == true)) result &= walkdir(path, recursive, callback);
        }
        return result;
    }

    /// impl cb_proc_t | cb_procs_t /////////////////////////////////////////////
    bool procs_wait(const Procs &procs) { return std::all_of(procs.begin(), procs.end(), proc_wait); }
    bool proc_wait(proc_t proc) {
        if (proc == CB_INVALID_PROC) return false;
#    ifdef CB_WINDOWS
        defer { CloseHandle(proc); };
        DWORD result = WaitForSingleObject(proc, INFINITE);
        if (result == WAIT_FAILED) CB_BAIL_ERROR(return false, "could not wait on child process: %lu", GetLastError());
        DWORD exit_status;
        if (!GetExitCodeProcess(proc, &exit_status)) CB_BAIL_ERROR(return false, "could not get process exit code: %lu", GetLastError());
        if (exit_status != 0) CB_BAIL_ERROR(return false, "command exited with exit code %lu", exit_status);
#    else
        for (;;) {
            int wstatus = 0;
            if (waitpid(proc, &wstatus, 0) < 0) CB_BAIL_ERROR(return false, "could not wait on command (pid %d): %s", proc, strerror(errno));
            if (WIFEXITED(wstatus)) {
                int exit_status = WEXITSTATUS(wstatus);
                if (exit_status != 0) CB_BAIL_ERROR(return false, "command exited with exit code %d", exit_status);
                break;
            }
            if (WIFSIGNALED(wstatus)) CB_BAIL_ERROR(return false, "command process was terminated by %s", strsignal(WTERMSIG(wstatus)));
        }
        return true;
#    endif
    }
    /// impl cb_cmd_t /////////////////////////////////////////////
    proc_t cmd_run_async(Cmd &cmd) {
        if (cmd.size() < 1) CB_BAIL_ERROR(return CB_INVALID_PROC, "Could not run empty command");

        fprintf(stderr, "CMD: ");
        for (size_t i = 0; i < cmd.size(); ++i) {
            const char *arg = cmd[i];
            if (arg == nullptr) break;
            if (i > 0) fprintf(stderr, " ");
            if (!strchr(arg, ' ')) {
                fprintf(stderr, "%s", arg);
            } else {
                fprintf(stderr, "'%s'", arg);
            }
        }
        fprintf(stderr, CB_LINE_END);

#    ifdef CB_WINDOWS
        // https://docs.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output

        STARTUPINFO siStartInfo;
        ZeroMemory(&siStartInfo, sizeof(siStartInfo));
        siStartInfo.cb         = sizeof(STARTUPINFO);
        // NOTE: theoretically setting nullptr to std handles should not be a problem
        // https://docs.microsoft.com/en-us/windows/console/getstdhandle?redirectedfrom=MSDN#attachdetach-behavior
        // TODO: check for errors in GetStdHandle
        siStartInfo.hStdError  = GetStdHandle(STD_ERROR_HANDLE);
        siStartInfo.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
        siStartInfo.hStdInput  = GetStdHandle(STD_INPUT_HANDLE);
        siStartInfo.dwFlags |= STARTF_USESTDHANDLES;

        PROCESS_INFORMATION piProcInfo;
        ZeroMemory(&piProcInfo, sizeof(PROCESS_INFORMATION));
        defer { CloseHandle(piProcInfo.hThread); };

        std::string sb;
        std::for_each(cmd.begin(), cmd.end(), [&](const char *&piece) {
            sb += piece;
            sb += " ";
        });
        BOOL bSuccess = CreateProcessA(nullptr, sb.c_str(), nullptr, nullptr, TRUE, 0, nullptr, nullptr, &siStartInfo, &piProcInfo);

        if (!bSuccess) CB_BAIL_ERROR(return CB_INVALID_PROC, "Could not create child process: %lu", GetLastError());
        return piProcInfo.hProcess;
#    else
        pid_t cpid = fork();
        if (cpid < 0) CB_BAIL_ERROR(return CB_INVALID_PROC, "Could not fork child process: %s", strerror(errno));
        if (cpid == 0) {
            cmd.push_back(nullptr);
            if (execvp(cmd[0], (char *const *)cmd.data()) < 0) CB_BAIL_ERROR(exit(1), "Could not exec child process: %s", strerror(errno));
            CB_ASSERT(false, "unreachable");
        }
        return cpid;
#    endif
    }

    bool cmd_run(Cmd &cmd) {
        proc_t p = cmd_run_async(cmd);
        if (p == CB_INVALID_PROC) return false;
        return proc_wait(p);
    }

    Status popen_stdout(const Str &cmd, Str &stdout_content) {
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
        if (!CreatePipe(&stdout_read_, &stdout_write_, &sa, 0)) CB_BAIL_ERROR(return status::ERR, "Error creating pipes on Windows");

        ZeroMemory(&si, sizeof(STARTUPINFO));
        si.cb         = sizeof(STARTUPINFO);
        si.hStdError  = GetStdHandle(STD_ERROR_HANDLE);
        si.hStdOutput = stdout_write_;
        si.hStdInput  = GetStdHandle(STD_INPUT_HANDLE);
        si.dwFlags |= STARTF_USESTDHANDLES;

        ZeroMemory(&pi_info, sizeof(PROCESS_INFORMATION));
        if (!CreateProcessA(nullptr, cmd.c_str(), nullptr, nullptr, TRUE, 0, nullptr, nullptr, &si, &pi_info))
            CB_BAIL_ERROR(return status::ERR, "Could not create child process: %lu", GetLastError());

        DWORD bytesRead = 0;
        while (ReadFile(stdout_read_, buffer, 1 << 10, &bytesRead, nullptr) && bytesRead > 0) stdout_content.append(buffer, bytesRead);
#    else
        int   stdout_pipe[2];
        pid_t pid_proc;
        if (pipe(stdout_pipe) == -1) CB_BAIL_ERROR(return Status::ERR, "Error creating pipes on Linux")
        if ((pid_proc = fork()) < 0) CB_BAIL_ERROR(return Status::ERR, "Error forking process on Linux");

        if (pid_proc == 0) {
            dup2(stdout_pipe[1], STDOUT_FILENO);
            // Close unused pipe ends
            close(stdout_pipe[0]);
            close(stdout_pipe[1]);

            Cmd cmds{"/bin/sh", "-c", cmd.c_str(), nullptr};
            if (execvp(cmds[0], (char *const *)cmds.data()) < 0) CB_BAIL_ERROR(exit(EXIT_FAILURE), "Could not exec child process: %s", strerror(errno));
            exit(EXIT_SUCCESS);
        } else {  // Parent process
            close(stdout_pipe[1]);
        }
        defer {
            close(stdout_pipe[0]);
            if (pid_proc > 0) waitpid(pid_proc, nullptr, 0);
        };
        ssize_t bytes_read = 0;
        while ((bytes_read = read(stdout_pipe[0], buffer, 1 << 10)) > 0) stdout_content.append(buffer, bytes_read);

#    endif  // CB_WINDOWS
        return Status::OK;
    }

    static inline void print_help(const Map<StrView, callbacks_cb_t> &callbacks) {
        fprintf(stderr, "USAGE: %*s <SUBCOMMAND> [OPTIONS]" CB_LINE_END, SVArg(program_name));
        for (const auto &[key, _] : callbacks) fprintf(stderr, "   %*s %*s" CB_LINE_END, SVArg(program_name), SVArg(key));
        fprintf(stderr, CB_LINE_END "OPTIONS: " CB_LINE_END);
        fprintf(stderr,
                "   -ct, --compiler_type    set Compiler type   [clang, gnu, msvc] (defualt same as `cb.h` compiles "
                "to)" CB_LINE_END);
        fprintf(stderr,
                "   -c, --compiler          set Compiler        [path_to_compiler] (default will search Compiler "
                "type)" CB_LINE_END);
        fprintf(stderr,
                "   -b,  --build            set build type      [debug, release, relwithdebinfo]  (default to "
                "'debug')" CB_LINE_END);
        fprintf(stderr, "   -p,  --program          set program type    [C, CPP] (default to 'C')" CB_LINE_END);
        fprintf(stderr,
                "   -t,  --target           set target OS type  [windows, macos, unix] (default to current run "
                "OS)" CB_LINE_END);
        fprintf(stderr,
                "   -a,  --arch             set architecture    [X64, X86, ARM64, ARM32] (default to current run "
                "arch)" CB_LINE_END);
        fprintf(stderr, "   -h,  --help             print this help text" CB_LINE_END);
        fprintf(stderr, "   -q,  --quite            set output to quite" CB_LINE_END);
        fprintf(stderr, "   -d,  --display          display config  and target, will not start process" CB_LINE_END);
        fprintf(stderr, "        --release          set build type to release" CB_LINE_END);
        fprintf(stderr, "        --debug            set build type to debug" CB_LINE_END);
    }
    // clang-format on

#    define opt(l)     (arg == l)
#    define opts(s, l) ((arg == s) || (arg == l))

    Config Config::create(const Str &name) {
        Config cfg;
        cfg.project_name = name;
        if (!current_path(cfg.project_path)) {
            cfg.project_path = "./";
        };
        cfg.build_path = cfg.project_path;
        cfg.build_path.append("build");

        cfg.build_artifact_path = cfg.build_path;
        cfg.build_artifact_path.append(((cfg.is_release()) ? "release" : "debug"));

        cfg.config_path = cfg.build_path;
        cfg.config_path.append("config.cb");

        cfg.targets_path = cfg.build_path;
        cfg.targets_path.append("targets.cb");

        cfg.set_install_prefix(cfg.is_windows() ? "c:\\Program Files\\${PROJECT_NAME}" : "/usr");
        return cfg;
    }

    void Config::set_install_prefix(const fs::path &prefix) {
        install_prefix  = prefix;
        bin_install_dir = install_prefix;
        bin_install_dir.append("bin");
        lib_install_dir = install_prefix;
        lib_install_dir.append("lib");
    }
    void Config::set_build_path(const fs::path &path) {
        this->build_path          = path;
        this->build_artifact_path = build_path;
        this->build_artifact_path.append(((is_release()) ? "release" : "debug"));
    }
    void Config::set_compiler(const fs::path &cpath, Compiler ctype) {
        this->compiler_type = ctype;
        this->compiler_path = cpath;
    }

    bool Config::parse_from_args(const Vec<StrView> args, const Map<StrView, callbacks_cb_t> &callbacks) {
        program_name = args.front();

        if (file_exists(config_path)) {
            if (load(config_path) == Status::ERR) return false;
            CB_INFO("Success load config from '%s'", config_path.c_str());
        } else {
            mkdir_if_not_exists(build_path);
            mkdir_if_not_exists(build_artifact_path);
            if (save(config_path) == Status::OK) return false;
            CB_INFO("Success save default config to '%s'", config_path.c_str());
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
                    CB_ERROR("unknown arguments: '" SVFmt "' <" SVFmt ">", SVArg(arg), SVArg(arg_next));
                    print_help(callbacks);
                    return false;
                }
            } else {
                CB_ERROR("unknown arguments: '%*s'", (int)arg.size(), arg.data()); 
                print_help(callbacks);
                return false;
            }
            // clang-format on
        }

        if (compiler_path.empty() || last_ct != compiler_type) find_compiler(compiler_path, *this);
        if (is_changed()) {
            CB_INFO("Configuration changed, saving config to '%s'", config_path.c_str());
            return save(config_path) == Status::OK;
        }
        return true;
    }

    bool Config::serialize(std::ostream &out) {
        out << "build_type          = " << BUILD_TYPE_DISPLAY[build_type] << std::endl;
        out << "Platform            = " << PLATFORM_DISPLAY[platform_kind] << std::endl;
        out << "arch                = " << ARCH_DISPLAY[arch_kind] << std::endl;
        out << "compiler_type       = " << COMPILER_DISPLAY[compiler_type] << std::endl;
        out << "program_type        = " << PROGRAM_DISPLAY[program_type] << std::endl;
        out << "project_name        = " << project_name << std::endl;
        out << "project_path        = " << project_path.c_str() << std::endl;
        out << "build_path          = " << build_path.c_str() << std::endl;
        out << "build_artifact_path = " << build_artifact_path.c_str() << std::endl;
        out << "compiler_path       = " << compiler_path.c_str() << std::endl;
        out << "config_path         = " << config_path.c_str() << std::endl;
        out << "install_prefix      = " << install_prefix.c_str() << std::endl;
        out << "bin_install_dir     = " << bin_install_dir.c_str() << std::endl;
        out << "lib_install_dir     = " << lib_install_dir.c_str() << std::endl;
        return out.good();
    }
    // clang-format off
    bool Config::deserialize_key_value(Str &key, Str &v) {
        if      (key == "build_type")           build_type      = BUILD_TYPE_DISPLAY.parse(v);
        else if (key == "Platform")             platform_kind   = PLATFORM_DISPLAY.parse(v);
        else if (key == "arch")                 arch_kind       = ARCH_DISPLAY.parse(v);
        else if (key == "compiler_type")        compiler_type   = COMPILER_DISPLAY.parse(v);
        else if (key == "program_type")         program_type    = PROGRAM_DISPLAY.parse(v);
        else if (key == "project_name")         project_name    = v;
        else if (key == "project_path")         project_path    = v;
        else if (key == "build_path")           build_path      = v;
        else if (key == "build_artifact_path")  build_artifact_path = v;
        else if (key == "compiler_path")        compiler_path   = v;
        else if (key == "config_path")          config_path     = v;
        else if (key == "install_prefix")       install_prefix  = v;
        else if (key == "bin_install_dir")      bin_install_dir = v;
        else if (key == "lib_install_dir")      lib_install_dir = v;
        else {
            CB_WARNING("Unknown key '%s' on configuration file", key.c_str());
            return false;
        }
        return true;
    }
    // clang-format on

    Status Config::save(const fs::path &path) {
        try {
            std::ofstream out(path);
            if (!out) {
                CB_ERROR("Failed to open config file '%s'", path.c_str());
                return Status::ERR;
            }
            if (!this->serialize(out)) {
                CB_ERROR("Failed to write config file '%s'", path.c_str());
                return Status::ERR;
            }
            __hash = hash();
        } catch (const std::exception &e) {
            CB_ERROR("Failed to open file config '%s' - %s", path.c_str(), e.what());
            return Status::ERR;
        }
        return Status::OK;
    }
    Status Config::load(const fs::path &path) {
        if (!file_exists(path)) CB_BAIL_ERROR(return Status::ERR, "File config '%s' is not exists", path.c_str());
        try {
            std::ifstream in(path);
            if (!in) {
                CB_ERROR("Failed to open config file '%s'", path.c_str());
                return Status::ERR;
            }
            if (!this->deserialize(in)) {
                CB_ERROR("Failed to deserialize file '%s'", path.c_str());
                return Status::ERR;
            }
            __hash = hash();
        } catch (const std::exception &e) {
            CB_ERROR("Failed to open file config '%s' - %s", path.c_str(), e.what());
            return Status::ERR;
        }
        return Status::OK;
    }

    size_t Config::hash() const {
        size_t seed = 0;
        hash_combine<uint8_t>(seed, (uint8_t)build_type, (uint8_t)platform_kind, (uint8_t)arch_kind, (uint8_t)compiler_type, (uint8_t)program_type);
        hash_combine(seed, project_name);
        hash_combine<fs::path>(seed, project_path, build_path, build_artifact_path, compiler_path, config_path, targets_path, install_prefix, bin_install_dir,
                               lib_install_dir);
        return seed;
    }
    bool Config::is_changed() const { return hash() != __hash; }

    Source::Source(const fs::path &dir, const fs::path &src) : src(path_to_absolute(src)), out(dir) {
        out.append(src.filename().c_str());
        out.replace_extension(".o");
    }

    Target::Target(Str name, TargetType ty, const Config &cfg) : SerializeDeserialize(), type(ty), name(name), flags(), ldflags(), sources() {
        output_dir = cfg.build_artifact_path;
        output_dir.append(name);
        file.out        = output_dir;

        const char *ext = cfg.get_ext(ty);
        if (TargetType::STATIC_LIB == ty || ty == TargetType::DYNAMIC_LIB) {
            file.out.append(Str("lib") + name.data());
            file.out.replace_extension(ext);
        } else if (ty == TargetType::EXEC) {
            file.out.append(name);
        }
    }

    Status Target::add_sources_with_ext(const fs::path &dir, const char *ext, bool recursive) {
        auto ret = walkdir(dir, recursive, [this, ext](const fs::path &p) {
            if (case_cmp(p.extension().generic_string(), ext)) this->add_source(p);
            return true;
        });
        return ret ? Status::OK : Status::ERR;
    }

    inline void serialize_vec_source(std::ostream &out, const char *name, const Vec<Source> &vecs) {
        out << name;
        for (size_t i = 0; i < vecs.size(); i++) {
            const auto &s = vecs[i];
            out << '{' << (s.src.empty() ? "" : s.src.string()) << ',';
            out << (s.out.empty() ? "" : s.out.string()) << '}';
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
            close       = v.find('}', open + 1);
            auto inside = v.substr(open + 1, close - open - 1);
            if (auto comma = trim(inside).find_first_of(','); comma != Str::npos) {
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
        while ((end = v.find(',', start)) != std::string::npos) {
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
        out << "target.output_dir=" << (output_dir.empty() ? "" : output_dir.string()) << std::endl;
        out << "target.output=" << (file.out.empty() ? "" : file.out.string()) << std::endl;
        out << "target.source=" << (file.src.empty() ? "" : file.src.string()) << std::endl;
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

    Status Target::link_library(const std::shared_ptr<Target> tgt) {
        switch (tgt->type) {
            case TargetType::SYSTEM_LIB: {
                for (const auto &ld : tgt->ldflags) {
                    if (ld.compare(0, 2, "-I") == 0) {
                        flags.push_back(ld);
                    } else {
                        ldflags.push_back(ld);
                    }
                }
            } break;
            case TargetType::STATIC_LIB: ldflags.push_back("-static"); [[fallthrough]];
            case TargetType::DYNAMIC_LIB: {
                ldflags.insert(ldflags.end(), tgt->ldflags.begin(), tgt->ldflags.end());
                ldflags.insert(flags.end(), tgt->flags.begin(), tgt->flags.end());
                add_flags(Str(Str("-L") + tgt->name.data()), Str(Str("-l") + tgt->file.out.c_str()));
            } break;
            default: CB_ASSERT(false, "cb_target_link_library does not accept lib->type thats not equal to library type"); break;
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

        std::for_each(sources.begin(), sources.end(), [&](const Source &s) { c.push_back(s.out.c_str()); });
        std::for_each(ldflags.begin(), ldflags.end(), str_inserter);

        return c;
    }

    Status Target::run(const Config &cfg) {
        if (!this->need_rebuild()) return Status::OK;
        CB_INFO("Running target %*s", (int)name.size(), name.data());
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
                CB_ERROR("cmd_run_async returned invalid proc");
                result = Status::ERR;
            } else {
                procs.push_back(p);
            }
            cmd.resize(save_idx);
        }
        if (!procs_wait(procs)) CB_BAIL_ERROR(return Status::ERR, "Failed to wait process of procs_t");
        if (result == Status::ERR) return result;

        cmd = this->into_cmd(cfg);
        if (!cmd_run(cmd)) CB_BAIL_ERROR(return Status::ERR, "Failed to run sync cmd");
        return result;
    }

    constexpr fs::perms EXEC_PERMS =
        (fs::perms::owner_all | fs::perms::group_read | fs::perms::group_exec | fs::perms::others_read | fs::perms::others_exec) & fs::perms::mask;
    Status Target::install(fs::path install_path) {
        if (file.out.empty() || !file_exists(file.out)) {
            CB_ERROR("File output is empty or not exists for target '%s'", name.c_str());
            CB_ERROR("build it first before installing!");
            return Status::ERR;
        }
        install_path.append(this->name);
        if (!cb::copy_file(install_path, file.out)) return Status::ERR;
        if (type == TargetType::EXEC) set_permissions(install_path, EXEC_PERMS);
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
        for (const auto &[source, output] : tg.sources) hash_combine(seed, source, output);
        return seed;
    }

    Cb::Cb(const char *name) : cfg(Config::create(name)), targets(), callbacks() {}

    std::shared_ptr<Target> Cb::create_target(Str name, TargetType type, const fs::path &source) {
        auto tgt = std::make_shared<Target>(name, type, cfg);
        if (!source.empty()) {
            if (tgt->add_main_source(source) == Status::ERR) {
                return nullptr;
            }
        }
        return targets.emplace_back(tgt);
    }

    std::shared_ptr<Target> Cb::create_target_pkgconf(Str name) {
#    ifdef CB_WINDOWS
        CB_ERROR("cb_create_target_pkgconf is not supported in windows");
        return nullptr;
#    else
        auto tgt = std::make_shared<Target>(name, TargetType::SYSTEM_LIB, cfg);
        Str  cmd("/usr/bin/pkg-config --cflags --libs " + name);

        Str  contents_buff;
        contents_buff.reserve(2 << 10);
        if (popen_stdout(cmd, contents_buff) != Status::OK) CB_BAIL_ERROR(return nullptr, "Failed to procecss open cmd: '%s'", cmd.c_str());

        char *data  = contents_buff.data();
        char *token = nullptr;
        token       = strtok(data, " \n\t");
        while (token != nullptr) {
            if (!(token[0] == '\n' || token[0] == '\t' || token[0] == ' ')) {
                tgt->ldflags.push_back(token);
            }
            token = strtok(nullptr, " ");
        }
        targets.push_back(tgt);
        return targets.back();
#    endif
    }

    Status Cb::save_targets() {
        try {
            std::ofstream out(cfg.targets_path);
            if (!out) {
                CB_ERROR("Failed to open targets file '%s'", cfg.targets_path.c_str());
                return Status::ERR;
            }
            out << "target_count=" << targets.size() << std::endl;
            for (size_t i = 0; (i < targets.size()) && out.good(); ++i) {
                if (!targets[i]->serialize(out)) break;
                if (i != targets.size() - 1) {
                    out << "----";
                }
                out << std::endl;
            }
            if (!out.good()) out.exceptions(out.rdstate());
            __source_hashes = source_hash();
        } catch (const std::ios_base::failure &e) {
            CB_ERROR("Failed to save target '%s' - [(%d): %s]", cfg.targets_path.c_str(), e.code().value(), e.what());
            return Status::ERR;
        } catch (const std::exception &e) {
            CB_ERROR("Failed to save target '%s' - [%s]", cfg.targets_path.c_str(), e.what());
            return Status::ERR;
        }
        return Status::OK;
    }
    static Str read_to_string(std::ifstream &ifs, const fs::path &file) {
        try {
            ifs.seekg(0, std::ios::end);
            std::ifstream::pos_type sz = ifs.tellg();
            ifs.seekg(0, std::ios::beg);
            Str bytes(sz, '\0');
            ifs.read(bytes.data(), sz);

            if (!ifs.good()) ifs.exceptions(ifs.rdstate());
            return bytes;
        } catch (const std::exception &e) {
            CB_ERROR("Failed to load target configuration '%s' - %s", file.c_str(), e.what());
            return "";
        }
    }

    Status Cb::load_targets() {
        if (!file_exists(cfg.targets_path))
            CB_BAIL_ERROR(return Status::ERR, "no targets available, use command 'config' as subcommand to initiate project configuration");
        try {
            std::ifstream ifs(cfg.targets_path);
            Str           content         = read_to_string(ifs, cfg.targets_path);
            Vec<StrView>  targets_content = split(content, "----");

            for (const auto tg : targets_content) {
                if (tg.empty()) continue;
                auto target = std::make_shared<Target>();
                for (const auto line : split(tg, "\n")) {
                    if (line.empty() || line.front() == '#') continue;
                    if (auto eq_delim = line.find_first_of('='); eq_delim != StrView::npos) {
                        Str key{line.substr(0, eq_delim)};
                        Str value{line.substr(eq_delim + 1)};
                        if (key == "target_count") {
                            this->targets.reserve(std::atol(value.c_str()));
                            continue;
                        }
                        target->deserialize_key_value(key, value);
                    }
                }
                this->targets.push_back(target);
            }

            __source_hashes = source_hash();
        } catch (const std::exception &e) {
            CB_ERROR("Failed to load target configuration '%s' - %s", cfg.targets_path.c_str(), e.what());
            return Status::ERR;
        }
        return Status::OK;
    }

    template <typename V>
    static inline void display_vec(const char *name, const Vec<V> values, std::function<void(const V &)> on_values) {
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
            printf("=====================================================" CB_LINE_END);
            Str type = TARGET_TYPE_DISPLAY[t->type];
            printf("cb.targets.type       = %s" CB_LINE_END, type.c_str());
            printf("cb.targets.name       = %s" CB_LINE_END, t->name.c_str());
            if (t->type != TargetType::SYSTEM_LIB) {
                printf("cb.targets.output_dir = '%s'" CB_LINE_END, t->output_dir.c_str());
                printf("cb.targets.output     = '%s'" CB_LINE_END, t->file.out.c_str());
                printf("cb.targets.source     = '%s'" CB_LINE_END, t->file.src.c_str());
            }
            display_vec<Str>("flags", t->flags, [](const Str &v) { printf("%s", v.c_str()); });
            display_vec<Str>("ldflags", t->ldflags, [](const Str &v) { printf("%s", v.c_str()); });
            if (t->type != TargetType::SYSTEM_LIB) {
                display_vec<Source>("includes", t->sources, [](const Source &v) { printf("{src: %s, out: %s}", v.src.c_str(), v.out.c_str()); });
            }
            printf(CB_LINE_END);
        }
        printf(CB_LINE_END);
    }

    bool Cb::is_builded() const {
        return !std::all_of(targets.begin(), targets.end(), [](const std::shared_ptr<Target> &t) { return t->need_rebuild(); });
    }
    bool Cb::is_configured() const {
        bool            ret = true;
        std::error_code ec;
        ret = fs::exists(cfg.config_path, ec) && fs::exists(cfg.targets_path, ec);
        ret = !fs::is_empty(cfg.config_path, ec) && !fs::is_empty(cfg.targets_path, ec);
        return on_errc(ec, "Failed to check if file is exists and not empty") && ret;
    }
    bool   Cb::is_targets_changed() const { return source_hash() != __source_hashes; }
    size_t Cb::source_hash() const {
        size_t seed = 0;
        for (const auto &tg : targets) {
            if (tg) hash_combine<Target, target_hash>(seed, *tg);
        }
        return seed;
    }

    Status Cb::m_on_build_target(Cb *cb) {
        if (auto c = cb->callbacks.find("build"); (c != cb->callbacks.end() && c->second != nullptr)) {
            return c->second(cb);
        }

        for (const auto &tg : cb->targets) {
            if (tg->type == TargetType::SYSTEM_LIB || tg->type == TargetType::EXEC) continue;
            mkdir_if_not_exists(tg->output_dir);
            if (tg->run(cb->cfg) == Status::ERR) CB_BAIL_ERROR(return Status::ERR, "failed to run target: '%s'", tg->name.c_str());
        }

        for (const auto &tg : cb->targets) {
            if (tg->type == TargetType::EXEC) {
                mkdir_if_not_exists(tg->output_dir);
                if (tg->run(cb->cfg) == Status::ERR) CB_BAIL_ERROR(return Status::ERR, "failed to run target: '%s'", tg->name.c_str());
            }
        }

        return Status::OK;
    }

    Status Cb::m_on_config_target(Cb *cb) {
        if (auto callback = cb->callbacks.find("config"); (callback != cb->callbacks.end()) && (callback->second != nullptr))
            callback->second(cb);
        else {
            fs::path def_source_path = cb->cfg.project_path;
            def_source_path.append("src");
            fs::path def_include_path = cb->cfg.project_path;
            def_include_path.append("include");

            auto exec = cb->create_exec(cb->cfg.project_name);
            exec->add_sources_with_ext(cb->cfg.project_path, program_ext(cb->cfg.program_type), true);
            exec->add_includes(def_include_path);
            exec->add_flags("-Wall", "-Wextra", "-Werror", "-pedantic");
        }

        if (cb->cfg.is_changed()) {
            if (cb->cfg.save(cb->cfg.config_path) == Status::ERR) CB_BAIL_ERROR(return Status::ERR, "Failed to save config");
            CB_INFO("(CB) - Saving Configuration to '%s'", cb->cfg.config_path.c_str());
        }
        if (cb->is_targets_changed()) {
            if (cb->save_targets() == Status::ERR) return Status::ERR;
            CB_INFO("(CB) - Saving Targets Information to '%s'", cb->cfg.targets_path.c_str());
        }

        if (cb->cfg.dump_compile_command) {
            compile_commands(cb);
        }

        return Status::OK;
    }

    Status Cb::m_on_install_target(Cb *cb) {
        if (auto callback = cb->callbacks.find("install"); (callback != cb->callbacks.end()) && (callback->second != nullptr)) {
            return callback->second(cb);
        }

        if (cb->cfg.install_prefix.empty()) {
            CB_BAIL_ERROR(return Status::ERR,
                                 "cfg.install_prefix should set to install, set the prefix with "
                                 "`cb_config_set_install_prefix` function");
        }
#    ifdef CB_UNIX
        if (cb->cfg.install_prefix.root_path() == "/")
            if (getuid() != 0) CB_BAIL_ERROR(return Status::ERR, "Command install requires Admin Privilages!");
#    endif

        bool result;
        result = mkdir_if_not_exists(cb->cfg.bin_install_dir);
        result = mkdir_if_not_exists(cb->cfg.lib_install_dir);
        if (!result) return Status::ERR;

        Status sts = Status::OK;
        for (const auto &tg : cb->targets) {
            if (tg->type == TargetType::SYSTEM_LIB) continue;
            sts &= tg->install(cb->cfg.bin_install_dir);
        }
        return sts;
    }
    Status Cb::m_on_clean_target(Cb *cb) {
        if (auto callback = cb->callbacks.find("clean"); (callback != cb->callbacks.end()) && (callback->second != nullptr)) return callback->second(cb);

        bool is_ok = remove_dir_if_exists(cb->cfg.build_artifact_path);
        if (!is_ok) CB_BAIL_ERROR(return Status::ERR, "Failed to remove directory");
        return Status::OK;
    }

    Status Cb::run(int argc, char **argv) {
        cfg.parse_from_args({argv, argv + argc}, this->callbacks);
        mkdir_if_not_exists(cfg.build_path);
        mkdir_if_not_exists(cfg.build_artifact_path);

        if (cfg.subcmd == "build") {
            if (load_targets() == Status::ERR) return Status::ERR;
            CB_INFO("(CB) - Running Build");
            if (m_on_build_target(this) == Status::ERR) return Status::ERR;
            if (g_display_config) {
                cfg.serialize(std::cerr);
                targets_display();
            }
            CB_INFO("(CB) - Finish Build");
        } else if (cfg.subcmd == "config") {
            CB_INFO("(CB) - Running Configure");
            if (m_on_config_target(this) == Status::ERR) return Status::ERR;
            if (g_display_config) {
                cfg.serialize(std::cerr);
                targets_display();
            }
            CB_INFO(
                "(CB) - Success Configuring Project, run `build` or `tests` to "
                "build and run tests");
        } else if (cfg.subcmd == "clean") {
            if (m_on_clean_target(this) == Status::ERR) return Status::ERR;
        } else if (cfg.subcmd == "install") {
            CB_INFO("(CB) - Running Install");
            cfg.build_type = Build::RELEASE;

            if (!is_builded())
                if (m_on_config_target(this) == Status::ERR) return Status::ERR;
            if (!is_configured())
                if (m_on_build_target(this) == Status::ERR) return Status::ERR;

            if (auto cb = callbacks.find("install"); (cb != callbacks.end()) && (cb->second != nullptr)) {
                if ((cb->second)(this) == Status::ERR) return Status::ERR;
            } else {
                if (m_on_install_target(this) == Status::ERR) return Status::ERR;
            }
            CB_INFO("(CB) - Success Running Install");
        } else {
            if (g_display_config) {
                cfg.serialize(std::cerr);
                targets_display();
            }
            if (auto item = callbacks.find(cfg.subcmd); item != callbacks.end()) {
                return item->second(this);
            }
        }
        return Status::OK;
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
            // TODO: opendir should set errno accordingly on FindFirstFile fail
            // https://docs.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-getlasterror
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
                    // TODO: readdir should set errno accordingly on
                    // FindNextFile fail
                    // https://docs.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-getlasterror
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
            // TODO: closedir should set errno accordingly on FindClose fail
            // https://docs.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-getlasterror
            errno = ENOSYS;
            return -1;
        }
        if (dirp->dirent) CB_FREE(dirp->dirent);
        CB_FREE(dirp);
        return 0;
    }

    // COM objects for the ridiculous Microsoft craziness.

    struct DECLSPEC_UUID("B41463C3-8866-43B5-BC33-2B0676F7F42E") DECLSPEC_NOVTABLE ISetupInstance : public IUnknown {
        STDMETHOD(GetInstanceId)(_Out_ BSTR *pbstrInstanceId)                                        = 0;
        STDMETHOD(GetInstallDate)(_Out_ LPFILETIME pInstallDate)                                     = 0;
        STDMETHOD(GetInstallationName)(_Out_ BSTR *pbstrInstallationName)                            = 0;
        STDMETHOD(GetInstallationPath)(_Out_ BSTR *pbstrInstallationPath)                            = 0;
        STDMETHOD(GetInstallationVersion)(_Out_ BSTR *pbstrInstallationVersion)                      = 0;
        STDMETHOD(GetDisplayName)(_In_ LCID lcid, _Out_ BSTR *pbstrDisplayName)                      = 0;
        STDMETHOD(GetDescription)(_In_ LCID lcid, _Out_ BSTR *pbstrDescription)                      = 0;
        STDMETHOD(ResolvePath)(_In_opt_z_ LPCOLESTR pwszRelativePath, _Out_ BSTR *pbstrAbsolutePath) = 0;
    };

    struct DECLSPEC_UUID("6380BCFF-41D3-4B2E-8B2E-BF8A6810C848") DECLSPEC_NOVTABLE IEnumSetupInstances : public IUnknown {
        STDMETHOD(Next)
        (_In_ ULONG celt, _Out_writes_to_(celt, *pceltFetched) ISetupInstance **rgelt, _Out_opt_ _Deref_out_range_(0, celt) ULONG *pceltFetched) = 0;
        STDMETHOD(Skip)(_In_ ULONG celt)                                                                                                         = 0;
        STDMETHOD(Reset)(void)                                                                                                                   = 0;
        STDMETHOD(Clone)(_Deref_out_opt_ IEnumSetupInstances **ppenum)                                                                           = 0;
    };

    struct DECLSPEC_UUID("42843719-DB4C-46C2-8E7C-64F1816EFD5B") DECLSPEC_NOVTABLE ISetupConfiguration : public IUnknown {
        STDMETHOD(EnumInstances)(_Out_ IEnumSetupInstances **ppEnumInstances)                   = 0;
        STDMETHOD(GetInstanceForCurrentProcess)(_Out_ ISetupInstance **ppInstance)              = 0;
        STDMETHOD(GetInstanceForPath)(_In_z_ LPCWSTR wzPath, _Out_ ISetupInstance **ppInstance) = 0;
    };

    // The beginning of the actual code that does things.

    struct Version_Data {
        int32_t  best_version[4];  // For Windows 8 versions, only two of these numbers are used.
        wchar_t *best_name;
    };

    static bool os_file_exists(wchar_t *name) {
        // @Robustness: What flags do we really want to check here?

        auto attrib = GetFileAttributesW(name);
        if (attrib == INVALID_FILE_ATTRIBUTES) return false;
        if (attrib & FILE_ATTRIBUTE_DIRECTORY) return false;

        return true;
    }

    static wchar_t *concat(wchar_t *a, wchar_t *b, wchar_t *c = nullptr, wchar_t *d = nullptr) {
        // Concatenate up to 4 wide strings together. Allocated with malloc.
        // If you don't like that, use a programming language that actually
        // helps you with using custom allocators. Or just edit the code.

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
        // Visit everything in one folder (non-recursively). If it's a directory
        // that doesn't start with ".", call the visit proc on it. The visit proc
        // will see if the filename conforms to the expected versioning pattern.

        auto wildcard_name = concat(dir_name, L"\\*");
        defer { free(wildcard_name); };

        WIN32_FIND_DATAW find_data;
        auto             handle = FindFirstFileW(wildcard_name, &find_data);
        if (handle == INVALID_HANDLE_VALUE) return false;

        while (true) {
            if ((find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && (find_data.cFileName[0] != '.')) {
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
        // Returns nullptr if read failed.
        // Otherwise returns a wide string allocated via 'malloc'.

        //
        // If the registry data changes between the first and second calls to RegQueryValueExW,
        // we may fail to get the entire key, even though it told us initially that our buffer length
        // would be big enough. The only solution is to keep looping until we don't fail.
        //

        DWORD required_length;
        auto  rc = RegQueryValueExW(key, value_name, nullptr, nullptr, nullptr, &required_length);
        if (rc != 0) return nullptr;

        wchar_t *value;
        DWORD    length;
        while (1) {
            length = required_length + 2;            // The +2 is for the maybe optional zero later on. Probably we are over-allocating.
            value  = (wchar_t *)malloc(length + 2);  // This second +2 is for crazy situations where there are race
                                                     // conditions or the API doesn't do what we want!
            if (!value) return nullptr;

            DWORD type;
            rc = RegQueryValueExW(key, value_name, nullptr, &type, (LPBYTE)value,
                                  &length);  // We know that version is zero-terminated...
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

        // The documentation says that if the string for some reason was not stored
        // with zero-termination, we need to manually terminate it. Sigh!!

        auto num_wchars   = length / 2;
        value[num_wchars] = 0;  // If the string was already zero-terminated, this just puts an extra 0 after (since that 0 was counted
                                // in 'length'). If it wasn't, this puts a 0 after the nonzero characters we got.

        return value;
    }

    static void win10_best(wchar_t *short_name, wchar_t *full_name, Version_Data *data) {
        // Find the Windows 10 subdirectory with the highest version number.

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

        // we have to copy_string and free here because visit_files free's the full_name string
        // after we execute this function, so Win*_Data would contain an invalid pointer.
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

        // we have to copy_string and free here because visit_files free's the full_name string
        // after we execute this function, so Win*_Data would contain an invalid pointer.
        if (data->best_name) free(data->best_name);
        data->best_name = _wcsdup(full_name);

        if (data->best_name) {
            data->best_version[0] = i0;
            data->best_version[1] = i1;
        }
    }

    static void find_windows_kit_root(Find_Result *result) {
        // Information about the Windows 10 and Windows 8 development kits
        // is stored in the same place in the registry. We open a key
        // to that place, first checking preferntially for a Windows 10 kit,
        // then, if that's not found, a Windows 8 kit.

        HKEY main_key;

        auto rc = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows Kits\\Installed Roots", 0,
                                KEY_QUERY_VALUE | KEY_WOW64_32KEY | KEY_ENUMERATE_SUB_KEYS, &main_key);
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

    static bool find_visual_studio_2017_by_fighting_through_microsoft_craziness(Find_Result *result) {
        // The name of this procedure is kind of cryptic. Its purpose is
        // to fight through Microsoft craziness. The things that the fine
        // Visual Studio team want you to do, JUST TO FIND A SINGLE FOLDER
        // THAT EVERYONE NEEDS TO FIND, are ridiculous garbage.

        // For earlier versions of Visual Studio, you'd find this information in the registry,
        // similarly to the Windows Kits above. But no, now it's the future, so to ask the
        // question "Where is the Visual Studio folder?" you have to do a bunch of COM object
        // instantiation, enumeration, and querying. (For extra bonus points, try doing this in
        // a new, underdeveloped programming language where you don't have COM routines up
        // and running yet. So fun.)
        //
        // If all this COM object instantiation, enumeration, and querying doesn't give us
        // a useful result, we drop back to the registry-checking method.

        auto rc                                       = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        // "Subsequent valid calls return false." So ignore false.
        // if rc != S_OK  return false;

        GUID                 my_uid                   = {0x42843719, 0xDB4C, 0x46C2, {0x8E, 0x7C, 0x64, 0xF1, 0x81, 0x6E, 0xFD, 0x5B}};
        GUID                 CLSID_SetupConfiguration = {0x177F0C4A, 0x1CD3, 0x4DE7, {0xA3, 0x2C, 0x71, 0xDB, 0xBB, 0x9F, 0xA3, 0x6D}};

        ISetupConfiguration *config                   = nullptr;
        auto                 hr                       = CoCreateInstance(CLSID_SetupConfiguration, nullptr, CLSCTX_INPROC_SERVER, my_uid, (void **)&config);
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

            auto tools_filename = concat(bstr_inst_path, L"\\VC\\Auxiliary\\Build\\Microsoft.VCToolsVersion.default.txt");
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

            auto version_bytes = (tools_file_size.QuadPart + 1) * 2;  // Warning: This multiplication by 2 presumes there is no variable-length encoding
                                                                      // in the wchars (wacky characters in the file could betray this expectation).
            wchar_t *version   = (wchar_t *)malloc(version_bytes);
            defer { free(version); };

            auto read_result = fgetws(version, version_bytes, f);
            if (!read_result) continue;

            auto version_tail = wcschr(version, '\n');
            if (version_tail) *version_tail = 0;  // Stomp the data, because nobody cares about it.

            auto library_path = concat(bstr_inst_path, L"\\VC\\Tools\\MSVC\\", version, L"\\lib\\x64");
            auto library_file = concat(library_path, L"\\vcruntime.lib");  // @Speed: Could have library_path point to this string, with
                                                                           // a smaller count, to save on memory flailing!

            if (os_file_exists(library_file)) {
                auto link_exe_path      = concat(bstr_inst_path, L"\\VC\\Tools\\MSVC\\", version, L"\\bin\\Hostx64\\x64");
                result->vs_exe_path     = link_exe_path;
                result->vs_library_path = library_path;
                return true;
            }

            /*
               Ryan Saunderson said:
               "Clang uses the 'SetupInstance->GetInstallationVersion' / ISetupHelper->ParseVersion to find the newest
               version and then reads the tools file to define the tools path - which is definitely better than what i
               did."

               So... @Incomplete: Should probably pick the newest version...
            */
        }

        // If we get here, we didn't find Visual Studio 2017. Try earlier versions.
        return false;
    }

    static void find_visual_studio_by_fighting_through_microsoft_craziness(Find_Result *result) {
        bool found_visual_studio_2017 = find_visual_studio_2017_by_fighting_through_microsoft_craziness(result);
        if (found_visual_studio_2017) return;

        HKEY vs7_key;
        auto rc = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\VisualStudio\\SxS\\VS7", 0, KEY_QUERY_VALUE | KEY_WOW64_32KEY, &vs7_key);

        if (rc != S_OK) return;
        defer { RegCloseKey(vs7_key); };

        // Hardcoded search for 4 prior Visual Studio versions. Is there something better to do here?
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

        // If we get here, we failed to find anything.
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
        int      windows_sdk_version           = 0;  // Zero if no Windows SDK found.
        wchar_t *windows_sdk_root              = nullptr;
        wchar_t *windows_sdk_um_library_path   = nullptr;
        wchar_t *windows_sdk_ucrt_library_path = nullptr;

        wchar_t *vs_exe_path                   = nullptr;
        wchar_t *vs_library_path               = nullptr;
    };

    static Find_Result find_visual_studio_and_windows_sdk() { return Find_Result(); }
    static void        free_resources(Find_Result *result) { (void)result; }

#    endif  // CB_WINDOWS

    Status which_exec(const Str &exec, fs::path &out) {
        CB_INFO("Searching full path of executable: `%*s`", (int)exec.size(), exec.data());
        out.clear();

        char *paths = getenv("PATH");
        if (paths == nullptr) CB_BAIL_ERROR(return Status::ERR, "$PATH environment variable not set.\n");

        const char *token;
        while ((token = strsep(&paths, ":")) != nullptr) {
            walkdir(token, false, [&](const fs::path &path) {
                if (exec.compare(path.filename().c_str()) == 0) {
                    CB_INFO("Found which path: %s", path.c_str());
                    out = path;
                    return false;
                }
                return true;
            });
            if (!out.empty()) {
                CB_INFO("Found Program `%s` in $PATH: `%s`", exec.c_str(), out.c_str());
                return Status::OK;
            }
        }

        CB_ERROR("Program in $PATH for: `%s` is NotFound", exec.c_str());
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

    Status find_compiler(fs::path &compiler_path, const Config &cfg) {
        Status result = Status::OK;
        switch (cfg.compiler_type) {
            case Compiler::MSVC: {
                Find_Result msvc_find_result = find_visual_studio_and_windows_sdk();
                defer { free_resources(&msvc_find_result); };

                if (msvc_find_result.windows_sdk_version > 0 && msvc_find_result.vs_exe_path != nullptr) {
                    compiler_path = msvc_find_result.vs_exe_path;
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
            CB_INFO("Failed to get program path for: Compiler `%s`", COMPILER_DISPLAY[cfg.compiler_type].c_str());
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

    struct JsonWriter {
        JsonWriter(std::ostream &w) : m_writer(w), m_states({State::Root}) {}

        void sep() { m_writer << ','; }
        void begin_list(const Str &name = "") {
            m_begin_group(name, '[');
            m_states.push(State::List);
        }
        void end_list() {
            m_end_group(']');
            m_states.pop();
        }

        void begin_object(const Str &name = "") {
            m_begin_group(name, '{');
            m_states.push(State::Object);
        }
        void end_object() {
            m_end_group('}');
            m_states.pop();
        }

        template <typename T>
        void item(const T &s, const Str &name = "") {
            if (m_states.top() == State::Object && !name.empty()) m_writer << '\"' << name << "\":";
            m_writer << s;
        }
        void string(const Str &s, const Str &name = "") {
            if (m_states.top() == State::Object && !name.empty()) m_writer << '\"' << name << "\":";
            m_writer << std::quoted(s);
        }

       private:
        inline void m_begin_group(const Str &name, char delim) {
            if (m_states.top() == State::Object && !name.empty()) m_writer << '\"' << name << "\":";
            m_writer << delim;
        }
        inline void   m_end_group(char delim) { m_writer << delim; }

        std::ostream &m_writer;
        enum class State {
            Root,
            List,
            Object,
        };
        enum class Type {
            None,
            List,
            Object,
            Str,
            Num,
        };
        std::stack<State> m_states;
    };

    static void source_compile_commands(JsonWriter &jw, const fs::path &dir, const fs::path &compiler, const Source &src, const Vec<Str> &flags) {
        jw.begin_object();
        {
            jw.begin_list("arguments");
            {
                jw.item(compiler);
                jw.sep();
                for (const auto &flag : flags) {
                    jw.string(flag);
                    jw.sep();
                }
                jw.string("-c");
                jw.sep();
                jw.string("-o");
                jw.sep();
                jw.item(src.out);
                jw.sep();
                jw.item(src.src);
            }
            jw.end_list();
            jw.sep();

            jw.item(dir, "directory");
            jw.sep();

            jw.item(src.src, "file");
            jw.sep();

            jw.item(src.out, "output");
        }
        jw.end_object();
    }

    void compile_commands(Cb *cb) {
        const fs::path &project_dir   = cb->cfg.project_path;
        const fs::path &compiler_path = cb->cfg.compiler_path;
        try {
            fs::path cmpath = cb->cfg.build_path;
            cmpath.append("compile_commands.json");
            std::ofstream out(cmpath);
            JsonWriter    jw(out);
            jw.begin_list();
            for (const auto &target : cb->targets) {
                if (target->type == TargetType::EXEC || !target->file.src.empty()) {
                    source_compile_commands(jw, project_dir, compiler_path, target->file, target->flags);
                }
                if (!target->sources.empty()) jw.sep();

                for (size_t i = 0; i < target->sources.size(); i++) {
                    const auto &source = target->sources[i];
                    source_compile_commands(jw, project_dir, compiler_path, source, target->flags);
                    if (i != (target->sources.size() - 1)) jw.sep();
                }
            }
            jw.end_list();

        } catch (const std::exception &e) {
            CB_ERROR("Failed on genereating compile_commands.json");
        }
    }
}  // namespace cb

////////////////////////////////////////////////////////////////////////////////
#endif  // CB_IMPLEMENTATION
