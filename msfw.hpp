#ifndef MSFW_H
#define MSFW_H

#include <filesystem>
#include <string>

#ifdef _WIN32
#error "Win32 Is not supported yet"
#endif
#ifdef __linux__
#include <sys/inotify.h>
#include <unistd.h>
#endif  // __linux__

namespace msfw {

enum class action { NONE, ADD, DELETE, MOVE, MODIFY };

struct event {
    action type = action::NONE;
    std::filesystem::path& directory;
    std::filesystem::path& filename;
    std::filesystem::path& old_filename;
};

class watch_listener {
private:
    virtual void on_event(const event& event);

public:
    watch_listener() = default;
    virtual ~watch_listener() = default;
};

class file_watcher {
private:
public:
    void add_listener(const std::filesystem::path&, watch_listener* listener);
    void watch();

public:
    file_watcher() = default;
    ~file_watcher() = default;
};

}  // namespace msfw

#endif  // MSFW_H

// TODO: implement
#ifdef MSFW_IMPLEMENTATION

#endif  // MSFW_IMPLEMENTATION
