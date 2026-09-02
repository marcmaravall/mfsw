#ifndef MSFW_H
#define MSFW_H

#include <atomic>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#ifdef _WIN32
#error "Win32 Is not supported yet"
#endif
#ifdef __linux__
#include <poll.h>
#include <sys/eventfd.h>
#include <sys/inotify.h>
#include <unistd.h>

#include <climits>
#endif  // __linux__

namespace msfw {

enum class action { NONE, ADD, DELETE, MOVE, MODIFY };

struct event {
    action type = action::NONE;
    std::filesystem::path directory;
    std::filesystem::path filename;
    std::filesystem::path old_filename;
};

class watch_listener {
public:
    virtual void on_event(const event& event) = 0;

public:
    watch_listener() = default;
    virtual ~watch_listener() = default;
};

class file_watcher {
private:
    struct entry {
        const std::filesystem::path path;
        watch_listener* listener;
        bool recursive = true;

        entry(const std::filesystem::path& p, watch_listener* l,
              bool rec = true)
            : path(p), listener(l), recursive(rec) {}
        ~entry() = default;
    };

    std::deque<entry> m_entries;
    std::vector<std::thread> m_threads;
    std::atomic<bool> m_running{false};

#ifdef __linux__
    int m_stop_fd = -1;
    void run(entry& e);
#endif

public:
    void add_listener(const std::filesystem::path&, watch_listener* listener,
                      bool recursive = true);
    void watch();
    void stop();

public:
    file_watcher() = default;
    ~file_watcher() { stop(); }
};

}  // namespace msfw

#endif  // MSFW_H

#ifdef MSFW_IMPLEMENTATION

namespace msfw {

#ifdef __linux__

void file_watcher::add_listener(const std::filesystem::path& path,
                                watch_listener* listener, bool recursive) {
    m_entries.push_back(entry(path, listener, recursive));
}

void file_watcher::run(entry& e) {
    int fd = inotify_init1(IN_NONBLOCK);
    if (fd < 0) return;

    constexpr uint32_t mask = IN_CREATE | IN_DELETE | IN_MODIFY |
                              IN_CLOSE_WRITE | IN_MOVED_FROM | IN_MOVED_TO |
                              IN_DELETE_SELF | IN_IGNORED;

    std::unordered_map<int, std::filesystem::path> wd_to_path;
    std::unordered_map<uint32_t, event> pending_moves;

    auto add_watch = [&](const std::filesystem::path& dir) {
        int wd = inotify_add_watch(fd, dir.c_str(), mask);
        if (wd >= 0) wd_to_path[wd] = dir;
    };

    add_watch(e.path);
    if (e.recursive && std::filesystem::exists(e.path)) {
        std::error_code ec;
        auto opts = std::filesystem::directory_options::skip_permission_denied;
        for (auto& p :
             std::filesystem::recursive_directory_iterator(e.path, opts, ec)) {
            if (p.is_directory()) add_watch(p.path());
        }
    }

    constexpr ssize_t buffer_size = 64 * (sizeof(inotify_event) + NAME_MAX + 1);
    char buffer[buffer_size];

    struct pollfd fds[2];
    fds[0].fd = fd;
    fds[0].events = POLLIN;
    fds[1].fd = m_stop_fd;
    fds[1].events = POLLIN;

    while (m_running) {
        int ret = poll(fds, 2, -1);
        if (ret <= 0) continue;
        if (fds[1].revents & POLLIN) break;
        if (!(fds[0].revents & POLLIN)) continue;

        ssize_t len = read(fd, buffer, buffer_size);
        if (len <= 0) continue;

        ssize_t i = 0;
        while (i < len) {
            auto* raw = reinterpret_cast<inotify_event*>(buffer + i);
            i += sizeof(inotify_event) + raw->len;

            if (raw->mask & IN_IGNORED) {
                wd_to_path.erase(raw->wd);
                continue;
            }
            if (raw->len == 0) continue;

            auto it = wd_to_path.find(raw->wd);
            if (it == wd_to_path.end()) continue;

            const std::filesystem::path& dir = it->second;
            std::filesystem::path name = raw->name;
            std::filesystem::path full = dir / name;

            if (raw->mask & IN_MOVED_FROM) {
                pending_moves[raw->cookie] = event{action::MOVE, dir, name, {}};
                continue;
            }

            if (raw->mask & IN_MOVED_TO) {
                event ev{action::MOVE, dir, name, {}};
                auto pm = pending_moves.find(raw->cookie);
                if (pm != pending_moves.end()) {
                    ev.old_filename = pm->second.filename;
                    pending_moves.erase(pm);
                }
                if (e.recursive && std::filesystem::is_directory(full))
                    add_watch(full);
                e.listener->on_event(ev);
                continue;
            }

            action act = action::NONE;
            if (raw->mask & IN_CREATE)
                act = action::ADD;
            else if (raw->mask & (IN_DELETE | IN_DELETE_SELF))
                act = action::DELETE;
            else if (raw->mask & (IN_MODIFY | IN_CLOSE_WRITE))
                act = action::MODIFY;
            if (act == action::NONE) continue;

            if (act == action::ADD && e.recursive &&
                std::filesystem::is_directory(full)) {
                add_watch(full);
            }

            e.listener->on_event(event{act, dir, name, {}});
        }
    }

    for (auto& [wd, path] : wd_to_path) inotify_rm_watch(fd, wd);
    close(fd);
}

void file_watcher::watch() {
    m_running = true;
    m_stop_fd = eventfd(0, EFD_NONBLOCK);

    for (auto& e : m_entries) {
        m_threads.emplace_back([this, &e]() { run(e); });
    }
}

void file_watcher::stop() {
    if (!m_running.exchange(false)) return;

    if (m_stop_fd >= 0) {
        uint64_t one = 1;
        write(m_stop_fd, &one, sizeof(one));
    }
    for (auto& t : m_threads) {
        if (t.joinable()) t.join();
    }
    m_threads.clear();

    if (m_stop_fd >= 0) {
        close(m_stop_fd);
        m_stop_fd = -1;
    }
}

#endif  // __linux__

}  // namespace msfw

#endif  // MSFW_IMPLEMENTATION
