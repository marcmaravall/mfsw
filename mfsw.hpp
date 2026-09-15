#ifndef MFSW_H
#define MFSW_H

#include <atomic>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif
#ifdef __linux__
#include <poll.h>
#include <sys/eventfd.h>
#include <sys/inotify.h>
#include <unistd.h>

#include <climits>
#endif  // __linux__

namespace mfsw {

enum class action { NONE, ADD, REMOVE, MOVE, MODIFY };

struct event {
    action type = action::NONE;
    std::filesystem::path directory;
    std::filesystem::path filename;
    std::filesystem::path old_directory;
    std::filesystem::path old_filename;
    bool is_directory = false;
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

#ifdef _WIN32
    HANDLE m_stop_event = nullptr;
    void run(entry& e);
#elif defined(__linux__)
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

}  // namespace mfsw

#endif  // MFSW_H

#ifdef MFSW_IMPLEMENTATION

namespace mfsw {

void file_watcher::watch() {
    m_running = true;
#ifdef _WIN32
    m_stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
#elif defined(__linux__)
    m_stop_fd = eventfd(0, EFD_NONBLOCK);
#endif

    for (auto& e : m_entries) {
        m_threads.emplace_back([this, &e]() { run(e); });
    }
}

void file_watcher::stop() {
    if (!m_running.exchange(false)) return;

#ifdef _WIN32
    if (m_stop_event) SetEvent(m_stop_event);
#elif defined(__linux__)
    if (m_stop_fd >= 0) {
        uint64_t one = 1;
        write(m_stop_fd, &one, sizeof(one));
    }
#endif

    for (auto& t : m_threads) {
        if (t.joinable()) t.join();
    }
    m_threads.clear();

#ifdef _WIN32
    if (m_stop_event) {
        CloseHandle(m_stop_event);
        m_stop_event = nullptr;
    }
#elif defined(__linux__)
    if (m_stop_fd >= 0) {
        close(m_stop_fd);
        m_stop_fd = -1;
    }
#endif
}

void file_watcher::add_listener(const std::filesystem::path& path,
                                watch_listener* listener, bool recursive) {
    m_entries.push_back(entry(path, listener, recursive));
}

#ifdef _WIN32

// TODO: detect is_directory and handle it properly
void file_watcher::run(entry& e) {
    HANDLE hDir =
        CreateFileW(e.path.c_str(), FILE_LIST_DIRECTORY,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr, OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, nullptr);

    if (hDir == INVALID_HANDLE_VALUE) return;

    constexpr DWORD notify_filter =
        FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME |
        FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_CREATION;

    constexpr DWORD buffer_size = 64 * 1024;
    std::vector<BYTE> buffer(buffer_size);
    OVERLAPPED overlapped{};
    overlapped.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!overlapped.hEvent) {
        CloseHandle(hDir);
        return;
    }
    HANDLE handles[2] = {overlapped.hEvent, m_stop_event};
    event pending_rename;
    bool have_pending_rename = false;
    while (m_running) {
        DWORD bytes_returned = 0;
        BOOL ok = ReadDirectoryChangesW(hDir, buffer.data(), buffer_size,
                                        e.recursive, notify_filter,
                                        &bytes_returned, &overlapped, nullptr);
        if (!ok) break;

        DWORD wait_result = WaitForMultipleObjects(2, handles, FALSE, INFINITE);
        if (wait_result == WAIT_OBJECT_0 + 1) {
            CancelIoEx(hDir, &overlapped);
            GetOverlappedResult(hDir, &overlapped, &bytes_returned, TRUE);
            break;
        }
        if (wait_result != WAIT_OBJECT_0) continue;

        DWORD transferred = 0;
        if (!GetOverlappedResult(hDir, &overlapped, &transferred, FALSE) ||
            transferred == 0) {
            ResetEvent(overlapped.hEvent);
            continue;
        }
        ResetEvent(overlapped.hEvent);

        BYTE* ptr = buffer.data();
        while (true) {
            auto* info = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(ptr);

            std::wstring wname(info->FileName,
                               info->FileNameLength / sizeof(WCHAR));
            std::filesystem::path name(wname);

            switch (info->Action) {
                case FILE_ACTION_ADDED:
                    e.listener->on_event(
                        event{action::ADD, e.path, name, {}, {}});
                    break;
                case FILE_ACTION_REMOVED:
                    e.listener->on_event(
                        event{action::REMOVE, e.path, name, {}, {}});
                    break;
                case FILE_ACTION_MODIFIED:
                    e.listener->on_event(
                        event{action::MODIFY, e.path, name, {}, {}});
                    break;
                case FILE_ACTION_RENAMED_OLD_NAME:
                    pending_rename = event{action::MOVE, {}, {}, e.path, name};
                    have_pending_rename = true;
                    break;
                case FILE_ACTION_RENAMED_NEW_NAME: {
                    event ev{action::MOVE, e.path, name, {}, {}};
                    if (have_pending_rename) {
                        ev.old_directory = pending_rename.old_directory;
                        ev.old_filename = pending_rename.old_filename;
                        have_pending_rename = false;
                    }
                    e.listener->on_event(ev);
                    break;
                }
                default:
                    break;
            }

            if (info->NextEntryOffset == 0) break;
            ptr += info->NextEntryOffset;
        }
    }

    CloseHandle(overlapped.hEvent);
    CloseHandle(hDir);
}

#elif defined(__linux__)

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
            bool is_dir = raw->mask & IN_ISDIR;
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
                pending_moves[raw->cookie] = event{.type = action::MOVE,
                                                   .directory = dir,
                                                   .filename = name,
                                                   .is_directory = is_dir};
                continue;
            }

            if (raw->mask & IN_MOVED_TO) {
                event ev{.type = action::MOVE,
                         .directory = dir,
                         .filename = name,
                         .is_directory = is_dir};
                auto pm = pending_moves.find(raw->cookie);
                if (pm != pending_moves.end()) {
                    ev.old_directory = pm->second.directory;
                    ev.old_filename = pm->second.filename;
                    pending_moves.erase(pm);
                }
                if (e.recursive && is_dir) add_watch(full);
                e.listener->on_event(ev);
                continue;
            }

            action act = action::NONE;
            if (raw->mask & IN_CREATE)
                act = action::ADD;
            else if (raw->mask & (IN_DELETE | IN_DELETE_SELF))
                act = action::REMOVE;
            else if (raw->mask & (IN_MODIFY | IN_CLOSE_WRITE))
                act = action::MODIFY;
            if (act == action::NONE) continue;

            if (act == action::ADD && e.recursive &&
                std::filesystem::is_directory(full)) {
                add_watch(full);
            }

            e.listener->on_event(event{.type = act,
                                       .directory = dir,
                                       .filename = name,
                                       .is_directory = is_dir});
        }
    }

    for (auto& [wd, path] : wd_to_path) inotify_rm_watch(fd, wd);
    close(fd);
}

#endif  // __linux__

}  // namespace mfsw

#endif  // MFSW_IMPLEMENTATION
