#pragma once
#include <windows.h>
#include <bcrypt.h>
#include <filesystem>
#include <string>
#include <vector>
#include <stdexcept>
#include <utility>
#include <cstddef>
#include <cstring>

namespace fs = std::filesystem;

struct HttpError : std::runtime_error {
    int status;
    HttpError(int code, const std::string& text) : std::runtime_error(text), status(code) {}
};

inline std::string randomHex(size_t bytes = 32) {
    std::vector<unsigned char> data(bytes);
    if (BCryptGenRandom(nullptr, data.data(), static_cast<ULONG>(data.size()),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
        throw std::runtime_error("Windows secure random generator failed");
    constexpr char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(bytes * 2);
    for (auto b : data) { result += hex[b >> 4]; result += hex[b & 15]; }
    return result;
}

inline bool constantEqual(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    volatile unsigned int different = 0;
    for (size_t i = 0; i < a.size(); ++i)
        different = different | (static_cast<unsigned char>(a[i]) ^ static_cast<unsigned char>(b[i]));
    return different == 0;
}

inline std::wstring utf16(const std::string& text) {
    if (text.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
                              static_cast<int>(text.size()), nullptr, 0);
    if (!n) throw HttpError(400, "Invalid UTF-8 path");
    std::wstring result(n, L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), result.data(), n);
    return result;
}

class WinHandle {
    HANDLE handle_ = INVALID_HANDLE_VALUE;
public:
    explicit WinHandle(HANDLE h = INVALID_HANDLE_VALUE) : handle_(h) {}
    ~WinHandle() { reset(); }
    WinHandle(const WinHandle&) = delete;
    WinHandle& operator=(const WinHandle&) = delete;
    WinHandle(WinHandle&& other) noexcept : handle_(std::exchange(other.handle_, INVALID_HANDLE_VALUE)) {}
    WinHandle& operator=(WinHandle&& other) noexcept {
        if (this != &other) { reset(); handle_ = std::exchange(other.handle_, INVALID_HANDLE_VALUE); }
        return *this;
    }
    void reset() { if (handle_ != INVALID_HANDLE_VALUE) { CloseHandle(handle_); handle_ = INVALID_HANDLE_VALUE; } }
    HANDLE get() const { return handle_; }
    explicit operator bool() const { return handle_ != INVALID_HANDLE_VALUE; }
};

class SharedFolder {
    fs::path root_;
    WinHandle rootLock_;

    bool contains(const fs::path& path) const {
        auto a = root_.generic_wstring(), b = path.lexically_normal().generic_wstring();
        if (b.size() < a.size() || _wcsnicmp(a.c_str(), b.c_str(), a.size()) != 0) return false;
        return b.size() == a.size() || a.back() == L'/' || b[a.size()] == L'/';
    }

    void checkHandle(HANDLE handle, bool directory) const {
        BY_HANDLE_FILE_INFORMATION info{};
        if (!GetFileInformationByHandle(handle, &info)) throw HttpError(403, "Cannot inspect file");
        if (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
            throw HttpError(403, "Links and junctions cannot be shared");
        if (!directory && info.nNumberOfLinks > 1)
            throw HttpError(403, "Hard-linked files cannot be shared");
        DWORD n = GetFinalPathNameByHandleW(handle, nullptr, 0, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
        if (!n || n > 32768) throw HttpError(403, "Cannot verify file location");
        std::wstring actual(n, L'\0');
        DWORD written = GetFinalPathNameByHandleW(handle, actual.data(), n, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
        if (!written || written >= n) throw HttpError(403, "Cannot verify file location");
        actual.resize(written);
        if (actual.rfind(L"\\\\?\\UNC\\", 0) == 0) throw HttpError(403, "Network shares are not supported");
        if (actual.rfind(L"\\\\?\\", 0) == 0) actual.erase(0, 4);
        if (!contains(fs::path(actual))) throw HttpError(403, "Path is outside the shared folder");
    }

    static std::vector<std::wstring> components(const std::string& relative) {
        if (relative.size() > 4096) throw HttpError(400, "Path is too long");
        std::wstring path = utf16(relative);
        std::vector<std::wstring> parts;
        if (path.empty()) return parts;
        size_t start = 0;
        while (start < path.size()) {
            size_t end = path.find(L'/', start);
            auto part = path.substr(start, end == std::wstring::npos ? end : end - start);
            if (part.empty() || part == L"." || part == L".." || part.size() > 255 ||
                part.back() == L'.' || part.back() == L' ')
                throw HttpError(400, "Invalid path component");
            for (wchar_t c : part)
                if (c < 32 || c == 127 || std::wstring(L"\\:*?\"<>|").find(c) != std::wstring::npos)
                    throw HttpError(400, "Invalid Windows filename");
            auto stem = part.substr(0, part.find(L'.'));
            for (auto& c : stem) if (c >= L'a' && c <= L'z') c -= 32;
            bool device = stem == L"CON" || stem == L"PRN" || stem == L"AUX" || stem == L"NUL" ||
                          stem == L"CLOCK$" || stem == L"CONIN$" || stem == L"CONOUT$";
            if (stem.size() == 4 && (stem.substr(0, 3) == L"COM" || stem.substr(0, 3) == L"LPT"))
                device = (stem[3] >= L'1' && stem[3] <= L'9') || stem[3] == L'\u00b9' ||
                         stem[3] == L'\u00b2' || stem[3] == L'\u00b3';
            auto lower = part;
            for (auto& c : lower) if (c >= L'A' && c <= L'Z') c += 32;
            if (device || lower.rfind(L".sharehub-", 0) == 0)
                throw HttpError(400, "Reserved filename");
            parts.push_back(part);
            if (end == std::wstring::npos) break;
            start = end + 1;
            if (start == path.size()) throw HttpError(400, "Trailing separator is not allowed");
        }
        return parts;
    }

    std::vector<WinHandle> lockParents(const std::vector<std::wstring>& parts, bool create) const {
        fs::path current = root_;
        std::vector<WinHandle> locks;
        for (const auto& part : parts) {
            current /= part;
            if (create && !CreateDirectoryW(current.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS)
                throw HttpError(400, "Cannot create destination folder");
            WinHandle lock(CreateFileW(current.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ,
                nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
            if (!lock) throw HttpError(404, "Folder is unavailable");
            DWORD attr = GetFileAttributesW(current.c_str());
            if (attr == INVALID_FILE_ATTRIBUTES || !(attr & FILE_ATTRIBUTE_DIRECTORY))
                throw HttpError(400, "Not a folder");
            checkHandle(lock.get(), true);
            locks.push_back(std::move(lock));
        }
        return locks;
    }

public:
    explicit SharedFolder(const fs::path& root) {
        auto absolute = fs::absolute(root).lexically_normal();
        if (absolute.wstring().rfind(L"\\\\", 0) == 0) throw std::runtime_error("Use a local disk folder, not a UNC share");
        fs::create_directories(absolute);
        // Reject a reparse point anywhere in the configured root, too.
        fs::path check = absolute.root_path();
        for (const auto& part : absolute.relative_path()) {
            check /= part;
            DWORD attr = GetFileAttributesW(check.c_str());
            if (attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_REPARSE_POINT))
                throw std::runtime_error("The shared folder cannot contain a symlink or junction in its path");
        }
        root_ = fs::canonical(absolute);
        rootLock_ = WinHandle(CreateFileW(root_.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ,
            nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        if (!rootLock_) throw std::runtime_error("Cannot open the shared folder");
        checkHandle(rootLock_.get(), true);
    }

    const fs::path& root() const { return root_; }

    struct Directory {
        fs::path path;
        std::vector<WinHandle> locks;
    };
    Directory directory(const std::string& relative) const {
        auto parts = components(relative);
        auto locks = lockParents(parts, false);
        fs::path path = root_; for (const auto& part : parts) path /= part;
        return {path, std::move(locks)};
    }

    struct Download {
        WinHandle handle;
        std::vector<WinHandle> locks;
        uint64_t size;
        std::string name;
    };
    Download download(const std::string& relative) const {
        auto parts = components(relative);
        if (parts.empty()) throw HttpError(400, "A filename is required");
        auto filename = parts.back(); parts.pop_back();
        auto locks = lockParents(parts, false);
        fs::path path = root_; for (const auto& part : parts) path /= part; path /= filename;
        WinHandle file(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                 FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
        if (!file) throw HttpError(404, "File is unavailable");
        checkHandle(file.get(), false);
        BY_HANDLE_FILE_INFORMATION info{};
        if (!GetFileInformationByHandle(file.get(), &info) || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
            throw HttpError(400, "Not a file");
        return {std::move(file), std::move(locks),
                (static_cast<uint64_t>(info.nFileSizeHigh) << 32) | info.nFileSizeLow, path.filename().u8string()};
    }

    class Upload {
        const SharedFolder& owner_;
        fs::path destination_, temporary_;
        std::vector<WinHandle> locks_;
        WinHandle file_;
        bool committed_ = false;
    public:
        Upload(const SharedFolder& owner, const std::string& relative) : owner_(owner) {
            auto parts = components(relative);
            if (parts.empty()) throw HttpError(400, "A filename is required");
            auto filename = parts.back(); parts.pop_back();
            locks_ = owner.lockParents(parts, true);
            fs::path parent = owner.root_; for (const auto& part : parts) parent /= part;
            destination_ = parent / filename;
            if (GetFileAttributesW(destination_.c_str()) != INVALID_FILE_ATTRIBUTES)
                throw HttpError(409, "A file with this name already exists; choose a new name");
            temporary_ = parent / fs::u8path(".sharehub-upload-" + randomHex(16) + ".part");
            file_ = WinHandle(CreateFileW(temporary_.c_str(), GENERIC_WRITE | FILE_READ_ATTRIBUTES | DELETE, 0, nullptr,
                CREATE_NEW, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
            if (!file_) throw HttpError(400, "Cannot create upload file");
            try { owner_.checkHandle(file_.get(), false); }
            catch (...) { file_.reset(); DeleteFileW(temporary_.c_str()); throw; }
        }
        ~Upload() { file_.reset(); if (!committed_ && !temporary_.empty()) DeleteFileW(temporary_.c_str()); }
        void write(const char* data, DWORD length) {
            DWORD written = 0;
            if (!WriteFile(file_.get(), data, length, &written, nullptr) || written != length)
                throw HttpError(507, "Disk write failed");
        }
        void commit() {
            if (!FlushFileBuffers(file_.get())) throw HttpError(507, "Disk flush failed");
            owner_.checkHandle(file_.get(), false);
            // Rename the file through its still-open handle, so a local writer cannot
            // replace the source between closing it and a pathname-based rename.
            auto name = destination_.wstring();
            std::vector<unsigned char> storage(offsetof(FILE_RENAME_INFO, FileName) + (name.size() + 1) * sizeof(wchar_t));
            auto* rename = reinterpret_cast<FILE_RENAME_INFO*>(storage.data());
            rename->ReplaceIfExists = FALSE;
            rename->RootDirectory = nullptr;
            rename->FileNameLength = static_cast<DWORD>(name.size() * sizeof(wchar_t));
            std::memcpy(rename->FileName, name.data(), rename->FileNameLength);
            if (!SetFileInformationByHandle(file_.get(), FileRenameInfo, rename, static_cast<DWORD>(storage.size())))
                throw HttpError(409, "Cannot save upload; the destination may already exist");
            committed_ = true;
            file_.reset(); // Make the completed file readable before sending HTTP 201.
        }
    };
};
