#define _WIN32_WINNT 0x0602
#define NOMINMAX
#define SECURITY_WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <shellapi.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <thread>
#include "security.hpp"
#include "tls_transport.hpp"
#include "pairing_window.hpp"

using Clock = std::chrono::steady_clock;
constexpr size_t HEADER_LIMIT = 16 * 1024;
constexpr uint64_t MAX_UPLOAD = 2ull * 1024 * 1024 * 1024;
constexpr int SESSION_SECONDS = 1800;
std::mutex logMutex;
std::atomic<SOCKET> listener{INVALID_SOCKET};

static std::string lower(std::string s) {
    for (char& c : s) if (c >= 'A' && c <= 'Z') c += 32;
    return s;
}
static std::string trim(const std::string& s) {
    auto a = s.find_first_not_of(" \t"), b = s.find_last_not_of(" \t");
    return a == std::string::npos ? "" : s.substr(a, b - a + 1);
}
static int hexDigit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
static std::string decode(const std::string& s) {
    std::string result;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '%') {
            if (i + 2 >= s.size() || hexDigit(s[i + 1]) < 0 || hexDigit(s[i + 2]) < 0)
                throw HttpError(400, "Invalid URL encoding");
            result += static_cast<char>((hexDigit(s[i + 1]) << 4) | hexDigit(s[i + 2])); i += 2;
        } else result += s[i] == '+' ? ' ' : s[i];
    }
    return result;
}
static std::string encode(const std::string& s) {
    constexpr char hex[] = "0123456789ABCDEF";
    std::string result;
    for (unsigned char c : s) {
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
            c == '-' || c == '_' || c == '.' || c == '~') result += c;
        else { result += '%'; result += hex[c >> 4]; result += hex[c & 15]; }
    }
    return result;
}
static std::string escape(const std::string& s) {
    std::string result;
    for (char c : s) {
        switch (c) {
        case '&': result += "&amp;"; break; case '<': result += "&lt;"; break;
        case '>': result += "&gt;"; break; case '"': result += "&quot;"; break;
        case '\'': result += "&#39;"; break; default: result += c;
        }
    }
    return result;
}
static std::map<std::string, std::string> parameters(const std::string& text) {
    std::map<std::string, std::string> result;
    size_t start = 0;
    while (start < text.size()) {
        size_t end = text.find('&', start);
        auto part = text.substr(start, end == std::string::npos ? end : end - start);
        auto eq = part.find('=');
        if (eq == std::string::npos) throw HttpError(400, "Invalid parameters");
        auto key = decode(part.substr(0, eq)), value = decode(part.substr(eq + 1));
        if (!result.emplace(key, value).second) throw HttpError(400, "Duplicate parameter");
        if (end == std::string::npos) break;
        start = end + 1;
    }
    return result;
}
static bool privateIp(uint32_t networkOrder) {
    uint32_t ip = ntohl(networkOrder);
    return (ip >> 24) == 10 || (ip >> 24) == 127 || (ip >> 20) == 0xac1 ||
           (ip >> 16) == 0xc0a8 || (ip >> 16) == 0xa9fe;
}

class Connection {
    SOCKET socket_;
    std::unique_ptr<TlsConnection> tls_;
public:
    Connection(SOCKET socket, TlsServer* server) : socket_(socket) {
        if (server) tls_ = std::make_unique<TlsConnection>(socket, *server);
    }
    int read(char* buffer, int length) { return tls_ ? tls_->read(buffer, length) : recv(socket_, buffer, length, 0); }
    bool write(const char* data, size_t length) {
        if (tls_) return tls_->writeAll(data, length);
        while (length) {
            int n = send(socket_, data, static_cast<int>(std::min<size_t>(length, 256 * 1024)), 0);
            if (n <= 0) return false;
            data += n; length -= n;
        }
        return true;
    }
};

struct Request {
    std::string method, path, query, initialBody;
    std::map<std::string, std::string> headers;
    uint64_t length = 0;
    std::string header(const std::string& name) const {
        auto it = headers.find(name); return it == headers.end() ? "" : it->second;
    }
    std::string contentType() const {
        auto type = header("content-type");
        return lower(trim(type.substr(0, type.find(';'))));
    }
};

static Request readRequest(Connection& c) {
    std::string data;
    std::array<char, 8192> buffer{};
    auto deadline = Clock::now() + std::chrono::seconds(10);
    size_t end;
    while ((end = data.find("\r\n\r\n")) == std::string::npos) {
        if (data.size() >= HEADER_LIMIT || Clock::now() >= deadline) throw HttpError(431, "Request headers too large or slow");
        int n = c.read(buffer.data(), static_cast<int>(buffer.size()));
        if (n <= 0) throw HttpError(400, "Incomplete request");
        data.append(buffer.data(), n);
    }
    if (end + 4 > HEADER_LIMIT) throw HttpError(431, "Request headers too large");
    Request r;
    size_t first = data.find("\r\n");
    std::istringstream requestLine(data.substr(0, first));
    std::string version, extra, target;
    requestLine >> r.method >> target >> version;
    if (requestLine >> extra || version != "HTTP/1.1" || target.empty() || target.front() != '/' || target.size() > 4096)
        throw HttpError(400, "Invalid request line");
    if (r.method != "GET" && r.method != "POST") throw HttpError(405, "Method not allowed");
    for (unsigned char ch : target) if (ch <= 32 || ch >= 127 || ch == '#') throw HttpError(400, "Invalid request target");
    size_t q = target.find('?'); r.path = target.substr(0, q); r.query = q == std::string::npos ? "" : target.substr(q + 1);
    size_t pos = first + 2;
    while (pos < end) {
        auto next = data.find("\r\n", pos); auto line = data.substr(pos, next - pos); pos = next + 2;
        auto colon = line.find(':');
        if (colon == std::string::npos || colon == 0) throw HttpError(400, "Malformed header");
        auto name = lower(line.substr(0, colon)), value = trim(line.substr(colon + 1));
        for (unsigned char ch : name)
            if (!((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-')) throw HttpError(400, "Invalid header name");
        for (unsigned char ch : value) if ((ch < 32 && ch != '\t') || ch == 127) throw HttpError(400, "Invalid header value");
        if (!r.headers.emplace(name, value).second) throw HttpError(400, "Duplicate headers are not allowed");
    }
    if (r.header("host").empty() || r.headers.count("transfer-encoding") || r.headers.count("expect"))
        throw HttpError(400, "Unsupported request framing");
    auto length = r.header("content-length");
    if (!length.empty()) {
        if (length.size() > 12 || length.find_first_not_of("0123456789") != std::string::npos)
            throw HttpError(400, "Invalid Content-Length");
        r.length = std::stoull(length);
        if (r.length > MAX_UPLOAD) throw HttpError(413, "File exceeds 2 GiB");
    } else if (r.method == "POST") throw HttpError(411, "Content-Length is required");
    if (r.method == "GET" && r.length) throw HttpError(400, "GET cannot have a body");
    r.initialBody = data.substr(end + 4);
    if (r.initialBody.size() > r.length) throw HttpError(400, "Unexpected request data");
    return r;
}

static std::string statusName(int code) {
    switch (code) {
    case 200: return "OK"; case 201: return "Created"; case 303: return "See Other";
    case 400: return "Bad Request"; case 401: return "Unauthorized"; case 403: return "Forbidden";
    case 404: return "Not Found"; case 405: return "Method Not Allowed"; case 409: return "Conflict"; case 410: return "Gone";
    case 411: return "Length Required"; case 413: return "Payload Too Large"; case 429: return "Too Many Requests";
    case 431: return "Request Header Fields Too Large"; case 507: return "Insufficient Storage"; default: return "Internal Server Error";
    }
}
static bool sendHeaders(Connection& c, int code, const std::string& type, uint64_t length,
                        const std::string& extra = "", const std::string& nonce = "") {
    std::ostringstream h;
    h << "HTTP/1.1 " << code << " " << statusName(code) << "\r\nContent-Type: " << type << "\r\nContent-Length: " << length
      << "\r\nConnection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: same-origin"
      << "\r\nX-Frame-Options: DENY\r\nPermissions-Policy: camera=(), microphone=(), geolocation=()\r\nContent-Security-Policy: default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; connect-src 'self'; ";
    if (nonce.empty()) h << "script-src 'none'; style-src 'none'";
    else h << "script-src 'nonce-" << nonce << "'; style-src 'nonce-" << nonce << "'";
    h << "\r\n" << extra << "\r\n";
    auto text = h.str(); return c.write(text.data(), text.size());
}
static void reply(Connection& c, int code, const std::string& body, const std::string& extra = "") {
    if (sendHeaders(c, code, "text/plain; charset=utf-8", body.size(), extra)) c.write(body.data(), body.size());
}
static std::string smallBody(Connection& c, const Request& r, size_t max) {
    if (r.length > max) throw HttpError(413, "Request body too large");
    std::string body = r.initialBody; std::array<char, 1024> buf{};
    while (body.size() < r.length) {
        int n = c.read(buf.data(), static_cast<int>(std::min<uint64_t>(buf.size(), r.length - body.size())));
        if (n <= 0) throw HttpError(400, "Request interrupted");
        body.append(buf.data(), n);
    }
    return body;
}

struct Session { std::string csrf; Clock::time_point expires; };
class Authentication {
    std::string pairing_ = randomHex(16);
    std::mutex mutex_;
    std::map<std::string, Session> sessions_;
    struct Attempt { unsigned failures = 0; Clock::time_point start = Clock::now(); };
    std::map<std::string, Attempt> attempts_;
    std::string qrTicket_;
    Clock::time_point qrExpires_{};
    bool qrUsed_ = false;
    int qrSeconds_;
    void cleanup() {
        auto now = Clock::now();
        for (auto it = sessions_.begin(); it != sessions_.end();) {
            if (it->second.expires <= now) it = sessions_.erase(it); else ++it;
        }
        for (auto it = attempts_.begin(); it != attempts_.end();) {
            if (now - it->second.start >= std::chrono::seconds(60)) it = attempts_.erase(it); else ++it;
        }
    }
    Attempt& checkAttempts(const std::string& peer) {
        cleanup();
        if (attempts_.size() >= 256 && !attempts_.count(peer)) throw HttpError(429, "Try again in one minute");
        auto& attempt = attempts_[peer];
        if (attempt.failures >= 5) throw HttpError(429, "Too many attempts; try again in one minute");
        return attempt;
    }
    std::string createSession() {
        if (sessions_.size() >= 16) throw HttpError(429, "Too many active sessions");
        auto id = randomHex(); sessions_[id] = {randomHex(), Clock::now() + std::chrono::seconds(SESSION_SECONDS)};
        return id;
    }
public:
    explicit Authentication(int qrSeconds = 120) : qrSeconds_(qrSeconds) {}
    const std::string& pairing() const { return pairing_; }
    std::string login(const std::string& code, const std::string& peer) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto& attempt = checkAttempts(peer);
        if (!constantEqual(code, pairing_)) { ++attempt.failures; throw HttpError(401, "Incorrect pairing code"); }
        return createSession();
    }
    std::string issueQrTicket() {
        std::lock_guard<std::mutex> lock(mutex_);
        qrTicket_ = randomHex(); qrExpires_ = Clock::now() + std::chrono::seconds(qrSeconds_); qrUsed_ = false;
        return qrTicket_;
    }
    int qrStatus(const std::string& ticket) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!constantEqual(ticket, qrTicket_)) return -2;
        if (qrUsed_) return -1;
        if (Clock::now() >= qrExpires_) return 0;
        return static_cast<int>(std::chrono::duration_cast<std::chrono::seconds>(qrExpires_ - Clock::now()).count()) + 1;
    }
    std::string loginQr(const std::string& ticket, const std::string& peer) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto& attempt = checkAttempts(peer);
        if (ticket.empty() || !constantEqual(ticket, qrTicket_)) { ++attempt.failures; throw HttpError(401, "Invalid QR pairing link"); }
        if (qrUsed_ || Clock::now() >= qrExpires_) throw HttpError(410, "QR expired or already used; generate a new QR on Windows");
        auto id = createSession();
        qrUsed_ = true; // Consume and create session under one lock: only one scanner wins.
        return id;
    }
    std::optional<Session> get(const std::string& id) {
        std::lock_guard<std::mutex> lock(mutex_); cleanup();
        auto it = sessions_.find(id); if (it == sessions_.end()) return std::nullopt; return it->second;
    }
    void logout(const std::string& id) { std::lock_guard<std::mutex> lock(mutex_); sessions_.erase(id); }
};

struct State {
    SharedFolder folder;
    Authentication authentication;
    bool httpMode, readOnly;
    int port;
    State(fs::path path, bool local, bool readonly, int p, int qrSeconds) : folder(path), authentication(qrSeconds), httpMode(local), readOnly(readonly), port(p) {}
    std::string cookieName() const { return httpMode ? "sharehub-local" : "__Host-sharehub"; }
};
static std::string sessionId(const Request& r, const std::string& name) {
    std::istringstream cookies(r.header("cookie")); std::string part, result;
    while (std::getline(cookies, part, ';')) {
        part = trim(part); auto eq = part.find('=');
        if (eq != std::string::npos && part.substr(0, eq) == name) {
            if (!result.empty()) throw HttpError(400, "Duplicate session cookie");
            result = part.substr(eq + 1);
        }
    }
    return result;
}
static void validateOrigin(const Request& r, bool httpMode, const std::string& localIp, int port) {
    auto host = r.header("host");
    auto suffix = port == (httpMode ? 80 : 443) ? "" : ":" + std::to_string(port);
    bool allowed = host == localIp + suffix || (localIp == "127.0.0.1" && host == "localhost" + suffix);
    if (!allowed) throw HttpError(403, "Unrecognized Host header; connect using the displayed IP address");
    auto origin = r.header("origin");
    auto site = r.header("sec-fetch-site");
    std::string expected = (httpMode ? "http://" : "https://") + host;
    bool sameSite = site == "same-origin";
    if ((!origin.empty() && origin != expected) || (r.method == "POST" && origin != expected && !sameSite))
        throw HttpError(403, "Cross-origin request denied");
    // Opening a camera-scanned link is a top-level navigation. It carries no
    // credential in the HTTP URL and does not redeem a ticket until same-origin POST.
    bool qrLanding = r.method == "GET" && r.path == "/pair";
    if (!qrLanding && !site.empty() && site != "same-origin" && site != "none") throw HttpError(403, "Cross-site request denied");
}

static std::string pageStart(const std::string& nonce) {
    return "<!doctype html><html lang=ko><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>ShareHub</title><style nonce='" + nonce + R"('>
body{font:16px system-ui;max-width:780px;margin:32px auto;padding:0 20px;color:#182230}h1{font-size:1.6rem}.box{background:#f3f6fa;padding:20px;border-radius:12px;margin:20px 0}input{max-width:100%;box-sizing:border-box;margin:10px 0}input[type=password]{width:100%;padding:12px}button{padding:10px 16px;background:#155eef;color:white;border:0;border-radius:8px;font:inherit;cursor:pointer}button:disabled{opacity:.5}li{padding:10px 0;overflow-wrap:anywhere}small{color:#667085}progress{width:100%;margin-top:12px}#status{white-space:pre-wrap}.row{display:flex;gap:12px;align-items:center;justify-content:space-between}</style><h1>ShareHub</h1>)";
}
static void sendPage(Connection& c, const std::string& body, const std::string& nonce) {
    if (sendHeaders(c, 200, "text/html; charset=utf-8", body.size(), "", nonce)) c.write(body.data(), body.size());
}
static void loginPage(Connection& c, bool httpMode) {
    auto nonce = randomHex(16);
    auto body = pageStart(nonce) + (httpMode ? "<p><strong>비보안 모드 · HTTP</strong> — 연결 코드와 파일이 암호화되지 않습니다.</p>" : "<p><strong>보안 모드 · HTTPS</strong> — 연결 코드와 파일을 암호화하여 전송합니다.</p>") + R"(<p>아이폰 카메라로 Windows 앱의 QR 코드를 찍고 링크를 누르면 자동으로 연결됩니다.</p><p>또는 연결 코드를 직접 입력하세요. 연결은 30분 동안 유효합니다.</p><div class=box><form id=login method=post action=/login><label>연결 코드<input name=code type=password autocomplete=off required maxlength=32 spellcheck=false></label><button>연결</button><p id=status aria-live=polite></p></form></div><script nonce=')" + nonce + R"('>
document.querySelector('#login').onsubmit=async event=>{event.preventDefault();const form=event.currentTarget,button=form.querySelector('button'),status=document.querySelector('#status');button.disabled=true;status.textContent='연결 중…';try{const response=await fetch('/login',{method:'POST',mode:'cors',credentials:'same-origin',referrerPolicy:'same-origin',body:new URLSearchParams(new FormData(form))});if(response.ok){form.reset();location.replace('/browse')}else{status.textContent=response.status===401?'연결 코드가 올바르지 않습니다.':response.status===429?'입력 시도가 너무 많습니다. 1분 후 다시 시도하세요.':'연결하지 못했습니다. 페이지를 새로고침하고 다시 시도하세요.'}}catch(error){status.textContent='연결을 확인하고 다시 시도하세요.'}finally{button.disabled=false}};
</script></html>)";
    sendPage(c, body, nonce);
}
static void qrLandingPage(Connection& c, bool httpMode) {
    auto nonce = randomHex(16);
    auto body = pageStart(nonce) + (httpMode ? "<p><strong>비보안 모드 · HTTP</strong> — 연결 정보와 파일이 암호화되지 않습니다.</p>" : "<p><strong>보안 모드 · HTTPS</strong></p>") + R"(<section class=box><p id=status aria-live=polite>QR로 연결 중…</p><a href='/'>수동 연결 화면</a></section><script nonce=')" + nonce + R"('>
(async()=>{const params=new URLSearchParams(location.hash.slice(1));let ticket=params.get('ticket')||'';history.replaceState(null,'','/pair');const status=document.querySelector('#status');if(Array.from(params.keys()).length!==1||!/^[a-f0-9]{64}$/.test(ticket)){status.textContent='올바른 QR 링크가 아닙니다. Windows 앱에서 새 QR을 찍어 주세요.';return}try{const body=new URLSearchParams({ticket});ticket='';params.delete('ticket');const response=await fetch('/pair',{method:'POST',mode:'cors',credentials:'same-origin',referrerPolicy:'same-origin',headers:{'X-Pairing-Request':'1'},body});if(response.ok){location.replace('/browse')}else if(response.status===410||response.status===401){status.textContent='QR이 만료되었거나 이미 사용되었습니다. Windows 앱에서 새 QR을 찍어 주세요.'}else if(response.status===429){status.textContent='연결 시도가 너무 많습니다. 잠시 후 다시 시도하세요.'}else{status.textContent='연결하지 못했습니다. Windows 앱에서 새 QR을 찍어 주세요.'}}catch(error){status.textContent='연결이 끊겼습니다. Wi-Fi를 확인하고 Windows 앱에서 새 QR을 찍어 주세요.'}})();
</script></html>)";
    sendPage(c, body, nonce);
}
static std::string sessionCookie(const State& state, const std::string& id) {
    return "Set-Cookie: " + state.cookieName() + "=" + id + "; Path=/; HttpOnly; SameSite=Strict; Max-Age=" + std::to_string(SESSION_SECONDS) + (state.httpMode ? "" : "; Secure") + "\r\n";
}
static void browse(Connection& c, State& state, const Session& session, const std::string& relative) {
    auto dir = state.folder.directory(relative);
    auto nonce = randomHex(16);
    std::ostringstream body;
    body << pageStart(nonce) << (state.httpMode ? "<p><strong>비보안 모드 · HTTP</strong> — 파일과 연결 코드가 암호화되지 않습니다.</p>" : "<p><strong>보안 모드 · HTTPS</strong> — 암호화 전송 중</p>") << "<div class=row><span>" << escape(relative.empty() ? "공유 폴더" : relative)
         << "</span><button id=logout>연결 종료</button></div>";
    if (!relative.empty()) {
        auto slash = relative.find_last_of('/');
        body << "<p><a href='/browse?dir=" << encode(slash == std::string::npos ? "" : relative.substr(0, slash)) << "'>← 상위 폴더</a></p>";
    }
    if (!state.readOnly) body << R"(<section class=box><form id=upload><label>파일 선택 <input id=files type=file multiple></label><br><label>폴더 선택 <input id=folder type=file multiple webkitdirectory></label><p><small>기존 파일은 덮어쓰지 않습니다. 파일당 최대 2 GiB입니다.</small></p><button id=send>업로드</button><progress id=progress value=0 max=1></progress><p id=status aria-live=polite></p></form></section>)";
    else body << "<p>이 공유는 다운로드만 허용합니다.</p>";
    body << "<h2>파일</h2><ul>";
    struct Item { std::string name; bool directory; uint64_t size; };
    std::vector<Item> entries;
    for (const auto& item : fs::directory_iterator(dir.path, fs::directory_options::skip_permission_denied)) {
        auto name = item.path().filename().u8string();
        if (lower(name).rfind(".sharehub-", 0) == 0) continue;
        DWORD attr = GetFileAttributesW(item.path().c_str());
        if (attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_REPARSE_POINT)) continue;
        bool directory = (attr & FILE_ATTRIBUTE_DIRECTORY) != 0;
        std::error_code error;
        auto size = directory ? 0 : item.file_size(error);
        if (error) continue;
        if (entries.size() == 5000) break;
        entries.push_back({name, directory, size});
    }
    std::sort(entries.begin(), entries.end(), [](const Item& a, const Item& b) {
        return a.directory != b.directory ? a.directory > b.directory : a.name < b.name;
    });
    for (const auto& item : entries) {
        auto path = relative.empty() ? item.name : relative + "/" + item.name;
        body << "<li><a href='" << (item.directory ? "/browse?dir=" : "/download?path=") << encode(path) << "'>"
             << (item.directory ? "📁 " : "📄 ") << escape(item.name) << (item.directory ? "/" : "") << "</a>";
        if (!item.directory) body << " <small>" << item.size << " bytes</small>";
        body << "</li>";
    }
    if (entries.empty()) body << "<li>아직 파일이 없습니다.</li>";
    if (entries.size() == 5000) body << "<li>목록은 최대 5,000개까지 표시됩니다.</li>";
    // User-controlled paths stay in escaped HTML attributes, never in JavaScript source.
    body << "</ul><div id=config data-dir='" << escape(relative) << "' data-csrf='" << session.csrf << "'></div><script nonce='" << nonce << R"('>
const config=document.querySelector('#config').dataset;
const btn=document.querySelector('#logout');if(btn)btn.onclick=async()=>{btn.disabled=true;btn.textContent='종료 중…';try{const r=await fetch('/logout',{method:'POST',mode:'cors',credentials:'same-origin',referrerPolicy:'same-origin',headers:{'X-CSRF-Token':config.csrf},body:''});if(r.ok){if(location.pathname==='/'&&!location.search)location.reload();else location.replace('/');}else{alert(await r.text()||'연결을 종료하지 못했습니다.');btn.disabled=false;btn.textContent='연결 종료';}}catch(e){alert('연결을 종료하지 못했습니다.');btn.disabled=false;btn.textContent='연결 종료';}};
const form=document.querySelector('#upload');
if(form)form.onsubmit=async event=>{event.preventDefault();const files=[...document.querySelector('#files').files,...document.querySelector('#folder').files],button=document.querySelector('#send'),status=document.querySelector('#status'),progress=document.querySelector('#progress');if(!files.length){status.textContent='파일을 선택하세요.';return}button.disabled=true;let count=0;try{for(const file of files){if(file.size>2147483648)throw Error('파일이 2 GiB를 초과합니다: '+file.name);const path=[config.dir,file.webkitRelativePath||file.name].filter(Boolean).join('/');await new Promise((resolve,reject)=>{const xhr=new XMLHttpRequest();xhr.open('POST','/api/upload?path='+encodeURIComponent(path));xhr.setRequestHeader('X-CSRF-Token',config.csrf);xhr.timeout=30*60*1000;xhr.upload.onprogress=e=>{if(e.lengthComputable)progress.value=e.loaded/e.total;status.textContent=`${count+1}/${files.length} · ${file.name}`};xhr.onload=()=>xhr.status===201?resolve():reject(Error(xhr.responseText||'업로드 실패'));xhr.onerror=()=>reject(Error('네트워크 연결이 끊겼습니다.'));xhr.ontimeout=()=>reject(Error('전송 시간이 초과되었습니다.'));xhr.send(file)});count++}status.textContent=`${count}개 파일을 저장했습니다.`;location.reload()}catch(error){status.textContent=error.message}finally{button.disabled=false}};
</script></html>)";
    sendPage(c, body.str(), nonce);
}

static void serve(Connection& c, State& state, const std::string& peer, const std::string& localIp) {
    auto r = readRequest(c); validateOrigin(r, state.httpMode, localIp, state.port);
    if (r.path == "/pair" && r.method == "GET") {
        if (!r.query.empty()) throw HttpError(400, "QR credentials must not be placed in the URL query");
        qrLandingPage(c, state.httpMode); return;
    }
    if (r.path == "/pair" && r.method == "POST") {
        if (!r.query.empty() || r.header("x-pairing-request") != "1" || r.contentType() != "application/x-www-form-urlencoded")
            throw HttpError(400, "Unsupported QR pairing request");
        auto params = parameters(smallBody(c, r, 128));
        if (params.size() != 1 || !params.count("ticket")) throw HttpError(400, "QR ticket is required");
        auto id = state.authentication.loginQr(params.at("ticket"), peer);
        reply(c, 200, "Connected", sessionCookie(state, id)); return;
    }
    if (r.path == "/login" && r.method == "POST") {
        if (r.contentType() != "application/x-www-form-urlencoded") throw HttpError(400, "Unsupported login body");
        auto params = parameters(smallBody(c, r, 128));
        if (params.size() != 1 || !params.count("code")) throw HttpError(400, "A pairing code is required");
        auto id = state.authentication.login(params.at("code"), peer);
        reply(c, 303, "Connected", sessionCookie(state, id) + "Location: /browse\r\n"); return;
    }
    auto id = sessionId(r, state.cookieName()); auto session = state.authentication.get(id);
    if (!session) {
        if (r.method == "GET" && (r.path == "/" || r.path == "/browse")) { loginPage(c, state.httpMode); return; }
        throw HttpError(401, "Session expired or missing; reconnect on the home page");
    }
    if (r.method == "POST" && !constantEqual(r.header("x-csrf-token"), session->csrf)) throw HttpError(403, "Invalid request token");
    if (r.path == "/logout" && r.method == "POST") {
        if (r.length) throw HttpError(400, "Unexpected logout body");
        state.authentication.logout(id);
        reply(c, 200, "Disconnected", "Set-Cookie: " + state.cookieName() + "=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0" + (state.httpMode ? "" : "; Secure") + "\r\n"); return;
    }
    auto params = parameters(r.query);
    if ((r.path == "/browse" || r.path == "/") && r.method == "GET") {
        if (params.size() > 1 || (!params.empty() && !params.count("dir"))) throw HttpError(400, "Invalid folder parameter");
        browse(c, state, *session, params.empty() ? "" : params.at("dir")); return;
    }
    if (params.size() != 1 || !params.count("path")) throw HttpError(404, "Not found");
    const auto& path = params.at("path");
    std::vector<char> buffer(256 * 1024);
    if (r.path == "/download" && r.method == "GET") {
        auto file = state.folder.download(path);
        if (!sendHeaders(c, 200, "application/octet-stream", file.size,
                         "Content-Disposition: attachment; filename*=UTF-8''" + encode(file.name) + "\r\n")) return;
        uint64_t remaining = file.size;
        while (remaining) {
            DWORD n = 0;
            if (!ReadFile(file.handle.get(), buffer.data(), static_cast<DWORD>(std::min<uint64_t>(buffer.size(), remaining)), &n, nullptr) || !n) return;
            if (!c.write(buffer.data(), n)) return;
            remaining -= n;
        }
        std::lock_guard<std::mutex> log(logMutex); std::cout << "[download] " << peer << " " << path << " (" << file.size << " bytes)\n"; return;
    }
    if (r.path == "/api/upload" && r.method == "POST") {
        if (state.readOnly) throw HttpError(403, "This share allows downloads only");
        SharedFolder::Upload upload(state.folder, path);
        uint64_t remaining = r.length;
        if (!r.initialBody.empty()) { upload.write(r.initialBody.data(), static_cast<DWORD>(r.initialBody.size())); remaining -= r.initialBody.size(); }
        auto deadline = Clock::now() + std::chrono::minutes(30);
        while (remaining) {
            if (Clock::now() > deadline) throw HttpError(400, "Upload time limit exceeded");
            int n = c.read(buffer.data(), static_cast<int>(std::min<uint64_t>(buffer.size(), remaining)));
            if (n <= 0) throw HttpError(400, "Upload interrupted; no file was saved");
            upload.write(buffer.data(), n); remaining -= n;
        }
        upload.commit();
        { std::lock_guard<std::mutex> log(logMutex); std::cout << "[upload] " << peer << " " << path << " (" << r.length << " bytes)\n"; }
        reply(c, 201, "Saved"); return;
    }
    throw HttpError(404, "Not found");
}

class Workers {
    struct Job { SOCKET socket; std::string peer, local; };
    std::mutex mutex_;
    std::condition_variable ready_;
    std::deque<Job> queue_;
    bool stop_ = false;
    std::vector<std::thread> workers_;
public:
    Workers(State& state, TlsServer* tls) {
        for (int i = 0; i < 8; ++i) workers_.emplace_back([this, &state, tls] {
            for (;;) {
                Job job;
                { std::unique_lock<std::mutex> lock(mutex_); ready_.wait(lock, [this] { return stop_ || !queue_.empty(); });
                  if (stop_) return;
                  job = std::move(queue_.front()); queue_.pop_front(); }
                try {
                    Connection c(job.socket, tls);
                    DWORD timeout = 30000;
                    setsockopt(job.socket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char*>(&timeout), sizeof(timeout));
                    try { serve(c, state, job.peer, job.local); }
                    catch (const HttpError& e) { reply(c, e.status, e.what(), e.status == 429 ? "Retry-After: 60\r\n" : ""); }
                    catch (...) { reply(c, 500, "Request failed"); }
                } catch (...) { /* TLS failures never fall back to plaintext or expose credential details. */ }
                // Send FIN after the response, then briefly drain already arriving
                // request bytes. Closing with unread bytes can reset the connection
                // and hide a useful 403/409 error from Safari.
                shutdown(job.socket, SD_SEND);
                auto drainDeadline = Clock::now() + std::chrono::milliseconds(500);
                std::array<char, 8192> discard{}; size_t drained = 0;
                while (Clock::now() < drainDeadline && drained < 1024 * 1024) {
                    fd_set reads; FD_ZERO(&reads); FD_SET(job.socket, &reads);
                    timeval wait{0, 100000};
                    if (select(0, &reads, nullptr, nullptr, &wait) <= 0) break;
                    int n = recv(job.socket, discard.data(), static_cast<int>(discard.size()), 0);
                    if (n <= 0) break;
                    drained += n;
                }
                closesocket(job.socket);
            }
        });
    }
    ~Workers() {
        { std::lock_guard<std::mutex> lock(mutex_); stop_ = true; for (auto& job : queue_) closesocket(job.socket); queue_.clear(); }
        ready_.notify_all(); for (auto& worker : workers_) worker.join();
    }
    bool add(SOCKET socket, std::string peer, std::string local) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (queue_.size() >= 8 || stop_) return false;
        queue_.push_back({socket, std::move(peer), std::move(local)}); ready_.notify_one(); return true;
    }
};

static BOOL WINAPI stopServer(DWORD event) {
    if (event == CTRL_C_EVENT || event == CTRL_BREAK_EVENT || event == CTRL_CLOSE_EVENT) {
        auto socket = listener.exchange(INVALID_SOCKET);
        if (socket != INVALID_SOCKET) closesocket(socket);
        return TRUE;
    }
    return FALSE;
}
static std::vector<std::string> localAddresses() {
    char hostname[256]{}; gethostname(hostname, sizeof(hostname));
    addrinfo hints{}, *results = nullptr; hints.ai_family = AF_INET;
    std::vector<std::string> addresses;
    if (getaddrinfo(hostname, nullptr, &hints, &results) == 0) {
        for (auto p = results; p; p = p->ai_next) {
            auto* addr = reinterpret_cast<sockaddr_in*>(p->ai_addr); char text[INET_ADDRSTRLEN]{};
            if (!privateIp(addr->sin_addr.s_addr) || (ntohl(addr->sin_addr.s_addr) >> 24) == 127) continue;
            inet_ntop(AF_INET, &addr->sin_addr, text, sizeof(text));
            if (std::find(addresses.begin(), addresses.end(), text) == addresses.end()) addresses.push_back(text);
        }
        freeaddrinfo(results);
    }
    return addresses;
}
int main() {
    SetConsoleOutputCP(CP_UTF8);
    SetProcessDPIAware(); // Keep QR modules on physical pixel boundaries.
    try {
        int argc; LPWSTR* raw = CommandLineToArgvW(GetCommandLineW(), &argc);
        if (!raw) throw std::runtime_error("Cannot read arguments");
        std::vector<std::wstring> args(raw, raw + argc); LocalFree(raw);
        fs::path folder = L"Shared"; bool httpMode = false, readOnly = false, forceLoopback = false, noQrWindow = false;
        std::string bindAddress = "0.0.0.0"; int port = 8765, qrSeconds = 120; std::wstring thumbprint;
        for (size_t i = 1; i < args.size(); ++i) {
            auto arg = args[i];
            if (arg == L"--local-http") { httpMode = true; forceLoopback = true; }
            else if (arg == L"--read-only") readOnly = true;
            else if (arg == L"--no-qr-window") noQrWindow = true;
            else if (arg == L"--folder" || arg == L"--port" || arg == L"--bind" || arg == L"--cert-thumbprint" || arg == L"--mode" || arg == L"--qr-seconds") {
                if (++i >= args.size()) throw std::runtime_error("Missing option value");
                if (arg == L"--mode") {
                    if (args[i] != L"secure" && args[i] != L"basic") throw std::runtime_error("Mode must be secure or basic");
                    httpMode = args[i] == L"basic";
                }
                else if (arg == L"--folder") folder = fs::path(args[i]);
                else if (arg == L"--cert-thumbprint") thumbprint = args[i];
                else if (arg == L"--bind") bindAddress.assign(args[i].begin(), args[i].end());
                else {
                    if (args[i].empty() || args[i].find_first_not_of(L"0123456789") != std::wstring::npos) throw std::runtime_error("Invalid numeric option");
                    unsigned long p = std::stoul(args[i]);
                    if (arg == L"--qr-seconds") {
                        if (p < 5 || p > 300) throw std::runtime_error("QR validity must be 5 to 300 seconds");
                        qrSeconds = static_cast<int>(p);
                    } else { if (p < 1 || p > 65535) throw std::runtime_error("Invalid port"); port = static_cast<int>(p); }
                }
            } else if (arg == L"--help") {
                std::cout << "sharehub.exe [--mode secure|basic] [--folder PATH] [--port 8765] [--bind IPv4] [--read-only]\n"
                          << "QR pairing window opens by default. --qr-seconds 5..300 sets QR validity (default120).\n"
                          << "--no-qr-window prints a one-use QR link instead. HTTPS requires setup-https.ps1 first.\n"
                          << "--local-http is loopback-only for development.\n"; return 0;
            } else throw std::runtime_error("Unknown option; run --help");
        }
        if (forceLoopback) {
            if (bindAddress != "0.0.0.0" && bindAddress != "127.0.0.1") throw std::runtime_error("--local-http cannot bind a LAN interface");
            bindAddress = "127.0.0.1";
        }
        IN_ADDR bindIp{};
        if (inet_pton(AF_INET, bindAddress.c_str(), &bindIp) != 1 || (bindAddress != "0.0.0.0" && !privateIp(bindIp.s_addr)))
            throw std::runtime_error("Bind to a private or loopback IPv4 address");
        std::unique_ptr<TlsServer> tls;
        if (!httpMode) {
            if (thumbprint.empty()) {
                std::ifstream config("tls-cert.txt"); std::string value; std::getline(config, value);
                value = trim(value); thumbprint.assign(value.begin(), value.end());
            }
            if (thumbprint.empty()) throw std::runtime_error("HTTPS certificate not configured. Run setup-https.ps1, or explicitly choose --mode basic for unencrypted HTTP.");
            tls = std::make_unique<TlsServer>(thumbprint);
        }
        State state(folder, httpMode, readOnly, port, qrSeconds);
        WSADATA wsa{}; if (WSAStartup(MAKEWORD(2, 2), &wsa)) throw std::runtime_error("Winsock initialization failed");
        struct WsaCleanup { ~WsaCleanup() { WSACleanup(); } } cleanup;
        SOCKET server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (server == INVALID_SOCKET) throw std::runtime_error("Socket creation failed");
        BOOL exclusive = TRUE; setsockopt(server, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<char*>(&exclusive), sizeof(exclusive));
        sockaddr_in address{}; address.sin_family = AF_INET; address.sin_port = htons(static_cast<u_short>(port)); address.sin_addr = bindIp;
        if (bind(server, reinterpret_cast<sockaddr*>(&address), sizeof(address)) || listen(server, 16)) {
            closesocket(server); throw std::runtime_error("Cannot open port; it may already be in use");
        }
        listener = server; SetConsoleCtrlHandler(stopServer, TRUE);
        std::cout << "ShareHub " << (httpMode ? "BASIC MODE (HTTP, NOT ENCRYPTED)" : "SECURE MODE (HTTPS)") << "\nFolder: " << state.folder.root().u8string() << "\n";
        auto addresses = bindAddress == "0.0.0.0" ? localAddresses() : std::vector<std::string>{bindAddress};
        if (addresses.empty()) addresses.push_back("127.0.0.1");
        std::vector<std::string> origins;
        for (const auto& ip : addresses) {
            // Browsers omit default ports when serializing Origin/Host.
            auto suffix = port == (httpMode ? 80 : 443) ? "" : ":" + std::to_string(port);
            auto origin = (httpMode ? "http://" : "https://") + ip + suffix;
            origins.push_back(origin); std::cout << origin << "/\n";
        }
        if (noQrWindow) {
            auto ticket = state.authentication.issueQrTicket();
            std::cout << "QR pairing link: " << origins.front() << "/pair#ticket=" << ticket << "\n";
        }
        std::cout << "Pairing code: " << state.authentication.pairing() << "\n"
                  << "Sessions expire in 30 minutes. " << (readOnly ? "Download only. " : "Existing files are never overwritten. ")
                  << "Press Ctrl+C to stop.\n" << std::flush;
        if (httpMode) std::cout << "HTTP does not encrypt pairing codes or files.\n" << std::flush;
        Workers workers(state, tls.get());
        std::unique_ptr<PairingWindow> qrWindow;
        if (!noQrWindow) {
            qrWindow = std::make_unique<PairingWindow>(origins, httpMode,
                [&state] { return state.authentication.issueQrTicket(); },
                [&state](const std::string& ticket) { return state.authentication.qrStatus(ticket); },
                [] { auto socket = listener.exchange(INVALID_SOCKET); if (socket != INVALID_SOCKET) closesocket(socket); });
        }
        for (;;) {
            sockaddr_in remote{}; int remoteSize = sizeof(remote);
            SOCKET client = accept(server, reinterpret_cast<sockaddr*>(&remote), &remoteSize);
            if (client == INVALID_SOCKET) break;
            if (!privateIp(remote.sin_addr.s_addr)) { closesocket(client); continue; }
            DWORD timeout = 10000; int bufferSize = 1024 * 1024;
            setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char*>(&timeout), sizeof(timeout));
            setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<char*>(&timeout), sizeof(timeout));
            setsockopt(client, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<char*>(&bufferSize), sizeof(bufferSize));
            setsockopt(client, SOL_SOCKET, SO_SNDBUF, reinterpret_cast<char*>(&bufferSize), sizeof(bufferSize));
            BOOL noDelay = TRUE;
            setsockopt(client, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<char*>(&noDelay), sizeof(noDelay));
            sockaddr_in local{}; int localSize = sizeof(local); getsockname(client, reinterpret_cast<sockaddr*>(&local), &localSize);
            char peerText[INET_ADDRSTRLEN]{}, localText[INET_ADDRSTRLEN]{};
            inet_ntop(AF_INET, &remote.sin_addr, peerText, sizeof(peerText)); inet_ntop(AF_INET, &local.sin_addr, localText, sizeof(localText));
            if (!workers.add(client, peerText, localText)) closesocket(client);
        }
        auto open = listener.exchange(INVALID_SOCKET); if (open != INVALID_SOCKET) closesocket(open);
        SetConsoleCtrlHandler(stopServer, FALSE);
    } catch (const std::exception& e) { std::cerr << "ShareHub: " << e.what() << "\n"; return 1; }
    return 0;
}
