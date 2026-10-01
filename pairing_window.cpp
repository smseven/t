#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include "pairing_window.hpp"
#include "third_party/qrcodegen.hpp"
#include <atomic>
#include <future>
#include <thread>
#include <stdexcept>

namespace {
std::wstring wide(const std::string& s) {
    int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), (int)s.size(), nullptr, 0);
    if (!n && !s.empty()) throw std::runtime_error("Invalid UTF-8 pairing origin");
    std::wstring w(n, L' ');
    if (n) MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), (int)s.size(), &w[0], n);
    return w;
}
}

struct PairingWindow::Impl {
    std::vector<std::string> origins;
    bool http;
    std::function<std::string()> issue;
    std::function<int(const std::string&)> status;
    std::function<void()> stop;
    std::thread thread;
    std::atomic<HWND> window{nullptr};
    std::atomic<bool> disposing{false};
    HWND combo = nullptr, label = nullptr;
    HFONT font = nullptr;
    std::unique_ptr<qrcodegen::QrCode> qr;
    std::string ticket;
    bool active = false, stopSent = false;
    int previous = -999;

    Impl(std::vector<std::string> o, bool h, std::function<std::string()> i,
         std::function<int(const std::string&)> s, std::function<void()> e)
        : origins(std::move(o)), http(h), issue(std::move(i)), status(std::move(s)), stop(std::move(e)) {}

    void refresh() {
        int left = status(ticket);
        if (left == previous) return;
        previous = left;
        active = left > 0;
        std::wstring text = left > 0 ? L"페어링 가능 · 남은 시간 " + std::to_wstring(left) + L"초" :
            left == -1 ? L"페어링 완료 · 새 기기는 새 QR을 만드세요" :
            left == -2 ? L"교체된 QR · 새 QR을 만드세요" : L"QR 만료 · 새 QR을 만드세요";
        SetWindowTextW(label, text.c_str());
        InvalidateRect(window.load(), nullptr, FALSE);
    }
    void generate() {
        active = false;
        qr.reset();
        ticket.clear();
        previous = -999;
        try {
            auto t = issue();
            if (t.size() != 64 || t.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos)
                throw std::runtime_error("Invalid pairing ticket");
            auto index = SendMessageW(combo, CB_GETCURSEL, 0, 0);
            if (index < 0 || (size_t)index >= origins.size()) throw std::runtime_error("No pairing origin");
            auto value = qrcodegen::QrCode::encodeText((origins[index] + "/pair#ticket=" + t).c_str(), qrcodegen::QrCode::Ecc::MEDIUM);
            ticket = std::move(t);
            qr.reset(new qrcodegen::QrCode(std::move(value)));
            refresh();
        } catch (...) {
            SetWindowTextW(label, L"QR 생성 실패 · 새 QR 버튼으로 다시 시도하세요");
            InvalidateRect(window.load(), nullptr, FALSE);
            throw;
        }
    }
    void paint(HWND hwnd) {
        PAINTSTRUCT ps; HDC dc = BeginPaint(hwnd, &ps);
        RECT r; GetClientRect(hwnd, &r);
        FillRect(dc, &r, (HBRUSH)GetStockObject(WHITE_BRUSH));
        auto old = SelectObject(dc, font); SetBkMode(dc, TRANSPARENT);
        SetTextColor(dc, http ? RGB(180,45,20) : RGB(20,90,50));
        RECT mode{24,14,r.right-24,44};
        DrawTextW(dc, http ? L"비보안 모드 · HTTP · 전송 암호화 없음" : L"보안 모드 · HTTPS 암호화", -1, &mode, DT_LEFT);
        SetTextColor(dc, RGB(25,25,25));
        RECT hint{24,100,r.right-24,185};
        DrawTextW(dc, http ? L"1. PC와 아이폰을 같은 Wi-Fi에 연결하세요.\n2. 아이폰 카메라로 QR을 찍고 링크를 누르면\n   자동 연결됩니다." : L"1. PC와 아이폰을 같은 Wi-Fi에 연결하세요.\n2. 아이폰에서 설정한 인증서를 신뢰해야 합니다.\n3. 카메라로 QR을 찍고 링크를 누르면 자동 연결됩니다.", -1, &hint, DT_LEFT | DT_WORDBREAK);
        RECT area{24,194,r.right-24,r.bottom-65};
        if (active && qr) {
            int modules = qr->getSize(), total = modules + 8;
            int scale = std::min(area.right-area.left, area.bottom-area.top)/total;
            if (scale > 0) {
                int x0 = (r.right-total*scale)/2, y0 = area.top + (area.bottom-area.top-total*scale)/2;
                for(int y=0;y<modules;y++) for(int x=0;x<modules;x++) if(qr->getModule(x,y)) {
                    RECT cell{x0+(x+4)*scale,y0+(y+4)*scale,x0+(x+5)*scale,y0+(y+5)*scale};
                    FillRect(dc,&cell,(HBRUSH)GetStockObject(BLACK_BRUSH));
                }
            }
        } else DrawTextW(dc, L"QR이 비활성화되었습니다.\n새 QR을 만들어 주세요.", -1, &area, DT_CENTER | DT_VCENTER | DT_WORDBREAK);
        SelectObject(dc,old); EndPaint(hwnd,&ps);
    }
    static LRESULT CALLBACK proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
        Impl* self = reinterpret_cast<Impl*>(GetWindowLongPtrW(hwnd,GWLP_USERDATA));
        if(msg == WM_NCCREATE) {
            self = static_cast<Impl*>(reinterpret_cast<CREATESTRUCTW*>(lp)->lpCreateParams);
            SetWindowLongPtrW(hwnd,GWLP_USERDATA,reinterpret_cast<LONG_PTR>(self));
            self->window.store(hwnd);
        }
        if(!self) return DefWindowProcW(hwnd,msg,wp,lp);
        switch(msg) {
        case WM_PAINT: self->paint(hwnd); return 0;
        case WM_COMMAND:
            if(LOWORD(wp)==2 || (LOWORD(wp)==1 && HIWORD(wp)==CBN_SELCHANGE)) {
                try { self->generate(); } catch (...) {} return 0;
            } break;
        case WM_TIMER:
            try { self->refresh(); } catch (...) { self->active=false; InvalidateRect(hwnd,nullptr,FALSE); } return 0;
        case WM_CLOSE:
            if(!self->disposing.load() && !self->stopSent) {
                self->stopSent=true;
                try { self->stop(); } catch (...) {}
            }
            DestroyWindow(hwnd); return 0;
        case WM_DESTROY: KillTimer(hwnd,1); PostQuitMessage(0); return 0;
        case WM_NCDESTROY: self->window.store(nullptr); break;
        }
        return DefWindowProcW(hwnd,msg,wp,lp);
    }
    void run(std::promise<void> ready) {
        bool announced=false;
        try {
            HINSTANCE instance = GetModuleHandleW(nullptr);
            WNDCLASSW wc{}; wc.lpfnWndProc=proc; wc.hInstance=instance; wc.lpszClassName=L"ShareHubPairingWindowV1";
            wc.hCursor=LoadCursorW(nullptr,MAKEINTRESOURCEW(32512)); wc.hbrBackground=(HBRUSH)GetStockObject(WHITE_BRUSH);
            if(!RegisterClassW(&wc) && GetLastError()!=ERROR_CLASS_ALREADY_EXISTS) throw std::runtime_error("Cannot register pairing window");
            HWND hwnd=CreateWindowExW(0,wc.lpszClassName,L"ShareHub · 아이폰 QR 페어링",WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_MINIMIZEBOX,
                CW_USEDEFAULT,CW_USEDEFAULT,570,740,nullptr,nullptr,instance,this);
            if(!hwnd) throw std::runtime_error("Cannot create pairing window");
            font=CreateFontW(-18,0,0,0,FW_NORMAL,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,DEFAULT_QUALITY,DEFAULT_PITCH,L"Malgun Gothic");
            combo=CreateWindowExW(0,L"COMBOBOX",L"",WS_CHILD|WS_VISIBLE|WS_TABSTOP|CBS_DROPDOWNLIST|WS_VSCROLL,24,52,350,240,hwnd,(HMENU)1,instance,nullptr);
            HWND button=CreateWindowExW(0,L"BUTTON",L"새 QR",WS_CHILD|WS_VISIBLE|WS_TABSTOP,390,52,130,32,hwnd,(HMENU)2,instance,nullptr);
            label=CreateWindowExW(0,L"STATIC",L"",WS_CHILD|WS_VISIBLE|SS_CENTER,18,640,530,40,hwnd,nullptr,instance,nullptr);
            if(!combo || !button || !label || !font) throw std::runtime_error("Cannot create pairing controls");
            for(HWND control:{combo,button,label}) SendMessageW(control,WM_SETFONT,(WPARAM)font,TRUE);
            for(const auto& origin:origins) SendMessageW(combo,CB_ADDSTRING,0,(LPARAM)wide(origin).c_str());
            SendMessageW(combo,CB_SETCURSEL,0,0);
            generate();
            if(!SetTimer(hwnd,1,1000,nullptr)) throw std::runtime_error("Cannot create pairing timer");
            ShowWindow(hwnd,SW_SHOW); UpdateWindow(hwnd);
            ready.set_value(); announced=true;
            MSG msg;
            while(GetMessageW(&msg,nullptr,0,0)>0) { if(!IsDialogMessageW(hwnd,&msg)) {TranslateMessage(&msg);DispatchMessageW(&msg);} }
        } catch (...) { if(!announced) ready.set_exception(std::current_exception()); }
        if(HWND hwnd=window.load()) DestroyWindow(hwnd);
        if(font) {DeleteObject(font);font=nullptr;}
    }
};

PairingWindow::PairingWindow(std::vector<std::string> origins,bool httpMode,
    std::function<std::string()> issueTicket,std::function<int(const std::string&)> ticketStatus,std::function<void()> stopServer) {
    if(origins.empty() || !issueTicket || !ticketStatus || !stopServer) throw std::invalid_argument("Missing pairing window configuration");
    impl_.reset(new Impl(std::move(origins),httpMode,std::move(issueTicket),std::move(ticketStatus),std::move(stopServer)));
    std::promise<void> ready; auto future=ready.get_future();
    impl_->thread=std::thread([this,p=std::move(ready)]() mutable {impl_->run(std::move(p));});
    try {future.get();} catch (...) {impl_->thread.join();throw;}
}
PairingWindow::~PairingWindow() {
    impl_->disposing.store(true);
    if(HWND hwnd=impl_->window.load()) PostMessageW(hwnd,WM_CLOSE,0,0);
    if(impl_->thread.joinable()) impl_->thread.join();
}
