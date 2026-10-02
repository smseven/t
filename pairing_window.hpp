#pragma once
#include <functional>
#include <memory>
#include <string>
#include <vector>

// Callbacks must remain valid until this object is destroyed. They run on the UI thread.
class PairingWindow {
public:
    PairingWindow(std::vector<std::string> origins, bool httpMode,
                  std::function<std::string()> issueTicket,
                  std::function<int(const std::string&)> ticketStatus,
                  std::function<bool()> takeRefreshRequest,
                  std::function<void()> stopServer);
    ~PairingWindow();
    PairingWindow(const PairingWindow&) = delete;
    PairingWindow& operator=(const PairingWindow&) = delete;
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
