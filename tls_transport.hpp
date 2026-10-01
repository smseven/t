#pragma once
#ifndef SECURITY_WIN32
#define SECURITY_WIN32
#endif
#include <winsock2.h>
#include <windows.h>
#include <security.h>
#include <schannel.h>
#include <wincrypt.h>
#include <vector>
#include <string>
#include <stdexcept>
#include <algorithm>
#include <cstring>
#ifdef _MSC_VER
#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "crypt32.lib")
#endif

// Socket ownership belongs to the caller. Each connection is used by one worker.
class TlsServer {
    CredHandle credential_{};
    bool acquired_ = false;
    friend class TlsConnection;
public:
    explicit TlsServer(const std::wstring& thumbprint) {
        BYTE hash[20]{}; size_t n = 0; int high = -1;
        for (wchar_t c : thumbprint) {
            if (c == L' ' || c == L'\r' || c == L'\n' || c == L'\t') continue;
            int v = c >= L'0' && c <= L'9' ? c-L'0' : c >= L'a' && c <= L'f' ? c-L'a'+10 : c >= L'A' && c <= L'F' ? c-L'A'+10 : -1;
            if (v < 0 || n >= sizeof(hash)) throw std::runtime_error("Invalid certificate thumbprint");
            if (high < 0) high = v; else { hash[n++] = BYTE(high*16+v); high = -1; }
        }
        if (n != sizeof(hash) || high >= 0) throw std::runtime_error("Certificate thumbprint must contain 40 hexadecimal digits");
        HCERTSTORE store = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_READONLY_FLAG, L"MY");
        if (!store) throw std::runtime_error("Cannot open Windows certificate store");
        CRYPT_HASH_BLOB blob{sizeof(hash), hash};
        PCCERT_CONTEXT cert = CertFindCertificateInStore(store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_SHA1_HASH, &blob, nullptr);
        if (!cert) { CertCloseStore(store, 0); throw std::runtime_error("HTTPS certificate not found; run setup-https.ps1"); }
        bool serverAuth=false, isCA=false;
        DWORD usageSize=0;
        if (CertGetEnhancedKeyUsage(cert,0,nullptr,&usageSize) && usageSize) {
            std::vector<BYTE> usageBytes(usageSize);
            auto usage=reinterpret_cast<PCERT_ENHKEY_USAGE>(usageBytes.data());
            if (CertGetEnhancedKeyUsage(cert,0,usage,&usageSize))
                for (DWORD i=0;i<usage->cUsageIdentifier;++i) if (std::strcmp(usage->rgpszUsageIdentifier[i],szOID_PKIX_KP_SERVER_AUTH)==0) serverAuth=true;
        }
        PCERT_EXTENSION constraints=CertFindExtension(szOID_BASIC_CONSTRAINTS2,cert->pCertInfo->cExtension,cert->pCertInfo->rgExtension);
        if (constraints) {
            PCERT_BASIC_CONSTRAINTS2_INFO decoded=nullptr; DWORD decodedSize=0;
            if (!CryptDecodeObjectEx(X509_ASN_ENCODING,X509_BASIC_CONSTRAINTS2,constraints->Value.pbData,constraints->Value.cbData,CRYPT_DECODE_ALLOC_FLAG,nullptr,&decoded,&decodedSize)) isCA=true;
            else { isCA=decoded->fCA != FALSE; LocalFree(decoded); }
        }
        if (!serverAuth || isCA) { CertFreeCertificateContext(cert); CertCloseStore(store,0); throw std::runtime_error("HTTPS requires a server-authentication leaf certificate"); }
        if (CertVerifyTimeValidity(nullptr, cert->pCertInfo) != 0) { CertFreeCertificateContext(cert); CertCloseStore(store,0); throw std::runtime_error("HTTPS certificate has expired or is not yet valid"); }
        SCHANNEL_CRED config{}; config.dwVersion = SCHANNEL_CRED_VERSION;
        config.cCreds = 1; config.paCred = &cert;
        // TLS 1.2 only: broadly compatible and rejects legacy protocols. TLS 1.3
        // requires newer SCH_CREDENTIALS support and post-handshake handling.
        config.grbitEnabledProtocols = SP_PROT_TLS1_2_SERVER;
        config.dwFlags = SCH_USE_STRONG_CRYPTO;
        TimeStamp expiry{};
        SECURITY_STATUS result = AcquireCredentialsHandleW(nullptr, const_cast<wchar_t*>(UNISP_NAME_W), SECPKG_CRED_INBOUND, nullptr, &config, nullptr, nullptr, &credential_, &expiry);
        CertFreeCertificateContext(cert); CertCloseStore(store,0);
        if (result != SEC_E_OK) throw std::runtime_error("Cannot acquire HTTPS private key credentials");
        acquired_ = true;
    }
    ~TlsServer() { if (acquired_) FreeCredentialsHandle(&credential_); }
    TlsServer(const TlsServer&) = delete;
    TlsServer& operator=(const TlsServer&) = delete;
};

class TlsConnection {
    SOCKET socket_; CtxtHandle context_{}; bool initialized_ = false;
    SecPkgContext_StreamSizes sizes_{};
    std::vector<char> encrypted_, plaintext_; size_t plainOffset_ = 0;
    static constexpr size_t MAX_BUFFER = 256 * 1024;
    bool rawWrite(const char* p, size_t n) {
        while (n) { int sent = ::send(socket_, p, int((std::min)(n,size_t(65536))),0); if (sent <= 0) return false; p += sent; n -= sent; } return true;
    }
    bool receive() {
        if (encrypted_.size() >= MAX_BUFFER) return false;
        char data[32768]; int n = ::recv(socket_,data,int((std::min)(sizeof(data),MAX_BUFFER-encrypted_.size())),0);
        if (n <= 0) return false;
        encrypted_.insert(encrypted_.end(),data,data+n); return true;
    }
    void keepExtra(ULONG extra) {
        if (extra > encrypted_.size()) throw std::runtime_error("Invalid TLS buffer");
        if (extra) std::memmove(encrypted_.data(), encrypted_.data()+encrypted_.size()-extra,extra);
        encrypted_.resize(extra);
    }
public:
    TlsConnection(SOCKET socket, TlsServer& server) : socket_(socket) {
        SecInvalidateHandle(&context_);
        DWORD oldReceiveTimeout=0; int timeoutLength=sizeof(oldReceiveTimeout);
        getsockopt(socket_,SOL_SOCKET,SO_RCVTIMEO,reinterpret_cast<char*>(&oldReceiveTimeout),&timeoutLength);
        try {
            const ULONGLONG deadline = GetTickCount64()+15000;
            size_t total = 0;
            for (unsigned rounds=0; rounds<128; ++rounds) {
                ULONGLONG now=GetTickCount64();
                if (now >= deadline) throw std::runtime_error("TLS handshake timeout");
                DWORD remaining=DWORD(deadline-now);
                if (setsockopt(socket_,SOL_SOCKET,SO_RCVTIMEO,reinterpret_cast<const char*>(&remaining),sizeof(remaining)) != 0)
                    throw std::runtime_error("Cannot set TLS handshake timeout");
                if (encrypted_.empty() && !receive()) throw std::runtime_error("TLS handshake disconnected");
                SecBuffer input[2]{{ULONG(encrypted_.size()),SECBUFFER_TOKEN,encrypted_.data()},{0,SECBUFFER_EMPTY,nullptr}};
                SecBuffer output{0,SECBUFFER_TOKEN,nullptr};
                SecBufferDesc in{SECBUFFER_VERSION,2,input}, out{SECBUFFER_VERSION,1,&output};
                ULONG attributes=0; TimeStamp expiry{};
                SECURITY_STATUS status = AcceptSecurityContext(&server.credential_, initialized_ ? &context_ : nullptr, &in,
                    ASC_REQ_SEQUENCE_DETECT | ASC_REQ_REPLAY_DETECT | ASC_REQ_CONFIDENTIALITY | ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_STREAM,
                    SECURITY_NATIVE_DREP,&context_,&out,&attributes,&expiry);
                if (SecIsValidHandle(&context_)) initialized_ = true;
                bool sent = true;
                if (output.pvBuffer) { sent = rawWrite(static_cast<char*>(output.pvBuffer),output.cbBuffer); FreeContextBuffer(output.pvBuffer); }
                if (!sent) throw std::runtime_error("TLS handshake write failed");
                if (status == SEC_E_INCOMPLETE_MESSAGE) {
                    size_t before = encrypted_.size(); if (!receive()) throw std::runtime_error("Incomplete TLS handshake");
                    total += encrypted_.size()-before;
                } else {
                    if (status != SEC_E_OK && status != SEC_I_CONTINUE_NEEDED) throw std::runtime_error("TLS negotiation failed");
                    keepExtra(input[1].BufferType == SECBUFFER_EXTRA ? input[1].cbBuffer : 0);
                    if (status == SEC_E_OK) {
                        if (!(attributes & ASC_RET_CONFIDENTIALITY) || QueryContextAttributes(&context_, SECPKG_ATTR_STREAM_SIZES,&sizes_) != SEC_E_OK || !sizes_.cbMaximumMessage)
                            throw std::runtime_error("TLS stream unavailable");
                        setsockopt(socket_,SOL_SOCKET,SO_RCVTIMEO,reinterpret_cast<const char*>(&oldReceiveTimeout),sizeof(oldReceiveTimeout));
                        return;
                    }
                }
                if (total > MAX_BUFFER) throw std::runtime_error("TLS handshake size exceeded");
            }
            throw std::runtime_error("TLS handshake round limit exceeded");
        } catch (...) { setsockopt(socket_,SOL_SOCKET,SO_RCVTIMEO,reinterpret_cast<const char*>(&oldReceiveTimeout),sizeof(oldReceiveTimeout)); if (initialized_) DeleteSecurityContext(&context_); initialized_=false; throw; }
    }
    ~TlsConnection() { if (initialized_) DeleteSecurityContext(&context_); }
    TlsConnection(const TlsConnection&) = delete;
    TlsConnection& operator=(const TlsConnection&) = delete;
    int read(char* buffer,int length) {
        if (length <= 0) return 0;
        for (;;) {
            if (plainOffset_ < plaintext_.size()) {
                size_t n = (std::min)(size_t(length),plaintext_.size()-plainOffset_);
                std::memcpy(buffer,plaintext_.data()+plainOffset_,n); plainOffset_ += n; return int(n);
            }
            plaintext_.clear(); plainOffset_=0;
            if (encrypted_.empty() && !receive()) return -1;
            SecBuffer b[4]{{ULONG(encrypted_.size()),SECBUFFER_DATA,encrypted_.data()},{0,SECBUFFER_EMPTY,nullptr},{0,SECBUFFER_EMPTY,nullptr},{0,SECBUFFER_EMPTY,nullptr}};
            SecBufferDesc desc{SECBUFFER_VERSION,4,b};
            SECURITY_STATUS status=DecryptMessage(&context_,&desc,0,nullptr);
            if (status == SEC_E_INCOMPLETE_MESSAGE) { if (!receive()) return -1; continue; }
            if (status == SEC_I_CONTEXT_EXPIRED) return 0;
            // Renegotiation is deliberately rejected to bound protocol complexity.
            if (status != SEC_E_OK) return -1;
            ULONG extra=0;
            for (auto& item : b) {
                if (item.BufferType == SECBUFFER_DATA && item.cbBuffer) {
                    auto p=static_cast<char*>(item.pvBuffer); plaintext_.insert(plaintext_.end(),p,p+item.cbBuffer);
                }
                if (item.BufferType == SECBUFFER_EXTRA) extra=item.cbBuffer;
            }
            keepExtra(extra);
        }
    }
    bool writeAll(const char* data,size_t length) {
        while (length) {
            ULONG chunk=ULONG((std::min)(length,size_t(sizes_.cbMaximumMessage)));
            std::vector<char> record(size_t(sizes_.cbHeader)+chunk+sizes_.cbTrailer);
            std::memcpy(record.data()+sizes_.cbHeader,data,chunk);
            SecBuffer b[4]{{sizes_.cbHeader,SECBUFFER_STREAM_HEADER,record.data()},{chunk,SECBUFFER_DATA,record.data()+sizes_.cbHeader},{sizes_.cbTrailer,SECBUFFER_STREAM_TRAILER,record.data()+sizes_.cbHeader+chunk},{0,SECBUFFER_EMPTY,nullptr}};
            SecBufferDesc desc{SECBUFFER_VERSION,4,b};
            if (EncryptMessage(&context_,0,&desc,0) != SEC_E_OK) return false;
            for (int i=0;i<3;++i) if (!rawWrite(static_cast<char*>(b[i].pvBuffer),b[i].cbBuffer)) return false;
            data+=chunk; length-=chunk;
        }
        return true;
    }
};
