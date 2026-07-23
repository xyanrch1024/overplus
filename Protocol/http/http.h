#pragma once

#include <cstdint>
#include <string>

class HttpRequest {
public:
    bool unstream(std::string& buf);

    std::string host;
    uint16_t port = 443;
};

class HttpResponse {
public:
    static void ok(std::string& buf);
};
