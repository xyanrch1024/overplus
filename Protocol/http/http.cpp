#include "http.h"
#include <algorithm>
#include <cctype>

bool HttpRequest::unstream(std::string& buf)
{
    auto line_end = buf.find("\r\n");
    if (line_end == std::string::npos)
        return false;

    std::string line = buf.substr(0, line_end);

    if (line.substr(0, 8) != "CONNECT ")
        return false;

    std::string address = line.substr(8);

    auto space_pos = address.find(' ');
    if (space_pos != std::string::npos)
        address = address.substr(0, space_pos);

    auto colon_pos = address.find(':');
    if (colon_pos != std::string::npos) {
        host = address.substr(0, colon_pos);
        port = static_cast<uint16_t>(std::stoi(address.substr(colon_pos + 1)));
    } else {
        host = address;
        port = 443;
    }

    return !host.empty();
}

void HttpResponse::ok(std::string& buf)
{
    buf = "HTTP/1.1 200 Connection Established\r\n\r\n";
}
