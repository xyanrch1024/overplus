#pragma once

#include <string>

#ifdef _WIN32
#include <windows.h>
inline std::string ToUTF8(const std::string& src)
{
    if (src.empty())
        return src;
    int wlen = MultiByteToWideChar(CP_ACP, 0, src.c_str(), (int)src.size(), nullptr, 0);
    if (wlen <= 0)
        return src;
    std::wstring wstr(wlen, L'\0');
    MultiByteToWideChar(CP_ACP, 0, src.c_str(), (int)src.size(), &wstr[0], wlen);
    int ulen = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), wlen, nullptr, 0, nullptr, nullptr);
    if (ulen <= 0)
        return src;
    std::string result(ulen, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), wlen, &result[0], ulen, nullptr, nullptr);
    return result;
}
#else
inline std::string ToUTF8(const std::string& src)
{
    return src;
}
#endif
