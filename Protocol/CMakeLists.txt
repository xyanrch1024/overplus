message(STATUS "Enter Protocal CMakeList ...")
set(proto_SRCS
        socks5/socks5.cpp
        socks5/UdpRequest.cpp
        trojan/TrojanReq.cpp
        trojan/UDPPacket.cpp
        VProtocal/VRequest.cpp
        http/http.cpp
        UdpFrame.cpp
        )

add_library(proto ${proto_SRCS})
target_link_libraries(proto shared)
