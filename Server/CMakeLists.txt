message(STATUS "Enter Server CMakeList ...")
if (MSVC)
    add_compile_options(/bigobj)
endif()

set(SRCS
        TlsSession.cpp
        WebsocketSession.cpp
        Service.cpp
        DtlsListener.cpp
        DtlsServerSession.cpp
        )
add_library(server ${SRCS})
target_link_libraries(server shared proto)