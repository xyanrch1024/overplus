message(STATUS "Enter client CMakeList ...")
if (MSVC)
    add_compile_options(/bigobj)
endif()
if (WIN32)
    set(CMAKE_AUTOUIC ON)
    set(CMAKE_AUTOMOC ON)
    set(CMAKE_AUTORCC ON)
    find_package(Qt5Core REQUIRED)
    find_package(Qt5Gui REQUIRED)
    find_package(Qt5Widgets REQUIRED)

    set(SRCS
            Server.h
            Server.cpp
            Session.cpp
            UdpRelay.cpp
            TunManager.h
            TunManager.cpp
            mainwindow.cpp
            mainwindow.h
            mainwindow.ui
            )
 

    add_executable(overplus_client main.cpp ${SRCS})
    target_link_libraries(overplus_client Threads::Threads shared proto OpenSSL::SSL
            Qt5::Core Qt5::Gui Qt5::Widgets ${Boost_LIBRARIES} wsock32 ws2_32 crypt32)
    if (MSVC)
        set_target_properties(overplus_client PROPERTIES
            LINK_FLAGS "/MANIFEST:EMBED /MANIFESTINPUT:${CMAKE_CURRENT_SOURCE_DIR}/overplus_client.manifest"
        )
    endif()
    set_target_properties(overplus_client PROPERTIES
            MACOSX_BUNDLE_GUI_IDENTIFIER my.example.com
            MACOSX_BUNDLE TRUE
            WIN32_EXECUTABLE TRUE
            )
else ()
    set(SRCS
            Server.h
            Server.cpp
            Session.cpp
            UdpRelay.cpp
            )
    add_executable(overplus_client CliMain.cpp ${SRCS})
    target_link_libraries(overplus_client Threads::Threads shared proto OpenSSL::SSL
            ${Boost_LIBRARIES} z dl pthread)
endif ()




