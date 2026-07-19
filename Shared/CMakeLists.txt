message(STATUS "Enter Shared CMakeList ...")
aux_source_directory(. shared_SRCS)
add_library(shared ${shared_SRCS})
target_link_libraries(shared OpenSSL::SSL OpenSSL::Crypto)
