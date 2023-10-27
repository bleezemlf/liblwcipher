cmake_minimum_required(VERSION 3.22)

set(CMAKE_C_STANDARD 99)

project(lwcipher)

set(SRC_DIR ${CMAKE_SOURCE_DIR}/src)
set(INCLUDE_DIR ${CMAKE_SOURCE_DIR}/include)
set(INTERNAL_INCLUDE_DIR ${CMAKE_SOURCE_DIR}/internal)

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/build)

add_library(lwcipher SHARED ${SRC_DIR}/lw_cipher.c
                                ${SRC_DIR}/lw_cipher_wrapper.c
                                ${SRC_DIR}/present.c
                                ${SRC_DIR}/simon.c
                                ${SRC_DIR}/speck.c
                                ${SRC_DIR}/xtea.c
                                ${SRC_DIR}/xxtea.c
)

target_include_directories(lwcipher PUBLIC ${INCLUDE_DIR})
target_include_directories(lwcipher PRIVATE ${INTERNAL_INCLUDE_DIR})

target_link_libraries(lwcipher PRIVATE ${LWCIPHER_LIBRARY})

# install the library and header files, run 'make install'
install(TARGETS lwcipher
        LIBRARY DESTINATION /usr/local/lib
)

file(GLOB HEADERS ${INCLUDE_DIR}/*.h)
install(FILES ${HEADERS} DESTINATION /usr/local/include/lwcipher)

# uninstall the installed files , run 'make uninstall'
add_custom_target(uninstall
        COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake
)

# test project
#project(lwcipher_test)
#add_executable(lwcipher_test main.cpp)
#find_library(LWCIPHER_LIBRARY
#        NAMES lwcipher
#        PATHS /usr/local/lib  # 设置库的查找路径
#)
#if(NOT LWCIPHER_LIBRARY)
#    message(FATAL_ERROR "liblwcipher.so not found")
#endif()
#target_link_libraries(lwcipher_test ${LWCIPHER_LIBRARY})
