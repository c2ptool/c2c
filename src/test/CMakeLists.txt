set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED on)

include_directories(
    ${CMAKE_INSTALL_PREFIX}/include
)

link_directories(
    ${CMAKE_INSTALL_PREFIX}/lib
)

add_executable(server mkcert.cpp mkcert.h server.cpp)
add_dependencies(server websocketpp_prj)

target_link_libraries(server
    boost_system
    boost_program_options
    boost_regex
    pthread
    ssl
    crypto)

add_executable(client client.cpp)
add_dependencies(client websocketpp_prj)

target_link_libraries(client
    boost_system
    boost_program_options
    boost_regex
    pthread
    ssl
    crypto)

install(TARGETS server client
    RUNTIME DESTINATION   bin
    PUBLIC_HEADER DESTINATION include
    LIBRARY DESTINATION   lib
    PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ
        GROUP_EXECUTE GROUP_READ
    ARCHIVE DESTINATION lib
)
