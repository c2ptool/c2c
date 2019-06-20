set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED on)

add_definitions(
    -DMSGPACK_USE_BOOST
)

include_directories(
    ${CMAKE_INSTALL_PREFIX}/include
    ${CMAKE_INSTALL_PREFIX}/include/luajit-2.0
    ${CMAKE_CURRENT_SOURCE_DIR}/../leveldb/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../leveldb
    ${CMAKE_CURRENT_SOURCE_DIR}/../variant/include/
)

link_directories(
    ${CMAKE_INSTALL_PREFIX}/lib
)

set(c2c_src
    conn.h
    func.h
    mkcert.h
    mkcert.cpp
    db.h
    db.cpp
    ldb.h
    ldb.cpp
    lresponse.h
    lresponse.cpp
    sol.h
    sol.cpp
    msg.h
    msg.cpp
    p2p.h
    p2p.cpp
    work.h
    work.cpp
    script.h
    script.cpp
    util.h
    util.cpp
    integer.h
    integer.cpp
    uint128_t.h
    uint128_t.cpp
    uint256_t.h
    uint256_t.cpp
    var.h
    var.cpp
    srv.h
    srv.cpp
    )

set(c2c_lib
    cmsgpack
    luajit-5.1
    leveldb
    boost_system
    boost_program_options
    boost_regex
    pthread
    ssl
    crypto
    sodium
    m
    dl)

add_library(c2c ${c2c_src})

add_dependencies(c2c
    websocketpp_prj
    sodium_prj
    msgpack_prj
    rapidjson_prj
    leveldb_prj
    easylogginpp_prj
    lua_prj
    sol2_prj
    lua_cmsgpack_prj
    boost_prj)

target_link_libraries(c2c ${c2c_lib})

set(c2cd_src
    easyloggingpp.cpp
    main.cpp)

add_executable(c2cd ${c2cd_src})
add_dependencies(c2cd c2c)

target_link_libraries(c2cd c2c m dl)


install(FILES
    var.h
    func.h
    conn.h
    db.h
    db.hpp
    p2p.h
    util.h
    integer.h
    uint128_t.h
    uint256_t.h
    DESTINATION ${CMAKE_INSTALL_PREFIX}/include/c2c
)

install(TARGETS c2c c2cd
    RUNTIME DESTINATION   bin
    PUBLIC_HEADER DESTINATION include
    LIBRARY DESTINATION   lib
    PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ
        GROUP_EXECUTE GROUP_READ
    ARCHIVE DESTINATION lib
)
