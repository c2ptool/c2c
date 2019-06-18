set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Qt5 COMPONENTS Core Quick REQUIRED)

include_directories(
    ${CMAKE_SOURCE_DIR}/src/p2p
    ${CMAKE_INSTALL_PREFIX}/include
    ${CMAKE_SOURCE_DIR}/src/variant/include)

link_directories(
    ${CMAKE_INSTALL_PREFIX}/lib
)

set(qc2c_src
    main.cpp
    qc2c.h
    qc2c.cpp
    qvar.h
    qvar.cpp)

add_executable(qc2c ${qc2c_src})

target_compile_definitions(qc2c PRIVATE $<$<OR:$<CONFIG:Debug>,$<CONFIG:RelWithDebInfo>>:QT_QML_DEBUG>)

target_link_libraries(qc2c
    PRIVATE Qt5::Core Qt5::Quick
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
    c2c
    m
    dl)

install(TARGETS qc2c
    RUNTIME DESTINATION   bin
    PUBLIC_HEADER DESTINATION include
    LIBRARY DESTINATION   lib
    PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ
        GROUP_EXECUTE GROUP_READ
    ARCHIVE DESTINATION lib
)
