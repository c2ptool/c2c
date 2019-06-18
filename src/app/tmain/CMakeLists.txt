set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Qt5 COMPONENTS Core Quick REQUIRED)

set(QC2C_DIR ${CMAKE_SOURCE_DIR}/src/qc2c)

include_directories(
    ${QC2C_DIR}
    ${CMAKE_SOURCE_DIR}/src/p2p
    ${CMAKE_INSTALL_PREFIX}/include
    ${CMAKE_SOURCE_DIR}/src/variant/include)

link_directories(
    ${CMAKE_INSTALL_PREFIX}/lib
)

set(tmain_src
    main.cpp
    ${QC2C_DIR}/qc2c.h
    ${QC2C_DIR}/qc2c.cpp
    ${QC2C_DIR}/qvar.h
    ${QC2C_DIR}/qvar.cpp
    qml.qrc)

add_executable(tmain ${tmain_src})

target_compile_definitions(tmain PRIVATE $<$<OR:$<CONFIG:Debug>,$<CONFIG:RelWithDebInfo>>:QT_QML_DEBUG>)

target_link_libraries(tmain
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

install(TARGETS tmain
    RUNTIME DESTINATION   bin
    PUBLIC_HEADER DESTINATION include
    LIBRARY DESTINATION   lib
    PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ
        GROUP_EXECUTE GROUP_READ
    ARCHIVE DESTINATION lib
)
