include_directories(${PROJECT_SOURCE_DIR}/include)

aux_source_directory(. SRC)

add_executable(${PROJECT_NAME} ${SRC})