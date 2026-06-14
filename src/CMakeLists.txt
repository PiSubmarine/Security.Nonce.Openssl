include("${_build_cmake_local}")

find_package(OpenSSL REQUIRED)

message("Adding library: ${PISUBMARINE_MODULE_NAME}")
add_library(${PISUBMARINE_MODULE_NAME}
        PiSubmarine/Security/Nonce/Openssl/Provider.cpp
        "../public/PiSubmarine/Security/Nonce/Openssl/Provider.h")
target_include_directories(${PISUBMARINE_MODULE_NAME} PUBLIC "../public")
PiSubmarineInitTarget(${PISUBMARINE_MODULE_NAME})

PiSubmarineAddDependency("https://github.com/PiSubmarine/Error.Api.git" "")
target_link_libraries(${PISUBMARINE_MODULE_NAME} PUBLIC PiSubmarine.Error.Api)

PiSubmarineAddDependency("https://github.com/PiSubmarine/Security.Nonce.Api.git" "")
target_link_libraries(${PISUBMARINE_MODULE_NAME} PUBLIC PiSubmarine.Security.Nonce.Api)

target_link_libraries(${PISUBMARINE_MODULE_NAME} PRIVATE OpenSSL::Crypto)
