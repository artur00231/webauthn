
include(${CMAKE_MODULE_PATH}FindLibFIDO2.cmake)

add_library(WebauthnClient
	Libfido2Authenticator.cpp
	WebAuthn.cpp
	Webauthnlibfido2.cpp
	WebAuthnWinHello.cpp
)

target_link_libraries(WebauthnClient PRIVATE Webauthn CBORLib Crypto ${LIBFIDO2_LIBRARY})

target_include_directories(WebauthnClient PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})