
find_package(OpenSSL REQUIRED)

add_library(Crypto
	CertificateValidator.cpp
	Crypto.cpp
	ECDSAKey.cpp
	EdDSAKey.cpp
	OpenSSLErros.cpp
	PublicKey.cpp
	RSAKey.cpp
	x509Cert.cpp
)

target_link_libraries(Crypto PRIVATE OpenSSL::Crypto CBORLib)

target_include_directories(Crypto PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})