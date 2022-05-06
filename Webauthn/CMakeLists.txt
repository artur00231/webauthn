
add_library(Webauthn
	Attestation.cpp
	AttestationObject.cpp
	AuthenticatorData.cpp
	TMPAttestation.cpp
	WebAuthnDef.cpp
)

target_link_libraries(Webauthn PRIVATE CBORLib CryptoLite)
target_link_libraries(Webauthn PUBLIC CryptoLite)

target_include_directories(Webauthn PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})