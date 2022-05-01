
add_library(Webauthn
	Attestation.cpp
	AttestationObject.cpp
	AuthenticatorData.cpp
	TMPAttestation.cpp
	WebAuthnDef.cpp
)

target_link_libraries(Webauthn PRIVATE CBORLib Crypto)

target_include_directories(Webauthn PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})