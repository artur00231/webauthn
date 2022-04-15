#include "WebAuthnWinHello.h"

#ifdef _WIN32

#include <iterator>
#include <algorithm>
#include <stdexcept>
#include <ranges>
#include <array>
#include <span>

namespace webauthn::impl::WH
{
	std::wstring fromASCIIString(std::string_view text)
	{
		std::wstring w_text{};
		std::copy(text.begin(), text.end(), std::back_inserter(w_text));
		return w_text;
	}

	std::string fromASCIIWString(std::wstring_view text)
	{
		std::string s_text{};
		std::transform(text.begin(), text.end(), std::back_inserter(s_text), [](auto x) {
			return static_cast<char>(x);
			});
		return s_text;
	}
}

webauthn::impl::WebAuthnWinHello::WebAuthnWinHelloDll::WebAuthnWinHelloDll()
{
	webauthn_lib = LoadLibraryA("webauthn.dll");
	if (!webauthn_lib)
	{
		throw std::runtime_error{ "Cannot load webauthn.dll library" };
	}

	WebAuthNGetApiVersionNumber = (WebAuthNGetApiVersionNumber_t)GetProcAddress(webauthn_lib, "WebAuthNGetApiVersionNumber");
	auto version = WebAuthNGetApiVersionNumber();

	if (version < WEBAUTHN_API_VERSION_3)
	{
		throw std::runtime_error{ "this library is intended for webauthn.dll version 3 and over" };
	}

	WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable = (WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable_t)GetProcAddress(webauthn_lib, "WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable");
	WebAuthNAuthenticatorMakeCredential = (WebAuthNAuthenticatorMakeCredential_t)GetProcAddress(webauthn_lib, "WebAuthNAuthenticatorMakeCredential");
	WebAuthNAuthenticatorGetAssertion = (WebAuthNAuthenticatorGetAssertion_t)GetProcAddress(webauthn_lib, "WebAuthNAuthenticatorGetAssertion");
	WebAuthNGetErrorName = (WebAuthNGetErrorName_t)GetProcAddress(webauthn_lib, "WebAuthNGetErrorName");
	WebAuthNFreeAssertion = (WebAuthNFreeAssertion_t)GetProcAddress(webauthn_lib, "WebAuthNFreeAssertion");
	WebAuthNFreeCredentialAttestation = (WebAuthNFreeCredentialAttestation_t)GetProcAddress(webauthn_lib, "WebAuthNFreeCredentialAttestation");

	BOOL isAvaiable{};

	auto result = WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable(&isAvaiable);

	if (result != S_OK)
	{
		isAvaiable = false;
	}

	this->isAvaiable = isAvaiable;
}

webauthn::impl::WebAuthnWinHello::WebAuthnWinHelloDll::~WebAuthnWinHelloDll()
{
	if (webauthn_lib)
	{
		FreeLibrary(webauthn_lib);
	}
}

webauthn::impl::WebAuthnWinHello::WebAuthnWinHello()
{
}

webauthn::impl::WebAuthnWinHello::~WebAuthnWinHello()
{
}

std::optional<webauthn::MakeCredentialResult> webauthn::impl::WebAuthnWinHello::makeCredential(const webauthn::UserData& user, const webauthn::RelyingParty& rp,
	const std::vector<std::byte>& challange, const std::optional<std::string>& password, const webauthn::WebAuthnOptions& options)
{
	if (!webAuthnWinHelloDll)
	{
		return {};
	}

	WEBAUTHN_RP_ENTITY_INFORMATION rpInformation{};
	rpInformation.dwVersion = WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION;
	rpInformation.pwszIcon = nullptr;
	auto RP_ID_w = WH::fromASCIIString(rp.ID);
	rpInformation.pwszId = RP_ID_w.c_str();
	auto RP_NAME_w = WH::fromASCIIString(rp.name);
	rpInformation.pwszName = RP_NAME_w.c_str();

	WEBAUTHN_USER_ENTITY_INFORMATION userInformation{};
	userInformation.dwVersion = WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION;
	userInformation.pwszIcon = nullptr;
	auto USER_DISPLAY_NAME_w = WH::fromASCIIString(user.display_name);
	userInformation.pwszDisplayName = USER_DISPLAY_NAME_w.c_str();
	auto USER_NAME_w = WH::fromASCIIString(user.name);
	userInformation.pwszName = USER_NAME_w.c_str();

	std::vector<BYTE> userInformation_Id{};
	std::ranges::transform(user.ID, std::back_inserter(userInformation_Id), 
		[](auto x) { return static_cast<BYTE>(x); });
	userInformation.cbId = static_cast<decltype(userInformation.cbId)>(userInformation_Id.size());
	userInformation.pbId = userInformation_Id.data();

	WEBAUTHN_COSE_CREDENTIAL_PARAMETERS pubKeyCredParams{};

	std::vector<WEBAUTHN_COSE_CREDENTIAL_PARAMETER> pubKeyCredParam{};

	std::ranges::for_each(options.allowed_algorithms, [&pubKeyCredParam](auto x) {
		pubKeyCredParam.emplace_back();
		pubKeyCredParam.back().dwVersion = WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION;
		pubKeyCredParam.back().pwszCredentialType = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY;
		pubKeyCredParam.back().lAlg = std::to_underlying(x);
		});

	pubKeyCredParams.pCredentialParameters = pubKeyCredParam.data();
	pubKeyCredParams.cCredentialParameters = static_cast<DWORD>(pubKeyCredParam.size());

	WEBAUTHN_CLIENT_DATA webAuthNClientData{};
	webAuthNClientData.dwVersion = WEBAUTHN_CLIENT_DATA_CURRENT_VERSION;
	webAuthNClientData.pwszHashAlgId = WEBAUTHN_HASH_ALGORITHM_SHA_256;
	std::vector<BYTE> data{};
	std::transform(challange.begin(), challange.end(), std::back_inserter(data),
		[](auto x) { return static_cast<BYTE>(x); });
	webAuthNClientData.pbClientDataJSON = data.data();
	webAuthNClientData.cbClientDataJSON = static_cast<decltype(webAuthNClientData.cbClientDataJSON)>(data.size());

	WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS webAuthNCredentialOptions{};
	webAuthNCredentialOptions.dwVersion = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_3;
	webAuthNCredentialOptions.dwTimeoutMilliseconds = 60000;
	webAuthNCredentialOptions.CredentialList = { 0, nullptr };
	webAuthNCredentialOptions.Extensions = { 0, nullptr };
	webAuthNCredentialOptions.dwAuthenticatorAttachment = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY;
	webAuthNCredentialOptions.bRequireResidentKey = false;
	webAuthNCredentialOptions.dwUserVerificationRequirement = [value = options.user_verification]() {
		switch (value)
		{
		case webauthn::USER_VERIFICATION::REQUIRED:
			return WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED;
		case webauthn::USER_VERIFICATION::PREFERRED:
			return WEBAUTHN_USER_VERIFICATION_REQUIREMENT_PREFERRED;
		case webauthn::USER_VERIFICATION::DISCOURAGED:
			return WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED;
			break;
		}

		return WEBAUTHN_USER_VERIFICATION_REQUIREMENT_ANY;
	}();
	webAuthNCredentialOptions.dwAttestationConveyancePreference = [value = options.attestation]() {
		switch (value)
		{
		case webauthn::ATTESTATION::NONE:
			return WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE;
		case webauthn::ATTESTATION::INDIRECT:
			return WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_INDIRECT;
		case webauthn::ATTESTATION::DIRECT:
			return WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT;
		}

		return WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_ANY;
	}();
	webAuthNCredentialOptions.dwFlags = 0;
	webAuthNCredentialOptions.pCancellationId = nullptr;
	webAuthNCredentialOptions.pExcludeCredentialList = nullptr;

	HWND Hwindow = GetForegroundWindow();

	WEBAUTHN_CREDENTIAL_ATTESTATION* webAuthNCredentialAttestation{};

	auto result = webAuthnWinHelloDll.WebAuthNAuthenticatorMakeCredential(Hwindow,
		&rpInformation, &userInformation, &pubKeyCredParams, &webAuthNClientData,
		&webAuthNCredentialOptions, &webAuthNCredentialAttestation);

	if (result != S_OK)
	{
		//std::cerr << "WinHello API Error: " << result << "\n";
		//std::wcerr << WebAuthNGetErrorName(result) << L"\n";

		return {};
	}

	std::vector<std::byte> attestationObject{};

	if (webAuthNCredentialAttestation != nullptr)
	{
		std::generate_n(std::back_inserter(attestationObject), webAuthNCredentialAttestation->cbAttestationObject,
			[ptr = webAuthNCredentialAttestation->pbAttestationObject]() mutable { return static_cast<std::byte>(*(ptr++)); });

		webAuthnWinHelloDll.WebAuthNFreeCredentialAttestation(webAuthNCredentialAttestation);
	}
	else
	{
		return {};
	}

	return { { attestationObject } };
}

std::optional<webauthn::GetAssertionResult> webauthn::impl::WebAuthnWinHello::getAssertion(const std::vector<webauthn::CredentialId>& id, const webauthn::RelyingParty& rp,
	const std::vector<std::byte>& challange, const std::optional<std::string>& password, const webauthn::WebAuthnOptions& options)
{
	std::vector<std::vector<BYTE>> credentials_id{};
	for (auto&& key_id : id)
	{
		credentials_id.emplace_back();
		std::transform(key_id.id.begin(), key_id.id.end(), std::back_inserter(credentials_id.back()),
			[](auto x) { return static_cast<BYTE>(x); });
	}

	WEBAUTHN_CLIENT_DATA webAuthNClientData{};
	webAuthNClientData.dwVersion = WEBAUTHN_CLIENT_DATA_CURRENT_VERSION;
	webAuthNClientData.pwszHashAlgId = WEBAUTHN_HASH_ALGORITHM_SHA_256;
	std::vector<BYTE> data{};
	std::transform(challange.begin(), challange.end(), std::back_inserter(data),
		[](auto x) { return static_cast<BYTE>(x); });
	webAuthNClientData.pbClientDataJSON = data.data();
	webAuthNClientData.cbClientDataJSON = static_cast<decltype(webAuthNClientData.cbClientDataJSON)>(data.size());

	BOOL pbU2fAppId = FALSE;

	std::vector<WEBAUTHN_CREDENTIAL> credentials{};

	for (auto&& key_id : credentials_id)
	{
		credentials.emplace_back();
		credentials.back().dwVersion = WEBAUTHN_CREDENTIAL_CURRENT_VERSION;
		credentials.back().pwszCredentialType = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY;

		credentials.back().cbId = static_cast<DWORD>(key_id.size());
		credentials.back().pbId = key_id.data();
	}

	WEBAUTHN_CREDENTIALS allowCredentialList = { static_cast<DWORD>(credentials.size()), credentials.data()};

	WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS WebAuthNAssertionOptions{};
	WebAuthNAssertionOptions.dwVersion = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_2;
	WebAuthNAssertionOptions.dwTimeoutMilliseconds = 60000;
	WebAuthNAssertionOptions.CredentialList = allowCredentialList;
	WebAuthNAssertionOptions.Extensions = { 0, nullptr };
	WebAuthNAssertionOptions.dwAuthenticatorAttachment = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY;
	WebAuthNAssertionOptions.dwUserVerificationRequirement = WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED;
	WebAuthNAssertionOptions.dwFlags = 0;
	WebAuthNAssertionOptions.pwszU2fAppId = nullptr;
	WebAuthNAssertionOptions.pbU2fAppId = &pbU2fAppId;

	WEBAUTHN_ASSERTION* webAuthNAssertion{};
	HWND Hwindow = GetForegroundWindow();
	auto RP_ID_w = WH::fromASCIIString(rp.ID);

	auto result = webAuthnWinHelloDll.WebAuthNAuthenticatorGetAssertion(Hwindow, RP_ID_w.c_str(), &webAuthNClientData, &WebAuthNAssertionOptions, &webAuthNAssertion);

	if (result != S_OK || webAuthNAssertion == nullptr)
	{
		return {};
	}

	GetAssertionResult get_assertion_result{};
	std::span sign_span{ webAuthNAssertion->pbSignature, webAuthNAssertion->cbSignature };
	std::transform(sign_span.begin(), sign_span.end(), std::back_inserter(get_assertion_result.signature),
		[](auto x) { return static_cast<std::byte>(x); });

	std::span id_span{ webAuthNAssertion->pbUserId, webAuthNAssertion->cbUserId };
	if (id_span.size() != 0)
	{
		std::vector<std::byte> user_id{};
		std::transform(id_span.begin(), id_span.end(), std::back_inserter(user_id),
			[](auto x) { return static_cast<std::byte>(x); });

		get_assertion_result.user_id = user_id;
	}

	std::span auth_data_span{ webAuthNAssertion->pbAuthenticatorData, webAuthNAssertion->cbAuthenticatorData };
	std::transform(auth_data_span.begin(), auth_data_span.end(), std::back_inserter(get_assertion_result.authenticator_data),
		[](auto x) { return static_cast<std::byte>(x); });

	webAuthnWinHelloDll.WebAuthNFreeAssertion(webAuthNAssertion);

	return get_assertion_result;
}

#endif // _WIN32