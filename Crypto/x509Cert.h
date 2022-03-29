#pragma once

#include <vector>
#include <cstddef>

#include <openssl/x509.h>

namespace webauthn::crypto
{
	class x509Cert
	{
	public:
		~x509Cert();

		x509Cert(const x509Cert&) = delete;
		x509Cert& operator=(const x509Cert&) = delete;
		x509Cert(x509Cert&&) noexcept;
		x509Cert& operator=(x509Cert&&) noexcept;

		static x509Cert loadFromDer(const std::vector<std::byte>& data);

		//private:
		x509Cert() = default;

		BIO* bio_mem{ nullptr };
		X509* x509{ nullptr };
	};
}

