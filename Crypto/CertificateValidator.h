#pragma once

#include <openssl/x509_vfy.h>

#include "x509Cert.h"

namespace webauthn::crypto
{
	class CertificateValidator
	{
	public:
		CertificateValidator();
		CertificateValidator(const CertificateValidator&) = delete;
		CertificateValidator& operator=(const CertificateValidator&) = delete;
		CertificateValidator(CertificateValidator&&) noexcept;
		CertificateValidator& operator=(CertificateValidator&&) noexcept;
		~CertificateValidator();

		CertificateValidator& pushCACert(const x509Cert& cert);
		bool verifyCert(const x509Cert& cert);

	private:
		X509_STORE_CTX* ctx{ nullptr };
		X509_STORE* store{ nullptr };
	};
}
