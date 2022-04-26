#pragma once

namespace webauthn::impl
{
	class Webauthnlibfido2;

	class Libfido2Token
	{
		Libfido2Token() = default;

		friend Webauthnlibfido2;
	};
}