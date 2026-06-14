#include "PiSubmarine/Security/Nonce/Openssl/Provider.h"

#include <limits>
#include <stdexcept>

#include <openssl/rand.h>

#include "PiSubmarine/Error/Api/MakeError.h"
#include "PiSubmarine/Security/Nonce/Api/ErrorCode.h"

namespace PiSubmarine::Security::Nonce::Openssl
{
    namespace
    {
        [[nodiscard]] Error::Api::Error MakeDeviceError(const Api::ErrorCode code)
        {
            return Error::Api::MakeError(Error::Api::ErrorCondition::DeviceError, make_error_code(code));
        }
    }

    Provider::Provider(Config config)
        : m_Config(config)
        , m_Prefix(config.PrefixSize)
    {
        if (m_Config.CounterSize == 0 ||
            m_Config.CounterSize > sizeof(std::uint64_t))
        {
            throw std::invalid_argument("Security.Nonce.Openssl requires counter size between 1 and 8 bytes");
        }

        if (m_Config.PrefixSize == 0)
        {
            throw std::invalid_argument("Security.Nonce.Openssl requires a non-empty random nonce prefix");
        }

        if (RAND_bytes(reinterpret_cast<unsigned char*>(m_Prefix.data()), static_cast<int>(m_Prefix.size())) != 1)
        {
            throw std::runtime_error("Security.Nonce.Openssl failed to initialize nonce prefix");
        }
    }

    Error::Api::Result<::PiSubmarine::Security::Api::Nonce> Provider::Next()
    {
        if (m_Exhausted)
        {
            return std::unexpected(MakeDeviceError(Api::ErrorCode::NonceExhausted));
        }

        const auto maximumCounter =
            m_Config.CounterSize == sizeof(std::uint64_t)
                ? std::numeric_limits<std::uint64_t>::max()
                : ((std::uint64_t{1} << (m_Config.CounterSize * 8U)) - 1U);

        ::PiSubmarine::Security::Api::Nonce nonce;
        nonce.Value = m_Prefix;
        nonce.Value.resize(m_Config.PrefixSize + m_Config.CounterSize);

        for (std::size_t index = 0; index < m_Config.CounterSize; ++index)
        {
            const auto shift = static_cast<unsigned>((m_Config.CounterSize - 1U - index) * 8U);
            nonce.Value[m_Config.PrefixSize + index] =
                static_cast<std::byte>((m_NextCounter >> shift) & 0xFFU);
        }

        if (m_NextCounter == maximumCounter)
        {
            m_Exhausted = true;
        }
        else
        {
            ++m_NextCounter;
        }

        return nonce;
    }
}
