#ifndef NFCACTIVEAUTHENTICATION_H
#define NFCACTIVEAUTHENTICATION_H

#include <vector>

class NFCActiveAuthentication
{

public:
    NFCActiveAuthentication();


private:
    std::vector<uint8_t> m_publicKey{};
};

#endif // NFCACTIVEAUTHENTICATION_H
