# user= “test” 
# domain= “workgroup”
# password = “test”
# NTProofStr = a0e42a75c54bbb0fab814593569faa22 
# EncryptedSessionKey = C914ADCEB0F1C32FB7C2548D8D959F01 
# both get from the Session Setup REquest, NTLMSSP_AUTH. EncryptedSessionKey maybe empty.  
#
# hash = MD4(password.encode(‘utf16-le’)) // NTLM hash
# # hash is 0cb6948805f797bf2a82807973b89537
# ResponseKeyNT(HMAC_MD5(hash, (user.toUpper()+domain.toUpper()).encode(‘utf16-le’)))
# # ResponseKeyNT is f31eb9f73fc9d5405f9ae516fb068315 
# KeyExchangeKey=HMAC_MD5(ResponseKeyNT, NTProofStr)
# # KeyExchangeKey is fd160d4ed7f2cb38f64262d7617f23b3
# RandomSessionKey = RC4(KeyExchangeKey,EncryptedSessionKey)
# # RandomSessionKey is 4462b99bb21423c29dbb4b4a983fde03

import hmac
import hashlib
from Crypto.Cipher import ARC4

def calc_random_sessionkey(user: str, domain: str, NTProofStr: str, EncryptedSessionKey: str, NTLMHash: str) -> str:
    NTLMHashHex = bytes.fromhex(NTLMHash)
    NTProofStrHex = bytes.fromhex(NTProofStr)
    EncryptedSessionKeyHex = bytes.fromhex(EncryptedSessionKey)

    message = user.upper().encode('utf-16-le') + domain.encode('utf-16-le')
    key = NTLMHashHex
    hmac_md5 = hmac.new(key, message, hashlib.md5)
    ResponseKeyNT = bytes.fromhex(hmac_md5.hexdigest())

    message = NTProofStrHex
    key = ResponseKeyNT
    hmac_md5 = hmac.new(key, message, hashlib.md5)
    KeyExchangeKey = bytes.fromhex(hmac_md5.hexdigest())

    if (EncryptedSessionKeyHex == b''):
        return KeyExchangeKey.hex()
    else:
        cipher = ARC4.new(KeyExchangeKey)
        RandomSessionKey = cipher.encrypt(EncryptedSessionKeyHex)
        return RandomSessionKey.hex()

def unit_test():
    user = "test"
    domain = "WORKGROUP"
    NTProofStr = "a0e42a75c54bbb0fab814593569faa22"
    EncryptedSessionKey = "C914ADCEB0F1C32FB7C2548D8D959F01"
    NTLMHash = "0cb6948805f797bf2a82807973b89537"
    if calc_random_sessionkey(user, domain, NTProofStr, EncryptedSessionKey,
                              NTLMHash) != '4462b99bb21423c29dbb4b4a983fde03':
        print("unit test failed!!")
        exit(0)

if __name__ == "__main__":
    unit_test()

    user = ""
    domain = "" # domain is showed on packet, maybe ad001 or ad001.s.n
    NTProofStr = "1e903817f86e8e780ecf8e9069501e62"
    EncryptedSessionKey = "e876393bba79a1cfee1dca943597b596" # can be empty string
    NTLMHash = ""
    SessionId = "750000c405bc0100" # hex stream copy from packet(network endian). saved for wireshark.
    print(calc_random_sessionkey(user, domain, NTProofStr, EncryptedSessionKey, NTLMHash))
