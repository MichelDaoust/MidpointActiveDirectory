#pragma once
class EncryptionUtils
{
public:
	EncryptionUtils();
	~EncryptionUtils();

	std::string Encrypt(std::string password); 
	std::string Decrypt(std::string password);

private: 

	void HexStr2CharStr(char const* pszHexStr, unsigned char* pucCharStr, size_t iSize);
	void Hex2Char(char const* szHex, unsigned char& rch);
	void CharStr2HexStr(unsigned char const* pucCharStr, char* pszHexStr, size_t iSize);
	void Char2Hex(unsigned char ch, char* szHex);







};

