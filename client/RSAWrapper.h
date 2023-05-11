#pragma once
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>


class RSAWrapper
{
	static const unsigned int PUB_KEY_SIZE          = 160;       // RSA 1024 bit X509 format
	static const unsigned int SYMMETRIC_KEY_SIZE    = 16;        // AES-CBC 128 bit
	static const unsigned int  KEY_LENGTH_BITS      = 1024;

private:
	CryptoPP::AutoSeededRandomPool prng;
	CryptoPP::RSA::PrivateKey private_key;

	std::string public_key_str;
	std::string private_key_str;

public:
	/// <summary>
	/// Creates public and private keys.
	/// </summary>
	void generateKeys();

	/// <summary>
	/// Returs public key as string.
	/// </summary>
	/// <returns></returns>
	std::string getPublicKey();

	/// <summary>
	/// Returns private key as string.
	/// </summary>
	/// <returns></returns>
	std::string getPrivateKey();

	/// <summary>
	/// Decrypts the given encrypted information, using private key
	/// </summary>
	/// <param name="aes"></param>
	/// <param name="size"></param>
	/// <returns></returns>
	std::string decrypt(unsigned char* encrypted, size_t size);

	/// <summary>
	/// Encrypts the content file according to the given path, using public key
	/// </summary>
	/// <param name="file_path"></param>
	/// <returns></returns>
	std::string encryptFile(std::string file_path);

	/// <summary>
	/// Loads the given string key to CryptoPP::RSA::PrivateKey object
	/// </summary>
	/// <param name="key"></param>
	void loadKey(std::string key);
};