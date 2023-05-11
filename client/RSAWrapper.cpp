#include "RSAWrapper.h"
#include <iostream>
#include <filesystem>
#include <boost/asio.hpp>
#include <cryptopp/modes.h>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>

#pragma pack(push, r1, 1)
void RSAWrapper::generateKeys()
{
	private_key.Initialize(prng, KEY_LENGTH_BITS);
}

std::string RSAWrapper::getPublicKey()
{
	CryptoPP::RSAFunction publicKey(this->private_key);
	std::string key;
	CryptoPP::StringSink ss(key);
	publicKey.Save(ss);
	public_key_str = key;
	return public_key_str;
}

std::string RSAWrapper::getPrivateKey()
{
	std::string key;
	CryptoPP::StringSink ss(key);
	private_key.Save(ss);
	private_key_str = key;
	return private_key_str;
}

void RSAWrapper::loadKey(std::string key)
{
	CryptoPP::StringSource ss(key, true);
	private_key.Load(ss);
}


std::string RSAWrapper::decrypt(unsigned char* encrypted, size_t size)
{
	std::string decrypted;
	std::string cipher;
	cipher.assign((reinterpret_cast<char*>(encrypted)), size);
	CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(private_key);
	// assert ic case of error 
	size_t dpl = decryptor.MaxPlaintextLength(size);
	assert(0 != dpl);
	CryptoPP::StringSource ss(cipher, true, new CryptoPP::PK_DecryptorFilter(prng, decryptor, new CryptoPP::StringSink(decrypted)));
	public_key_str = decrypted;
	return public_key_str;
}


std::string RSAWrapper::encryptFile(std::string file_path)
{
	CryptoPP::SecByteBlock key(SYMMETRIC_KEY_SIZE), iv(CryptoPP::AES::BLOCKSIZE);
	// fill iv with 0
	std::memset(iv, 0, iv.size());

	// load file
	auto path = std::filesystem::path(file_path);
	std::ifstream file(path, std::ios::binary);

	// copy public_key
	memcpy_s(key, key.size(), public_key_str.c_str(), public_key_str.length());

	std::string cipher;

	// encrypt
	CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryptor{ key, key.size(), iv };
	auto stream_filter = new CryptoPP::StreamTransformationFilter(encryptor, new CryptoPP::StringSink(cipher));
	CryptoPP::FileSource file_Source(file, true, stream_filter);

	if (file.is_open())
		file.close();
	return cipher;

}
#pragma pack(pop, r1)