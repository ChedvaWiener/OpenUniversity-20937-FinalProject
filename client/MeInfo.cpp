#include "MeInfo.h"
#include <fstream>
#include <boost/asio.hpp>
#include <cryptopp/base64.h>
#include "Base64Convertor.h"
#include "UUID.h"

MeInfo::MeInfo() {
	loadFile();

}

MeInfo::~MeInfo()
{
	delete[]  clientId;
}

void MeInfo::loadFile()
{
	try {
		std::ifstream file;
		file.open(FILE_NAME);
		if (!file)
		{
			std::cout << "Cannot open file: " << FILE_NAME << std::endl;
			return;
		}

		// try to read client name
		std::string line;
		std::getline(file, line);
		if (line.length() == 0)
		{
			std::cout << "Incorrect file format, missing client name" << FILE_NAME << std::endl;
			return;
		}

		// try to read client id
		this->clientName = line;
		std::getline(file, line);
		if (line.length() == 0)
		{
			std::cout << "Incorrect file format, missing client ID" << FILE_NAME << std::endl;
			return;
		}
		// convert id
		UUID::stringToUuid(clientId, line, UUID_SIZE);
		// try to read private key
		std::getline(file, line);
		if (line.length() == 0)
		{
			std::cout << "Incorrect file format, missing private key" << FILE_NAME << std::endl;
			return;
		}
		// decode private key
		this->private_key = Base64Convertor::decode(line);
		this->registration_required = false;
		file.close();
	}
	
	catch (const std::exception&) {
		this->registration_required = true;
	}

}

void MeInfo::saveDetailsToFile(std::string client_name, unsigned char client_id[], std::string private_key_str)
{
	std::ofstream file(FILE_NAME);

	if (!file.is_open()) {
		std::string err = "Cannot write client details to " + FILE_NAME;
		throw std::exception(err.c_str());
	}
	file << client_name << std::endl;
	file << UUID::uuidToString(client_id, UUID_SIZE) << std::endl;
	// encode private key
	file << Base64Convertor::encode(private_key_str);
	file.close();
}

bool MeInfo::getRegistrationRequired() const
{
	return registration_required;
}

std::string MeInfo::getPrivateKey() const
{
	return private_key;
}

std::string MeInfo::getClientName() const
{
	return clientName;
}

unsigned char* MeInfo::getClientId() const
{
	return clientId;
}
