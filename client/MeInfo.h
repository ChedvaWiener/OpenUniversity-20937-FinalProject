#pragma once
#include <boost/asio.hpp>
#include <iostream>
#include "Packages.h"


class MeInfo {
	const std::string FILE_NAME = "me.info";
private:
	std::string clientName;
	unsigned char* clientId = new unsigned char[CLIENT_ID_SIZE]{0};
	std::string private_key;

	bool registration_required = true;


	/// <summary>
	/// Reads and loads client details from me.info file.
	/// </summary>
	void loadFile();

public:
	MeInfo();
	~MeInfo();

	/// <summary>
	/// Returns registratins needed state.
	/// </summary>
	/// <returns></returns>
	bool getRegistrationRequired() const;

	/// <summary>
	/// Returns private key.
	/// </summary>
	/// <returns></returns>
	std::string getPrivateKey() const;

	/// <summary>
	/// Returns client name.
	/// </summary>
	/// <returns></returns>
	std::string getClientName() const;

	/// <summary>
	/// Saves client details into me.info file.
	/// </summary>
	/// <param name="client_name"></param>
	/// <param name="client_id"></param>
	/// <param name="private_key_str"></param>
	void saveDetailsToFile(std::string client_name, unsigned char client_id[], std::string private_key_str);

	/// <summary>
	/// Returns client ID.
	/// </summary>
	/// <returns></returns>
	unsigned char* getClientId() const;
};