#include "TransferInfo.h"
#include <iostream>
#include <fstream>
#include <stdexcept>
#include <boost/asio.hpp>
#include "Packages.h"
#include <filesystem>



TransferInfo::TransferInfo() {
	std::ifstream transferInfoFile(TRANSFER_INFO_FILE);
	if (!transferInfoFile.is_open()) {
		throwError("Cannot open " + TRANSFER_INFO_FILE);
	}

	// read host & port
	std::string line;
	std::getline(transferInfoFile, line);
	//extract host and port
	auto index = line.find(':');
	if (index == std::string::npos)
	{
		transferInfoFile.close();
		throwError("Incorrect file format, file: " + TRANSFER_INFO_FILE);
	}
	hostIP = line.substr(0, index);
	if (validateIpAddress(hostIP) == false)
	{
		std::cout << "Incorrect host ip, set ip to " << DEFAULT_HOST_IP << std::endl;
		hostIP = DEFAULT_HOST_IP;
	}
	try {
		// makes sure the port is valid
		port = std::stoi(line.substr(index + 1));
	}
	catch (...) {
		std::cout << "Incorrect port, set port to " << DEFAULT_PORT << std::endl;
		port = DEFAULT_PORT;
	}
	if (transferInfoFile.eof())
	{
		transferInfoFile.close();
		throwError("Incorrect file format missing client name, file: " + TRANSFER_INFO_FILE);
	}

	// client name & file
	getline(transferInfoFile, clientName);
	// makes sure the client name is valid
	if (clientName.size() == 0 || line.size() > MAX_CLIENT_NAME) {
		transferInfoFile.close();
		throwError("Invalid client name in " + TRANSFER_INFO_FILE);
	}
	if (transferInfoFile.eof())
	{
		throwError("No fiile path in " + TRANSFER_INFO_FILE);
	}
	std::string path;
	getline(transferInfoFile, path);
	// makes sure the file path is valid
	if (!std::filesystem::is_regular_file(std::filesystem::path(path)))
	{
		throwError("File does not exist " + path);
	}
	filePath = path;
	transferInfoFile.close();
}

void TransferInfo::throwError(std::string msg)
{
	throw std::exception(msg.c_str());
}

bool TransferInfo::validateIpAddress(const std::string& ip)
{
	try {
		boost::asio::ip::address ip_add = boost::asio::ip::make_address(ip);
		return ip_add.is_v4();
	}
	catch (...)
	{
		return false;
	}
}

std::string TransferInfo::getHostIP() const { return hostIP; }
uint16_t TransferInfo::getPort() const { return port; }
std::string TransferInfo::getClientName() const { return clientName; }
std::string TransferInfo::getFilePath() const { return filePath; }



