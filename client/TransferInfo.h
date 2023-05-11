#pragma once
#include <string>



#define DEFAULT_PORT 1234


class TransferInfo {
	const std::string TRANSFER_INFO_FILE = "transfer.info";
	const std::string DEFAULT_HOST_IP = "127.0.0.1";
private:
	std::string hostIP;
	uint16_t port;
	std::string clientName;
	std::string filePath;

	/// <summary>
	/// Returns whether the IP address is valid.
	/// </summary>
	/// <param name="ip"></param>
	/// <returns></returns>
	bool validateIpAddress(const std::string& ip);

	/// <summary>
	///  In case of an error that cannot be corrected, throw exception.
	/// </summary>
	void throwError(std::string msg);	

public:
	TransferInfo();

	std::string getHostIP() const;

	uint16_t getPort() const;

	std::string getClientName() const;

	std::string getFilePath() const;
};
