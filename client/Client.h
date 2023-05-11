#pragma once
#include "Packages.h"
#include "MeInfo.h"
#include <boost/asio.hpp>
#include <boost/crc.hpp>
#include "TransferInfo.h"
#include "CRC32.h"
#include "RSAWrapper.h"

using boost::asio::ip::tcp;

class Client {
private:
	const int DENT_FILE_ATTEMPTS = 4;
	MeInfo* meInfo;
	RSAWrapper* rsaWrapper;

	boost::asio::io_context io_context;
	tcp::socket socket;
	tcp::resolver resolver;

	// client details
	bool registration_required;
	bool connected;
	std::string client_name;
	unsigned char client_id[CLIENT_ID_SIZE] = { 'A' };

	std::string public_key_str;
	std::string private_key_str;

	// file to send details
	std::string file_to_send_path;
	std::string file_name;



	/// <summary>
	/// Genenerates private and public keys.
	/// </summary>
	void generateKeys();

	/// <summary>
	/// Saves client details to me.info.
	/// </summary>
	void saveDetailsToFile();


	/// <summary>
	/// Receives response from server, and returns an indication about the success of the registration.
	/// </summary>
	/// <returns></returns>
	bool successfulRegistration();

	/// <summary>
	/// Receives response from server, and returns an indication about the success of the success of sending the public key.
	/// </summary>
	/// <returns></returns>
	bool publicKeySentSuccessfully();

	/// <summary>
	/// Receives response from server, and returns an indication about the success of the success of sending the file.
	/// </summary>
	/// <returns></returns>
	bool validCRCresponse();

	/// <summary>
	/// Receives response from server, and returns an indication about the success of the success of reconnect.
	/// </summary>
	/// <returns></returns>
	uint16_t reconnectSuccessfully();

	/// <summary>
	/// Receives response confirm message from server.
	/// </summary>
	void confirmMessage();

	/// <summary>
	/// Sends registration request.
	/// </summary>
	void registration();

	/// <summary>
	/// Sends public key.
	/// </summary>
	void sendPublicKey();

	/// <summary>
	/// Sends reconnect request.
	/// </summary>
	void reconnect();

	/// <summary>
	/// Sends file to server.
	/// </summary>
	void sendFile();

	/// <summary>
	/// Sends valid CRC request.
	/// </summary>
	void validCRC();

	/// <summary>
	/// Sends invalid CRC retry request.
	/// </summary>
	void invalidCRCretry();

	/// <summary>
	/// Sends invalid CRC abort.
	/// </summary>
	void invalidCRCabort();

	/// <summary>
	/// Creates request header.
	/// </summary>
	/// <param name="header"></param>
	/// <param name="code"></param>
	/// <param name="payload_size"></param>
	void buildRequestHeader(struct RequestHeader* header, uint16_t code, uint32_t payload_size);

	/// <summary>
	/// In case server failed, throw exception
	/// </summary>
	void serverFailed();


public:
	/// <summary>
	/// Creates new client, connects to server, receives details from me.info file if exists.
	/// </summary>
	/// <param name="transferInfo"></param>
	Client(const TransferInfo& transferInfo);
	~Client();
	void runProcess();

};