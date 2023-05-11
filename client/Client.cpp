#include "Client.h"
#include <iostream>
#include <filesystem>
#include "Communicator.h"

using namespace boost::asio;
using ip::tcp;


Client::Client(const TransferInfo& transferInfo) : resolver(io_context), socket(io_context), connected(false)
{
	rsaWrapper = new RSAWrapper();

	meInfo = new MeInfo();
	registration_required = meInfo->getRegistrationRequired();

	// connect to server 
	boost::asio::ip::address ip = boost::asio::ip::make_address(transferInfo.getHostIP());
	socket.connect(tcp::endpoint(ip, transferInfo.getPort()));


	// fill client details 
	file_to_send_path = transferInfo.getFilePath();
	if (meInfo->getRegistrationRequired() == true)
	{
		client_name = transferInfo.getClientName();
	}
	else
	{
		client_name = meInfo->getClientName();
		memcpy_s(client_id, sizeof(client_id), meInfo->getClientId(), CLIENT_ID_SIZE);

		rsaWrapper->loadKey(meInfo->getPrivateKey());

	}
}

void Client::buildRequestHeader(struct RequestHeader* header, uint16_t code, uint32_t payload_size)
{
	memcpy_s(header->client_id, sizeof(header->client_id), &client_id, CLIENT_ID_SIZE);
	header->version = VERSION;
	header->code = code;
	header->payload_size = payload_size;
}
/*
template<typename T>
void Client::sendBytes(T* data)
{
	// cast struct to unsigned char*
	T tmp = *data;
	unsigned char* data_bytes = static_cast<unsigned char*>(static_cast<void*>(&tmp));

	// send bytes to server
	size_t bytes_sent = boost::asio::write(socket, boost::asio::buffer(data_bytes, sizeof(T)));

	if (bytes_sent < sizeof(T))
	{
		std::string err = "Send to server error: expected " + std::to_string(sizeof(T)) + " sent: " + std::to_string(bytes_sent);
		throw std::exception(err.c_str());
	}
}
*/
void Client::registration()
{

	// build the header
	size_t payload_size = MAX_CLIENT_NAME;
	RequestHeader t{};
	RequestHeader* request_header = &t;
	buildRequestHeader(request_header, RequestsCode::Register, payload_size);

	// build the request
	RegisterRequest request{};
	strcpy_s(request.client_name, sizeof(request.client_name), client_name.c_str());

	// send header
	Communicator::sendBytes(request_header, socket);

	// send request
	Communicator::sendBytes(&request, socket);
}

void Client::generateKeys()
{
	rsaWrapper->generateKeys();
	private_key_str = rsaWrapper->getPrivateKey();
	public_key_str = rsaWrapper->getPublicKey();
}

void Client::sendPublicKey()
{
	// build the header
	size_t payload_size = MAX_CLIENT_NAME + PUBLIC_KEY_SIZE;
	RequestHeader t{};
	RequestHeader* request_header = &t;
	buildRequestHeader(request_header, RequestsCode::SentPublicKey, payload_size);

	// send header
	Communicator::sendBytes(request_header, socket);

	// build the request
	SendPublicKeyRequest request{};
	strcpy_s(request.client_name, sizeof(request.client_name), this->client_name.c_str());
	memcpy_s(request.public_key, sizeof(request.public_key), this->public_key_str.c_str(), this->public_key_str.length());

	// send request
	Communicator::sendBytes(&request, socket);
}

void Client::reconnect()
{
	// build the header
	size_t payload_size = MAX_CLIENT_NAME;
	RequestHeader t{};
	RequestHeader* request_header = &t;
	buildRequestHeader(request_header, RequestsCode::Reconnect, payload_size);

	// build the request
	RegisterRequest request{};
	strcpy_s(request.client_name, sizeof(request.client_name), client_name.c_str());

	// send header
	Communicator::sendBytes(request_header, socket);

	// send request
	Communicator::sendBytes(&request, socket);
}

void Client::sendFile()
{
	//calculate content size
	auto path = std::filesystem::path(file_to_send_path);
	file_name = path.filename().string();
	if (file_name.length() >= MAX_FILE_NAME) {
		throw std::invalid_argument("File name to long");
	}

	auto file_size = std::filesystem::file_size(path);
	auto bloc_size = static_cast<int>(CryptoPP::AES::BLOCKSIZE);

	auto content_size = (ceil(file_size / bloc_size) + 1) * bloc_size;

	// build the header
	size_t payload_size = CONTENT_SIZE + MAX_FILE_NAME + content_size;

	RequestHeader t{};
	RequestHeader* request_header = &t;
	buildRequestHeader(request_header, RequestsCode::SendFile, payload_size);

	// build the request
	SendFileRequest request{};
	request.content_size = content_size;

	auto cipher = rsaWrapper->encryptFile(file_to_send_path);
	strcpy_s(request.file_name, sizeof(request.file_name), file_name.c_str());

	// send header
	Communicator::sendBytes(request_header, socket);

	// send request
	Communicator::sendBytes(&request, socket);

	// send file
	auto length = cipher.length();
	size_t bytes_sent = boost::asio::write(socket, boost::asio::buffer(cipher.c_str(), length));

	if (bytes_sent < length)
	{
		std::string err = "Send to server error: expected " + std::to_string(length) + " sent: " + std::to_string(bytes_sent);
		throw std::exception(err.c_str());
	}
}

void Client::validCRC()
{
	// build the header
	size_t payload_size = MAX_FILE_NAME;
	RequestHeader t{};
	RequestHeader* request_header = &t;
	buildRequestHeader(request_header, RequestsCode::ValidCRCrequestCode, payload_size);

	// build the request
	ValidCRCrequest request{};
	strcpy_s(request.file_name, sizeof(request.file_name), file_name.c_str());

	// send header
	Communicator::sendBytes(request_header, socket);

	// send request
	Communicator::sendBytes(&request, socket);
}

void Client::invalidCRCretry()
{
	// build the header
	size_t payload_size = MAX_FILE_NAME;
	RequestHeader t{};
	RequestHeader* request_header = &t;
	buildRequestHeader(request_header, RequestsCode::InvalidCRCretry, payload_size);

	// build the request
	InvalidCRCretryRequest request{};
	strcpy_s(request.file_name, sizeof(request.file_name), file_name.c_str());

	// send header
	Communicator::sendBytes(request_header, socket);

	// send request
	Communicator::sendBytes(&request, socket);

}

void Client::invalidCRCabort()
{
	// build the header
	size_t payload_size = MAX_FILE_NAME;
	RequestHeader t{};
	RequestHeader* request_header = &t;
	buildRequestHeader(request_header, RequestsCode::InvalidCRCabort, payload_size);

	// build the request
	InvalidCRCabortRequest request{};
	strcpy_s(request.file_name, sizeof(request.file_name), file_name.c_str());

	// send header
	Communicator::sendBytes(request_header, socket);

	// send request
	Communicator::sendBytes(&request, socket);
}

void Client::runProcess()
{
	try {
		while (!connected)
		{
			if (registration_required == true)
			{
				// try to register the client
				std::cout << "Registering client." << std::endl;
				registration();
				if (!successfulRegistration())
				{
					std::string err = "Registration failed.";
					throw std::exception(err.c_str());
				}

				// generate new keys 
				std::cout << "Generateing keys." << std::endl;
				generateKeys();

				// send the public key to server
				std::cout << "Sending public key." << std::endl;
				sendPublicKey();
				if (!publicKeySentSuccessfully())
				{
					std::string err = "Failed to send public key.";
					throw std::exception(err.c_str());
				}

				// write client details; name, id, private key
				saveDetailsToFile();
				connected = true;
			}
			else
			{
				// try to reconnect to server
				std::cout << "Trying to reconnect." << std::endl;
				reconnect();
				uint16_t reconnect = reconnectSuccessfully();
				if (reconnect == ResponseCode::ReconnectDenied)
				{
					std::cout << "Failed to reconnect, starting over." << std::endl;
				}
				else if (reconnect == ResponseCode::ServerFailed)
				{
					std::string err = "Server failed";
					throw std::exception(err.c_str());
				}
			}
		}
		std::cout << "\nConnected to server." << std::endl;
		std::cout << "\nSending file." << std::endl;

		int attempts = 1;
		while (attempts <= DENT_FILE_ATTEMPTS)
		{
			sendFile();
			std::cout << "\nSending attempt number: " << attempts << "." << std::endl;
			if (validCRCresponse() == true)
			{
				validCRC();
				confirmMessage();
				std::cout << "The file has been sent successfully." << std::endl;
				std::cout << "\nClient is done." << std::endl;
				break;
			}

			if (attempts != DENT_FILE_ATTEMPTS)
			{
				std::cout << "Server responded with an error." << std::endl;
				invalidCRCretry();
				std::cout << "Invalid CRC retrying" << std::endl;
			}
			if (attempts == DENT_FILE_ATTEMPTS)
			{
				invalidCRCabort();
				confirmMessage();
				std::cout << "Invalid CRC." << std::endl;
				std::cout << "Fatal error: cannot send file.\nABORTING." << std::endl;
				break;
			}
			attempts++;
		}
		socket.close();
	}
	catch (std::exception& e)
	{
		socket.close();
		std::string err = e.what();
		throw std::exception(err.c_str());
	}

}

void Client::saveDetailsToFile()
{
	meInfo->saveDetailsToFile(client_name, client_id, private_key_str);
}

void Client::confirmMessage()
{
	// get response header
	ResponseHeader header = Communicator::recieveSstruct <ResponseHeader>(socket);

	// check server response
	if (header.code == ResponseCode::ServerFailed)
	{
		serverFailed();
	}
	if (!header.code == ResponseCode::ConfirmMessage)
	{
		std::string err = "Unexpected response";
		throw std::exception(err.c_str());
	}

	// get response, the response is not used, but received according to the protocol
	ConfirmMessageResponse response = Communicator::recieveSstruct<ConfirmMessageResponse>(socket);
}

bool Client::successfulRegistration()
{
	// get response header
	ResponseHeader header = Communicator::recieveSstruct<ResponseHeader>(socket);

	// check server response
	if (header.code == ResponseCode::ServerFailed)
	{
		std::cout << "Server failed" << std::endl;
		return false;
	}
	if (header.code == ResponseCode::RegistrationFailed)
	{
		std::cout << "Server denied registration" << std::endl;
		return false;
	}
	if (header.code != ResponseCode::SuccessfulRegistration)
	{
		std::cout << "Unexpected response" << std::endl;
		return false;
	}
	registration_required = false;

	// get response 
	SuccessfulRegistrationResponse response = Communicator::recieveSstruct<SuccessfulRegistrationResponse>(socket);
	memcpy_s(client_id, sizeof(client_id), response.client_id, sizeof(response.client_id));
	return true;
}

bool Client::validCRCresponse()
{
	// get response header
	ResponseHeader header = Communicator::recieveSstruct <ResponseHeader>(socket);

	// check server response
	if (header.code == ResponseCode::ServerFailed)
	{
		serverFailed();
	}
	if (!header.code == ResponseCode::ValidCRCresponseCode)
	{
		std::cout << "Unexpected response" << std::endl;
		return false;
	}

	// get response 
	ValidCRCResponse response = Communicator::recieveSstruct<ValidCRCResponse>(socket);
	auto file_crc = CRC32().fileCRCcalc(file_to_send_path);
	return response.checksum == file_crc;
}
#pragma pack(push, r1, 1)
uint16_t Client::reconnectSuccessfully()
{
	// get response header
	ResponseHeader header = Communicator::recieveSstruct<ResponseHeader>(socket);

	// check server response
	if (header.code == ResponseCode::ServerFailed)
	{
		serverFailed();
	}
	else if (header.code == ResponseCode::ApproveReconnect)
	{
		// set the response struct 
		ApproveReconnectResponse response{};
		auto symetric_key_size = header.payload_size - CLIENT_ID_SIZE;
		response.client_id = new unsigned char[CLIENT_ID_SIZE];
		response.symetric_key = new unsigned char[symetric_key_size];

		// get response
		Communicator::recieveBytes(response.client_id, CLIENT_ID_SIZE, socket);

		Communicator::recieveBytes(response.symetric_key, symetric_key_size, socket);

		// decrypt the key
		public_key_str = rsaWrapper->decrypt(response.symetric_key, symetric_key_size);

		connected = true;

		delete[] response.client_id;
		delete[] response.symetric_key;
	}
	else
	{
		// get response, the response is not used, but received according to the protocol
		ReconnectDeniedResponse response = Communicator::recieveSstruct<ReconnectDeniedResponse>(socket);
		registration_required = true;
	}
	return header.code;
}

void Client::serverFailed()
{
	std::string err = "Server failed. ";
	throw std::exception(err.c_str());
}

bool Client::publicKeySentSuccessfully()
{
	// get response header
	ResponseHeader header = Communicator::recieveSstruct<ResponseHeader>(socket);

	// check server response
	if (header.code == ResponseCode::ServerFailed)
	{
		serverFailed();
	}
	if (!header.code == ResponseCode::KeySentGetAES)
	{
		std::cout << "Unexpected response" << std::endl;
		return false;
	}

	// set the response struct 
	KeySentGetAESresponse response{};
	auto symetric_key_size = header.payload_size - CLIENT_ID_SIZE;

	response.client_id = new unsigned char[CLIENT_ID_SIZE];
	response.symetric_key = new unsigned char[symetric_key_size];

	// get response
	Communicator::recieveBytes(response.client_id, CLIENT_ID_SIZE, socket);

	Communicator::recieveBytes(response.symetric_key, symetric_key_size, socket);

	// decrypt the key
	public_key_str = rsaWrapper->decrypt(response.symetric_key, symetric_key_size);

	delete[] response.client_id;
	delete[] response.symetric_key;

	return true;

}

#pragma pack(pop, r1)

Client::~Client()
{
	delete meInfo;
	delete rsaWrapper;
}





