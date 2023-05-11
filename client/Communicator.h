#pragma once
#include <boost/asio.hpp>
#include <boost/crc.hpp>
#include "Packages.h"

using boost::asio::ip::tcp;

static class Communicator {
public:
	/// <summary>
	/// Receives bytes from server.
	/// </summary>
	/// <param name="buffer"></param>
	/// <param name="bytes"></param>
	static void recieveBytes(unsigned char* buffer, size_t bytes, boost::asio::ip::tcp::socket& socket)
	{
		// recieve bytes from server
		size_t recieve_bytes = boost::asio::read(socket, boost::asio::buffer(buffer, bytes));
		if (recieve_bytes < bytes)
		{
			std::string err = "Recieve from server error: expected " + std::to_string(bytes) + " recieved: " + std::to_string(recieve_bytes);
			throw std::exception(err.c_str());
		}
	}


	/// <summary>
    /// Receives bytes from servet and converts them to struct.
    /// </summary>
    /// <typeparam name="T"></typeparam>
    /// <param name="val"></param>
    /// <returns></returns>
	template<typename T>
	static T recieveSstruct(boost::asio::ip::tcp::socket& socket)
	{
		T struct_temp;
		unsigned char* char_struct;
		char_struct = (unsigned char*)&struct_temp;

		// recieve bytes from server
		size_t recieve_bytes = boost::asio::read(socket, boost::asio::buffer(char_struct, sizeof(T)));
		if (recieve_bytes < sizeof(T))
		{
			std::string err = "Recieve from server error: expected " + std::to_string(sizeof(T)) + " recieved: " + std::to_string(recieve_bytes);
			throw std::exception(err.c_str());
		}

		// cast bytes to struct
		T* struct_ = (T*)char_struct;
		return *struct_;
	}

	/// <summary>
    /// Receives a struct and converts it to bytes and sends to the server.
    /// </summary>
    /// <typeparam name="T"></typeparam>
    /// <param name="data"></param>
	template<typename T>
	static void sendBytes(T* data, boost::asio::ip::tcp::socket& socket)
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


};

