#include "UUID.h"
#include <iostream>
#include <sstream>

#include <iomanip>
#include "Packages.h"


std::string UUID::uuidToString(unsigned char* uuid, size_t len)
{
    std::stringstream converter;
    converter << std::hex << std::setfill('0');

    for (size_t i = 0; i < len; i++)
        converter << std::setw(2) << (static_cast<unsigned>(uuid[i]) & 0xFF);
    return converter.str();

}


void UUID::stringToUuid(unsigned char* dest, const std::string src, size_t len)
{
    std::string bytes = "";
    std::stringstream converter;
    converter << std::hex << std::setfill('0');

    if (src.length() != CLIENT_ID_SIZE * 2)
        throw std::invalid_argument("Illegal uuid format");

    for (size_t i = 0; i < len*2; i += 2)
    {
        converter << std::hex << src.substr(i, 2);
        int byte;
        converter >> byte;
        bytes += (byte & 0xFF);
        converter.str(std::string());
        converter.clear();
    }
    memcpy(dest, bytes.c_str(), len);
}