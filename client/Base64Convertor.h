#pragma once

#include <string>



class Base64Convertor
{
public:
	/// <summary>
	/// Encode string on base 64.
	/// </summary>
	/// <param name="str"></param>
	/// <returns></returns>
	static std::string encode(const std::string& str);

	/// <summary>
	/// Decode string on base 64.
	/// </summary>
	/// <param name="str"></param>
	/// <returns></returns>
	static std::string decode(const std::string& str);
};
