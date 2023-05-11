#include <string>
#include <ostream>

#define UUID_SIZE (16)

class UUID {
public:
	/// <summary>
	/// Converts UUID to string.
	/// </summary>
	/// <param name="uuid"></param>
	/// <param name="len"></param>
	/// <returns></returns>
	static std::string uuidToString(unsigned char* uuid, size_t len);

	/// <summary>
	/// Converts string to UUID.
	/// </summary>
	/// <param name="dest"></param>
	/// <param name="src"></param>
	/// <param name="len"></param>
	static void stringToUuid(unsigned char* dest, const std::string src, size_t len);

};
