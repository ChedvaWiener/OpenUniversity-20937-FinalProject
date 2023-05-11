#pragma once
#include <cstdint>


#define VERSION           (3)
#define CLIENT_ID_SIZE    (16)
#define MAX_CLIENT_NAME   (255)
#define PUBLIC_KEY_SIZE   (160)
#define MAX_FILE_NAME     (255)
#define CHUNK_SIZE        (1024)
#define HEADER_SIZE       (7)
#define CONTENT_SIZE      (4)


// Responses and requests structs.

#pragma pack(push, r1, 1)
/* -----------------Requests-------------------  */
struct RequestHeader
{

	unsigned char client_id[CLIENT_ID_SIZE] = { 0 };
#pragma pack(push, 1)
	uint8_t version;
#pragma pack(pop)
	uint16_t code;
	unsigned int payload_size;
};




enum RequestsCode : uint16_t {
	Register              = 1100,
	SentPublicKey         = 1101,
	Reconnect             = 1102,
	SendFile              = 1103,
	ValidCRCrequestCode   = 1104,
	InvalidCRCretry       = 1105,
	InvalidCRCabort       = 1106
};


struct RegisterRequest {
	char client_name[MAX_CLIENT_NAME] = { 0 };
};

struct SendPublicKeyRequest {
	char client_name[MAX_CLIENT_NAME] = { 0 };
	char public_key[PUBLIC_KEY_SIZE] = { 0 };
};

struct ReconnecrRequest {
	char client_name[MAX_CLIENT_NAME] = { 0 };
};

struct SendFileRequest {
	unsigned int content_size;
	char file_name[MAX_FILE_NAME] = { 0 };
};

struct ValidCRCrequest {
	char file_name[MAX_FILE_NAME] = { 0 };
};

struct InvalidCRCretryRequest {
	char file_name[MAX_FILE_NAME] = { 0 };
};

struct InvalidCRCabortRequest {
	char file_name[MAX_FILE_NAME] = { 0 };
};

/* -------------------Responses---------------------------  */
struct ResponseHeader {
	unsigned char  version;
	uint16_t       code;             //
	unsigned int   payload_size; //4 bytes 
};



enum ResponseCode : uint16_t {
	SuccessfulRegistration   = 2100,
	RegistrationFailed       = 2101,
	KeySentGetAES            = 2102,
	ValidCRCresponseCode     = 2103,
	ConfirmMessage           = 2104,
	ApproveReconnect         = 2105,
	ReconnectDenied          = 2106,
	ServerFailed             = 2107
};

struct SuccessfulRegistrationResponse {
	unsigned char client_id[CLIENT_ID_SIZE];
};


struct KeySentGetAESresponse {
	unsigned char* client_id;
	unsigned char* symetric_key;
};

struct ApproveReconnectResponse {
	unsigned char* client_id;
	unsigned char* symetric_key;

};

struct ValidCRCResponse {
	unsigned char client_id[CLIENT_ID_SIZE];
	unsigned int content_size;
	char file_name[MAX_FILE_NAME];
	unsigned int checksum;
};

struct ConfirmMessageResponse {
	unsigned char client_id[CLIENT_ID_SIZE];
};

struct ReconnectDeniedResponse {
	unsigned char client_id[CLIENT_ID_SIZE];
};
#pragma pack(pop, r1)