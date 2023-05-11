from uuid import UUID
import uuid
from enum import Enum

import sizesInfo


class File:
    def __init__(self, client_id, file_name, path, verified):
        self.verified = verified
        self.path = path
        self.file_name = file_name
        self.client_id = client_id


class Client:
    def __init__(self, client_id: UUID, name, public_key, last_seen, aes_key):
        self.client_id = client_id
        self.name = name
        self.public_key = public_key
        self.last_seen = last_seen
        self.aes_key = aes_key


# -----------------Requests classes----------------------

class RequestHeader:
    def __init__(self, client_id, version, code, payload_size):
        try:
            self.client_id = uuid.UUID(bytes=client_id)
        except ValueError:
            raise Exception("Illegal client_id, not a UUID")
        self.version = version
        self.code = code
        self.payload_size = payload_size


class RegisterRequest:
    def __init__(self, name):
        self.name = name.decode('windows-1252').split('\0', 1)[0]


class ReconnectRequest:
    def __init__(self, name):
        self.name = name.decode('windows-1252').split('\0', 1)[0]


class ClientPublicKey:
    def __init__(self, name, public_key):
        self.name = name.decode('windows-1252').split('\0', 1)[0]
        self.public_key = public_key


class ReceiveFile:
    def __init__(self, content_size, file_name, message_content):
        self.content_size = content_size
        self.file_name = file_name.decode('windows-1252').split('\0', 1)[0]
        self.message_content = message_content


class ChecksumRequest:
    def __init__(self, file_name):
        self.file_name = file_name.decode('windows-1252').split('\0', 1)[0]


class RequestPayloadCodes(Enum):
    Register = 1100
    ClientSendPublicKey = 1101
    Reconnect = 1102
    SendFile = 1103
    ValidCRC = 1104
    InvalidCRCRetry = 1105
    InvalidCRCAbort = 1106


# -----------------Responses classes----------------------

class ResponsePayloadCodes(Enum):
    RegistrationSuccess = 2100
    RegistrationFailed = 2101
    SendAES = 2102
    ValidCRC = 2103
    ConfirmMessage = 2104
    ConfirmReconnect = 2105
    DenyReconnect = 2106
    ServerFailed = 2107


SERVER_VERSION = 3


class ResponseHeader:
    def __init__(self, code):
        self.version = SERVER_VERSION
        self.code = code
        self.payload_size = sizesInfo.EMPTY

    def update_payload(self, payload_size):
        self.payload_size = payload_size


class ResponseRegistrationSuccess(ResponseHeader):
    def __init__(self, client_id: UUID):
        super().__init__(ResponsePayloadCodes.RegistrationSuccess.value)
        self.client_id = client_id


class ResponseRegistrationFailed(ResponseHeader):
    def __init__(self):
        super().__init__(ResponsePayloadCodes.RegistrationFailed.value)


class ResponseSendAES(ResponseHeader):
    def __init__(self, client_id: UUID, aes_key: bytes):
        super().__init__(ResponsePayloadCodes.SendAES.value)
        self.client_id = client_id
        self.aes_key = aes_key


class ResponseValidCRC(ResponseHeader):
    def __init__(self, client_id: UUID, content_size: int, file_name: str, checksum: int):
        super().__init__(ResponsePayloadCodes.ValidCRC.value)
        self.client_id = client_id
        self.content_size = content_size
        self.file_name = file_name
        self.checksum = checksum


class ResponseConfirmMessage(ResponseHeader):
    def __init__(self, client_id: UUID):
        super().__init__(ResponsePayloadCodes.ConfirmMessage.value)
        self.client_id = client_id


class ResponseConfirmReconnect(ResponseHeader):
    def __init__(self, client_id: UUID, aes_key: bytes):
        super().__init__(ResponsePayloadCodes.ConfirmReconnect.value)
        self.client_id = client_id
        self.aes_key = aes_key


class ResponseDenyReconnect(ResponseHeader):
    def __init__(self, client_id: UUID):
        super().__init__(ResponsePayloadCodes.DenyReconnect.value)
        self.client_id = client_id


class ResponseServerFailed(ResponseHeader):
    def __init__(self):
        super().__init__(ResponsePayloadCodes.ServerFailed.value)
