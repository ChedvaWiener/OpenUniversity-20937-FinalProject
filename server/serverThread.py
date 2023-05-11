import os
import struct
import sys
import threading
from threading import Thread
from collections import namedtuple
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import unpad
from Crypto.Cipher import AES, PKCS1_OAEP
import CRC32
import sizesInfo
from packages import RequestHeader, RequestPayloadCodes, RegisterRequest, ClientPublicKey, \
    ReconnectRequest, \
    ReceiveFile, ChecksumRequest, Client, ResponseHeader, ResponseRegistrationSuccess, \
    ResponseRegistrationFailed, ResponseSendAES, ResponseValidCRC, ResponseConfirmMessage, ResponseConfirmReconnect, \
    ResponseDenyReconnect, ResponseServerFailed
import logging


class ServerThread(Thread):
    SERVER_VERSION = 3

    def __init__(self, client_socket, database):
        super().__init__(name='client_socket', daemon=True)
        self.client_socket = client_socket
        self.database = database

        # Create and configure logger
        logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.NOTSET)
        logging.info("Server Thread ID " + str(threading.current_thread().ident))

    def run(self) -> None:
        """
        Get and handel request
        :return: None
        """
        try:
            while True:
                self.handle_request()
        except Exception as error:
            error_msg = f"Request failed: {error}."
            self.close_connection(error_msg)

    # --------------------------------- Request --------------------------

    def handle_request(self) -> None:
        """
        Handles client request by receiving the header of the request, and processing the request
        :return: None
        """
        try:
            # receive client request header, without payload content
            header = self.receive_header()
            Header_namedtuple = namedtuple(
                'Header', ['client_id', 'version', 'code', 'payload_size'])
            unpacked_header = Header_namedtuple._make(self.parse_header(header))
            header = RequestHeader(unpacked_header.client_id, unpacked_header.version, unpacked_header.code,
                                   unpacked_header.payload_size)
            self.process_request(header)
        except Exception as error:
            error_msg = f"Request failed: {error}."
            self.close_connection(error_msg)

    @staticmethod
    def parse_header(header) -> tuple:
        """
        Unpacks the header according to given sizes (in bytes): client_id-16 bytes, version-1 byte,
        code-2 bytes, payload_size-4 bytes.
        header: the request header received from client
        returns unpacked header tuple
        """
        # Interpret bytes as packed binary data
        return struct.unpack(f'<{sizesInfo.UUID_SIZE}sBHI', header)

    def receive_header(self) -> bytes:
        """
        Receives the header of client request
        :return: bytes
        """
        try:
            # get header data from socket
            header = self.client_socket.recv(sizesInfo.REQUEST_HEADER_SIZE)
            if not header:
                raise ValueError("Request failed: missing header")
            if len(header) != sizesInfo.REQUEST_HEADER_SIZE:
                raise ValueError(
                    f"Request failed: invalid header format: requested header size: {sizesInfo.REQUEST_HEADER_SIZE}")
            else:
                return header
        except Exception as error:
            self.close_connection(error)

    def process_request(self, header: RequestHeader) -> None:
        """
        Receives a request and handles it; sends to the appropriate handler function
        header: unpacked header, represented by a Header class
        :return: None
        """
        # Handles the request according to the code.
        try:
            match header.code:
                case RequestPayloadCodes.Register.value:
                    self.register(header)
                case RequestPayloadCodes.ClientSendPublicKey.value:
                    self.client_send_public_key(header)
                case RequestPayloadCodes.Reconnect.value:
                    self.reconnect(header)
                case RequestPayloadCodes.SendFile.value:
                    self.receive_file(header)
                case RequestPayloadCodes.ValidCRC.value:
                    self.valid_crc(header)
                case RequestPayloadCodes.InvalidCRCRetry.value:
                    self.invalid_crc_retry(header)
                case RequestPayloadCodes.InvalidCRCAbort.value:
                    self.invalid_crc_abort(header)
                case _:
                    raise Exception("Request failed: invalid code request.")
        except Exception as error:
            self.close_connection(error)

    @staticmethod
    def parse_payload(payload, **kwargs) -> tuple:
        """
        Gets the payload bytes object, and unpacks it in a way
        that the resulted bytes would split into categories
        according to key word arguments provided.
        payload: payload  received from client
        kwargs: type dict, key value elements (categories in payload)
        :return: tuple that contains the payload, split according the kwargs argument.
        """
        if len(payload) > sum(kwargs.values()):
            # key word args refers as a dictionary
            raise ValueError("Could not parse payload, invalid size")
        splitter = ''
        for num_bytes in kwargs.values():
            # create format for unpacking payload
            splitter += f'{num_bytes}s'
        # unpack payload to wanted fields
        return struct.unpack(splitter, payload)

    def register(self, header: RequestHeader) -> None:
        """ Handles registration requests. """
        try:
            # build request
            request: RegisterRequest = self.registration_request(header)
            # makes sure the name is valid
            if self.database.invalid_name(request.name):
                raise ValueError(f"Request Failed: client named:{request.name} already exists ")
            new_id = self.database.register_client(request.name)
            # build response
            response = ResponseRegistrationSuccess(new_id)
            self.response_registration(response)
        except Exception as error:
            response = ResponseRegistrationFailed()
            self.response_registration_failed(response)
            self.close_connection(error)

    def registration_request(self, header: RequestHeader) -> RegisterRequest:
        """
        Receives payload and build RegisterRequest object
        :raise: Exception
        :return: RegisterRequest
        """
        # if didn't manage to receive payload - caller will raise exception
        try:
            payload = self.recv_payload(header.payload_size)
            Payload = namedtuple('Payload', ['client_name'])
            unpacked_payload = Payload._make(self.parse_payload(
                payload, clientname_size=sizesInfo.NAME_MAX_LENGTH))
            return RegisterRequest(unpacked_payload.client_name)
        except Exception as error:
            logging.error(error)
            response = ResponseRegistrationFailed()
            self.response_registration_failed(response)

    def recv_payload(self, size: int) -> bytes:
        """
        Receives the client payload from socket.
        size: payload size (bytes)
        :raise: Exception
        :return: payload (bytes object)
        """
        # receive payload data from socket
        data = self.client_socket.recv(size)
        if not data:
            raise ValueError("Empty request")
        if len(data) != size:
            raise ValueError("Request failed: incorrect payload length")
        return data

    def client_send_public_key(self, header: RequestHeader) -> None:
        """
        Handle key exchange request,
        and adds the public key to the clients BD table.
        """
        request: ClientPublicKey = self.client_send_public_key_request(header)
        logging.info(f"Creating key for client {request.name}.")
        # Create AES Key
        aes_key: bytes = os.urandom(sizesInfo.AES_KEY_SIZE)
        try:
            # save AES Key to database
            public_key: bytes = request.public_key  # .split(b'\0', 1)[0]

            # encrypt the key
            encrypted_key = PKCS1_OAEP.new(RSA.importKey(public_key)).encrypt(aes_key)

            self.database.update_keys(header.client_id, public_key, aes_key)
            # build response
            response = ResponseSendAES(header.client_id, encrypted_key)
            self.response_send_aes(response)

        except Exception as error:
            logging.error(error)
            self.response_server_failed(ResponseServerFailed())

    def client_send_public_key_request(self, header: RequestHeader) -> ClientPublicKey:
        """
        Unpacks the payload from the client.
        :return: ClientPublicKey
        """
        try:
            payload = self.recv_payload(header.payload_size)
            Payload = namedtuple('Payload', ['client_name', 'public_key'])
            unpacked_payload = Payload._make(self.parse_payload(
                payload, clientname_size=sizesInfo.NAME_MAX_LENGTH, public_key_size=sizesInfo.PUBLIC_KEY_SIZE))
            return ClientPublicKey(unpacked_payload.client_name, unpacked_payload.public_key)
        except Exception as error:
            logging.error(error)
            self.response_server_failed(ResponseServerFailed())

    def reconnect(self, header: RequestHeader) -> None:
        """ Handle reconnect request."""
        try:
            request: ReconnectRequest = self.reconnect_request(header)
            if not self.database.client_name_exists(request.name):
                raise ValueError(f"Failed to reconnect,cannot find registered client named: {request.name}")
            # update client last seen
            self.database.update_last_seen(header.client_id)
            # get client details
            client: Client = self.database.get_client_by_id(header.client_id)
            aes_key = client.aes_key
            if aes_key is None:
                raise ValueError(f"Client {client.client_id} has not sent AES yet.")
            # encrypt AES key using public key
            encrypted_aes = PKCS1_OAEP.new(RSA.importKey(client.public_key)).encrypt(aes_key)
            # build response
            response = ResponseConfirmReconnect(client.client_id, encrypted_aes)
            self.response_confirm_reconnect(response)
        except Exception as error:
            logging.error(error)
            response = ResponseDenyReconnect(header.client_id)
            self.response_deny_reconnect(response)

    def reconnect_request(self, header: RequestHeader) -> ReconnectRequest:
        """
        Receives payload and build ReconnectRequest object
        :raise: Exception
        :return: ReconnectRequest
        """
        # if didn't manage to receive payload - caller will raise exception
        payload = self.recv_payload(header.payload_size)
        Payload = namedtuple('Payload', ['client_name'])
        unpacked_payload = Payload._make(self.parse_payload(
            payload, clientname_size=sizesInfo.NAME_MAX_LENGTH))
        return ReconnectRequest(unpacked_payload.client_name)

    def receive_file(self, header: RequestHeader) -> None:
        """ Handle send file request.
        If there is already a file for the client with this name,
        it will overwrite the previous file and update the DB."""
        try:
            # get request
            request: ReceiveFile = self.receive_file_request(header)
            client_id = header.client_id
            logging.info(f"Receive file: client: {client_id},file: {request.file_name}.")
            # get client details
            client: Client = self.database.get_client_by_id(header.client_id)
            key = client.aes_key
            if key is None:
                raise ValueError(f"Client {client.client_id} has not sent AES yet.")
            # create dir
            # checking if the directory for the client exist or not.
            tmp_path = os.path.join('received_files', client.name.strip())
            if not os.path.exists(tmp_path):
                # if is not present then create it.
                os.makedirs(tmp_path)
            # create path for local file
            path = os.path.join(tmp_path, request.file_name)
            message_content = request.message_content
            self.write_to_file(path, message_content, key)
            # update the DB
            self.database.add_file(client.client_id, request.file_name, path)
            # calculate the file CRC
            crc = CRC32.CRC32().file_crc_calc(path)
            logging.info(f"The file's ({request.file_name}) CRC is 0x{crc:02x}.")
            # build response
            response = ResponseValidCRC(client.client_id, request.content_size, request.file_name, crc)
            self.response_valid_crc(response)
        except Exception as error:
            logging.error(f"Receive file failed: {error}")
            self.response_server_failed(ResponseServerFailed())

    @staticmethod
    def write_to_file(path, message_content, key):
        """"Decrypt the message and write to a local file"""
        # create zeroed iv
        iv = (b'\0' * AES.block_size)
        cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=iv)
        # decrypt the message and remove the standard padding
        stripped: bytes = unpad(cipher.decrypt(message_content), AES.block_size)
        # write to local file
        with open(path, 'wb+') as file:
            file.write(stripped)

    def receive_file_request(self, header: RequestHeader) -> ReceiveFile:
        """
        Receives payload and build ReceiveFile object
        :raise: Exception
        :return: ReceiveFile
        """
        # if didn't manage to receive payload - caller will raise exception
        try:
            # receive payload
            payload_size = sizesInfo.CONTENT_SIZE + sizesInfo.FILE_NAME_LENGTH
            payload = self.recv_payload(payload_size)
            Payload = namedtuple('Payload', ['content_size', 'file_name'])
            unpacked_payload = Payload._make(self.parse_payload(
                payload, content_size=sizesInfo.CONTENT_SIZE, file_name=sizesInfo.FILE_NAME_LENGTH))

            # receive file
            message_size = header.payload_size - payload_size
            message_content = self.recv_payload(message_size)
            Message_content = namedtuple('Message_content', ['content'])
            content = Message_content._make(self.parse_payload(
                message_content, message_size=message_size))

            return ReceiveFile(message_size, unpacked_payload.file_name, content.content)

        except Exception as error:
            raise error

    def checksum_request(self, header: RequestHeader) -> ChecksumRequest:
        """
        Receives payload and build ChecksumRequest object
        :raise: Exception
        :return: ChecksumRequest
        """
        # if didn't manage to receive payload - caller will raise exception
        try:
            payload = self.recv_payload(header.payload_size)
            Payload = namedtuple('Payload', ['file_name'])
            unpacked_payload = Payload._make(self.parse_payload(
                payload, file_name=sizesInfo.FILE_NAME_LENGTH))
            return ChecksumRequest(unpacked_payload.file_name)
        except Exception as error:
            raise error

    def valid_crc(self, header: RequestHeader) -> None:
        """ Handles valid CRC requests. """
        try:
            # receive request
            request: ChecksumRequest = self.checksum_request(header)
            self.database.verified_file(header.client_id, request.file_name)
            logging.info(f"Checksum verified for file {request.file_name}, client {header.client_id}.")
            # build response
            response = ResponseConfirmMessage(header.client_id)
            self.response_confirm_message(response)
            self.close_connection_info("Client process is done.")

        except Exception as error:
            logging.error(error)
            self.response_server_failed(ResponseServerFailed())

    def invalid_crc_retry(self, header: RequestHeader) -> None:
        """ Handles invalid valid CRC requests - retry. """
        # receive request
        request: ChecksumRequest = self.checksum_request(header)
        logging.warning(
            f"Upload file failed:\n client: {header.client_id},\n file: {request.file_name}.\nTry again.")
        # build response
        response = ResponseConfirmMessage(header.client_id)
        self.response_confirm_message(response)

    def invalid_crc_abort(self, header: RequestHeader) -> None:
        """ Handles invalid valid CRC requests - abort. """
        # receive request
        request: ChecksumRequest = self.checksum_request(header)
        logging.warning(f"Receive  file aborted:\n client: {header.client_id},\n file: {request.file_name}.")
        # delete the local file if exists
        try:
            file_path = self.database.get_file_path(header.client_id, request.file_name)
            if os.path.isfile(file_path):
                os.remove(file_path)
            # delete the local file from DB
            self.database.delete_file(header.client_id, request.file_name)
            # build response
            response = ResponseConfirmMessage(header.client_id)
            self.response_confirm_message(response)
            self.close_connection_info("Client process aborted.")
        except Exception as error:
            logging.error(error)
            self.response_server_failed(ResponseServerFailed())

    # --------------------------------- Response --------------------------

    @staticmethod
    def response_header(header: ResponseHeader) -> bytes:
        return struct.pack('<BHI', header.version, header.code, header.payload_size)

    def send(self, package: bytes):
        """Sends server response to client through socket."""
        self.client_socket.send(package)

    def response_registration(self, response: ResponseRegistrationSuccess):
        """Response registration successes."""
        response.update_payload(sizesInfo.UUID_SIZE)
        packed_header = self.response_header(response)
        packed_payload = struct.pack(f'<{sizesInfo.UUID_SIZE}s', response.client_id.bytes)
        # send header
        self.send(packed_header)
        # send payload
        self.send(packed_payload)

    def response_registration_failed(self, response: ResponseRegistrationFailed):
        """Response registration failed."""
        packed_header = self.response_header(response)
        # send header
        self.send(packed_header)

    def response_send_aes(self, response: ResponseSendAES):
        """Response send aes."""
        response.update_payload(len(response.aes_key) + sizesInfo.UUID_SIZE)
        packed_header = self.response_header(response)
        packed_payload = struct.pack(f'<{sizesInfo.UUID_SIZE}s', response.client_id.bytes) + response.aes_key
        # send header
        self.send(packed_header)
        # send payload
        self.send(packed_payload)

    def response_confirm_message(self, response: ResponseConfirmMessage):
        """Response confirm message."""
        fmt = f'<{sizesInfo.UUID_SIZE}s'
        v = [response.client_id.bytes]
        response.update_payload(struct.calcsize(fmt))
        packed_header = self.response_header(response)
        packed_payload = struct.pack(fmt, *v)
        # send header
        self.send(packed_header)
        # send payload
        self.send(packed_payload)

    def response_valid_crc(self, response: ResponseValidCRC):
        """Response sent file valid checksum."""
        fmt = f'<{sizesInfo.UUID_SIZE}sL{sizesInfo.FILE_NAME_LENGTH}sL'
        v = [response.client_id.bytes, response.content_size, str.encode(response.file_name), response.checksum]
        response.update_payload(struct.calcsize(fmt))
        packed_header = self.response_header(response)
        packed_payload = struct.pack(fmt, *v)
        # send header
        self.send(packed_header)
        # send payload
        self.send(packed_payload)

    def response_confirm_reconnect(self, response: ResponseConfirmReconnect):
        """Response confirm reconnect."""
        response.update_payload(len(response.aes_key) + sizesInfo.UUID_SIZE)
        packed_header = self.response_header(response)
        packed_payload = struct.pack(f'<{sizesInfo.UUID_SIZE}s', response.client_id.bytes) + response.aes_key
        # send header
        self.send(packed_header)
        # send payload
        self.send(packed_payload)

    def response_deny_reconnect(self, response: ResponseDenyReconnect):
        """Response deny reconnection."""
        fmt = f'<{sizesInfo.UUID_SIZE}s'
        v = [response.client_id.bytes]
        response.update_payload(struct.calcsize(fmt))
        packed_header = self.response_header(response)
        packed_payload = struct.pack(fmt, *v)
        # send header
        self.send(packed_header)
        # send payload
        self.send(packed_payload)

    def response_server_failed(self, response: ResponseServerFailed):
        """Response server failed."""
        packed_header = self.response_header(response)
        self.send(packed_header)  # send header

    def close_connection(self, error):
        """In case of fatal or a protocol error, close client connection."""
        logging.error(error)
        logging.info("Client connection is down, du to a fatal error or a protocol error")
        self.client_socket.close()
        sys.exit(-1)

    def close_connection_info(self, info):
        """When process is done."""
        logging.info(info)
        logging.info("Client connection is down.")
        self.client_socket.close()
        sys.exit(0)



