import logging
import sys
from serverThread import ServerThread
from database import Database
import socket


class Server:
    DEFAULT_PORT = 1234
    HOST = '127.0.0.1'

    PORT_INFO = 'port.info.txt'

    def __init__(self):
        logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.NOTSET)
        logging.info("Hello from server.")
        self.port = self.DEFAULT_PORT
        self.database = Database()
        self.get_port()
        self.create_socket()

    def get_port(self):
        """Reads PORT from the file PORT_INFO"""
        try:
            with open(Server.PORT_INFO, 'r') as file:
                lines = [line.strip() for line in file]
                if len(lines) > 1:
                    logging.warning(
                        f"In correct port file format: {Server.PORT_INFO},using port: {Server.DEFAULT_PORT}.")
                elif not lines[0].isnumeric():
                    logging.warning(f"Incorrect port: {lines[0]},using port:{Server.DEFAULT_PORT}.")
                    pass
                else:
                    self.port = int(lines[0])
        except Exception as error:
            logging.error(f"Cannot open file {Server.PORT_INFO}: {error}.")
            logging.info(f"Using port:{Server.DEFAULT_PORT}.")

    def create_socket(self):
        """Creates socket and waits for a client connection"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
                server.bind((Server.HOST, self.port))
                server.listen()
                logging.info(f"Server listening  on {Server.HOST}:{self.port}.")
                while True:
                    client_socket, address = server.accept()
                    logging.info(f"New client on {address}.")
                    ServerThread(client_socket, self.database).start()
        except Exception as error:
            self.shut_down(error)
        finally:
            self.database.conn.close()

    @staticmethod
    def shut_down(error):
        """In case of fatal error shut the server down"""
        logging.error(error)
        logging.info("Server shutdown")
        sys.exit(-1)
