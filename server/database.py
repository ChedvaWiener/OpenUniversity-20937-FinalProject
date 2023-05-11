import logging
import sys
from typing import Dict
from datetime import date
from packages import Client, File
import sqlite3
from threading import Lock
from uuid import uuid4, UUID


class Database:
    DB_FILE = 'server.db'
    SQLITE_DATABASE_FILE_HEADER = 100

    def __init__(self):
        self.clients: Dict[UUID, Client] = {}
        # in order to let client send more than one file, files contains list of file to each client
        self.files: Dict[UUID, list] = {}

        self.conn = None
        self.create_or_open_database()
        self.create_tables()
        self.load_data()
        self.lock = Lock()

    def create_or_open_database(self):
        """Open the DB"""
        self.conn = sqlite3.connect(self.DB_FILE, check_same_thread=False)

    # self.conn.text_factory = bytes

    def create_tables(self):
        """Create table if not exists"""
        try:
            self.conn.executescript("""
                CREATE TABLE IF NOT EXISTS clients (
                ID int NOT NULL PRIMARY KEY,
                Name varchar(255) NOT NULL,
                PublicKey BLOB,
                LastSeen text,
                AESKey BLOB);
                """)

            self.conn.executescript(""" 
                  CREATE TABLE IF NOT EXISTS files (
                  ID blob NOT NULL PRIMARY KEY,
                  FileName varchar(255) NOT NULL,
                  PathName varchar(255) NOT NULL,
                  Verified text  
                 );
                  """)
            self.conn.commit()

        except Exception as error:
            self.shut_down(error)

    def load_data(self):
        """Load data from tables into dict"""
        try:
            cursor = self.conn
            clients = cursor.execute("SELECT* FROM clients").fetchall()
            files = cursor.execute("SELECT* FROM files").fetchall()

            for file in files:
                client_id = UUID(bytes=file[0])
                file = File(client_id=client_id, file_name=file[1], path=file[2],
                            verified=file[3])
                if client_id in self.files.keys():
                    self.files[client_id].insert(0,file)
                else:
                    self.files[client_id] = [file]

            for client in clients:
                client_id: UUID = UUID(bytes=client[0])
                self.clients[client_id] = Client(client_id=client_id, name=client[1], public_key=client[2],
                                                 last_seen=client[3], aes_key=client[4])
        except Exception as error:
            self.shut_down(error)

    def invalid_name(self, name):
        """Returns whether the name is invalid"""
        for client in self.clients.values():
            if client.name == name:
                return True
        return False

    def update_keys(self, client_id, public_key, aes_key):
        """Update key for a given client"""
        try:
            self.lock.acquire()
            cursor = self.conn.cursor()
            cursor.execute("UPDATE clients SET PublicKey=?, AESKey=? WHERE ID=?",
                           [public_key, aes_key, client_id.bytes])

            # in order to avoid exception, because there is no need to verify if the client registered first
            if client_id not in self.clients:
                last_seen = str(date.today())
                self.clients[client_id] = Client(client_id=client_id, name="Unknown name", public_key=public_key,
                                                 aes_key=public_key, last_seen=last_seen)
                cursor.execute("INSERT INTO clients (ID,Name, PublicKey, AESKey) VALUES (?,?, ?, ?)",
                               [client_id.bytes, "Unknown name", public_key, aes_key])
            else:
                self.clients[client_id].aes_key = aes_key
                self.clients[client_id].public_key = public_key
                self.conn.commit()

        except Exception as error:
            raise error

        finally:
            self.lock.release()

    def get_client_by_id(self, client_id) -> Client:
        """Get client info by ID"""
        try:
            self.lock.acquire()
            return self.clients[client_id]
        finally:
            self.lock.release()

    def register_client(self, name):
        """
        Register a new client, creates a new uuid as a client id, updates db with the new client,
        set last seen to current date.
        :return: A new client ID (UUID)
        """
        try:
            self.lock.acquire()
            client_id: UUID = uuid4()
            cursor = self.conn.cursor()
            last_seen = str(date.today())
            cursor.execute("INSERT INTO clients (ID, Name, LastSeen) VALUES (?, ?, ?)",
                           [client_id.bytes, name, last_seen])
            self.conn.commit()
            self.clients[client_id] = self.clients[client_id] = Client(client_id, name, public_key=None,
                                                                       last_seen=last_seen, aes_key=None)
            return client_id
        except Exception as error:
            raise error
        finally:
            self.lock.release()

    def add_file(self, client_id: UUID, file_name, path):
        """Add file for given client ID"""
        try:
            self.lock.acquire()
            cursor = self.conn.cursor()
            cursor.execute("INSERT OR REPLACE INTO files (ID, FileName, PathName, Verified) VALUES (?, ?, ?, ?)",
                           [client_id.bytes, file_name, path, "False"])
            self.conn.commit()
            file = File(client_id, file_name, path, False)
            if client_id in self.files.keys():
                self.files[client_id].insert(0, file)
            else:
                self.files[client_id] = [file]

        except Exception as error:
            raise error
        finally:
            self.lock.release()

    def verified_file(self, client_id: UUID, file_name):
        """Update a file for given client, set  file property: Verified to be True """
        try:
            cursor = self.conn.cursor()
            cursor.execute("UPDATE files SET Verified='TRUE' WHERE ID=? AND FileName=?", [client_id.bytes, file_name])
            self.conn.commit()
            self.lock.acquire()
            for file in self.files[client_id]:
                if file.file_name == file_name:
                    file.verified = True
            self.lock.release()
        except Exception as error:
            raise error

    def delete_file(self, client_id: UUID, file_name):
        """Delete the given file for the given client ID"""
        try:
            cursor = self.conn.cursor()
            cursor.execute("DELETE from files WHERE ID=? AND FileName=?", [client_id.bytes, file_name])
            self.conn.commit()
            self.lock.acquire()
            for file in self.files[client_id]:
                if file.file_name == file_name:
                    self.files[client_id].remove(file)

            self.lock.release()
        except Exception as error:
            raise error

    def update_last_seen(self, client_id):
        """Update client property: Last Seen set to the current date"""
        try:
            last_seen = str(date.today())
            cursor = self.conn.cursor()
            cursor.execute("UPDATE clients SET LastSeen=? WHERE ID=?",
                           [last_seen, client_id.bytes])
            self.conn.commit()
            self.lock.acquire()
            self.clients[client_id].last_seen = last_seen
        except Exception as error:
            raise error
        finally:
            self.lock.release()

    def get_file_path(self, client_id, file_name):
        """Get a file path for given client ID and file name"""
        self.lock.acquire()
        path = ''
        for file in self.files[client_id]:
            if file.file_name == file_name:
                path = file.path
        self.lock.release()
        return path

    def client_name_exists(self, client_name):
        result = False
        self.lock.acquire()
        for client in self.clients.values():
            if client.name == client_name:
                result = True
        self.lock.release()
        return result

    @staticmethod
    def shut_down(error):
        """In case of fatal error"""
        logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.NOTSET)
        logging.error(error)
        logging.info("Server shutdown")
        sys.exit(-1)
