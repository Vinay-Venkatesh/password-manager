import mysql.connector

class Database():
    def __init__(self):
        self.__host = "localhost"
        self.__user = "root"
        self.__password = "root"
        self.__database = "password_keeper"
        self.__auth_plugin = "mysql_native_password"

    def db_connector(self):
        mydb_connector = mysql.connector.connect(
            host=self.__host,
            user=self.__user,
            password=self.__password,
            database=self.__database,
            auth_plugin=self.__auth_plugin
        )
        return mydb_connector