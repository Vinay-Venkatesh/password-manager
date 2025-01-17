
import re
from db_connector import Database
import bcrypt

# Instance of Database class
db_object = Database()

class Validator:
    def validate_inputs(self,_email,_password):

        if self.validate_email(_email):
            print("email is present")
            if self.validate_master_password(_email,_password):
                return True
            else:
                return False
        else:
            print("email {0} is not present, signup if new user".format(_email))
            exit(1)

    def validate_email(self,_email):
        # Check if the mail id is as per standards (@gmail.com)
        # exit(1) if the mail id is not as per standard
        # if mail id is present - valid it against the db record
        # returns true or false
        regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'
        if re.fullmatch(regex,_email):
            print("The email id is valid")
        else:
            print("Invalid email id format - should be the format : example@gmail.com")
            exit(1)

        # mysql connection
        mysql_con = db_object.db_connector()
        mysql_cur = mysql_con.cursor()
        mysql_cur.execute("select uuid from password_keeper.user_info where email = %s", [_email])
        _present = mysql_cur.fetchone()
        mysql_con.close()
        if _present:
            return True
        else:
            return False

    def validate_master_password(self,_email,_password):
        # Checks if the password matches
        # returns true or false

        # mysql connection
        mysql_con = db_object.db_connector()
        mysql_cur = mysql_con.cursor()
        mysql_cur.execute("select master_key from password_keeper.user_info where email = %s", [_email])
        user_pass = mysql_cur.fetchone()[0]

        # key, salt, hash_algo, iterations = user_details[2:6]
        #
        # # Recompute hash from user password
        # password_hash = hashlib.pbkdf2_hmac(
        #     hash_algo,
        #     _password.encode('utf-8'),
        #     salt,
        #     iterations
        # )
        mysql_con.close()

        return bcrypt.checkpw(_password.encode('utf-8'), user_pass)

    def validate_link(self,_passlink):
        # mysql connection
        mysql_con = db_object.db_connector()
        mysql_cur = mysql_con.cursor()
        mysql_cur.execute("select link from password_keeper.password_info where link = %s", [_passlink])
        _present = mysql_cur.fetchone()
        mysql_con.close()
        if _present:
            return True
        else:
            return False