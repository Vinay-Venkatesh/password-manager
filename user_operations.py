from validator import Validator
import uuid
from security import generate_secure_password, Encryption, Decryption
from db_connector import Database
import bcrypt


# instance of Database class
db_object = Database()
encrypt_object = Encryption()
decrypt_object = Decryption()
validator_object = Validator()

class UserMgmt:
    ## persist new user details
    def user_signup(self,_email, _password):
        if not validator_object.validate_email(_email):

            uuid = str(self.get_uuid())
            password_hash = generate_secure_password(_password)

            # Split hash into components
            # salt, key = password_hash[:16], password_hash[16:]
            # hash_algo = "sha256"
            # iterations = 100_000

            # mysql connection
            mysql_con = db_object.db_connector()
            mysql_cur = mysql_con.cursor()
            sql = "INSERT INTO password_keeper.user_info (uuid, email, master_key) VALUES (%s, %s, %s)"
            val = (uuid,_email,password_hash)

            mysql_cur.execute(sql, val)
            mysql_con.commit()

            print(mysql_cur.rowcount, "record inserted.")
        else:
            print("user with this email is already present , login with the user credentials..")
            exit(1)

    def get_uuid(self):
        return uuid.uuid4()


class PasswordMgmt:
    #### New password entry.
    def add_password(self,_email, _master_key):
        print("*********************************")
        print("ADD NEW PASSWORD FOR A WEBSITE")
        print("*********************************")
        website_link = input("Enter the link or name of website which uses this password ")
        _is_present = validator_object.validate_link(website_link)
        if _is_present:
            print("An entry for this link or name of website is already present ")
            exit(1)
        else:
            passcode = input("Enter the password for above link or name of website ")
            salt = bcrypt.gensalt()
            key = encrypt_object.get_encryption_key(_master_key, salt) # generating encryption key with master_key + salt

            encrypted_passcode = encrypt_object.encrypt_password(passcode, key) # encrypting password with encryption key

            # mysql connection
            mysql_con = db_object.db_connector()
            mysql_cur = mysql_con.cursor()
            sql = "INSERT INTO password_keeper.password_info (email, link, passcode, salt) VALUES (%s, %s, %s, %s)"
            val = (_email, website_link, encrypted_passcode, salt)

            mysql_cur.execute(sql, val)
            mysql_con.commit()

            print(mysql_cur.rowcount, "record inserted.")

    def list_passwords(self,_email, _master_key):
        print("******************************************************")
        print("LIST OF PASSWORDS FOR THE USER - {0} ".format(_email))
        print("******************************************************")

        # mysql connection
        mysql_con = db_object.db_connector()
        mysql_cur = mysql_con.cursor()
        mysql_cur.execute("select * from password_keeper.password_info where email = %s",[_email])
        res = mysql_cur.fetchall()
        if res is None:
            print("No records found")
        else:
            for row in res:
                key = encrypt_object.get_encryption_key(_master_key, row[3])
                decrypted_passcode = decrypt_object.decrypt_password(row[2], key)
                print("Link - " + row[1])
                print("Password - " + decrypted_passcode)

        mysql_con.close()

    ## delete password
    def delete_password(self):
        print("*********************************")
        print("DELETE PASSWORD FOR A WEBSITE")
        print("*********************************")
        website_link = input("Enter the link or name of website to be deleted ")
        _is_present = validator_object.validate_link(website_link)
        if not _is_present:
            print("An entry for this link or name of website does not exists")
            exit(1)
        else:
            # mysql connection
            mysql_con = db_object.db_connector()
            mysql_cur = mysql_con.cursor()
            mysql_cur.execute("DELETE FROM password_keeper.password_info where link = %s",[website_link])
            mysql_con.commit()
            mysql_con.close()

            print(mysql_cur.rowcount, "record deleted.")

    ## update password
    def update_password(self,_email,_master_key):
        print("*********************************")
        print("UPDATE PASSWORD FOR A WEBSITE")
        print("*********************************")
        website_link = input("Enter the link or name of website to be deleted ")
        _is_present = validator_object.validate_link(website_link)
        if not _is_present:
            print("An entry for this link or name of website does not exists ")
            exit(1)
        else:
            curr_pass = input("Enter the current password ")
            decrypted_passcode = ""
            # mysql connection
            mysql_con = db_object.db_connector()
            mysql_cur = mysql_con.cursor()
            mysql_cur.execute(
                "select * from password_keeper.password_info p, password_keeper.user_info u where p.email = u.email and link = %s",[website_link])
            res = mysql_cur.fetchall()
            if res is None:
                print("No records found")
            else:
                for row in res:
                    key = encrypt_object.get_encryption_key(_master_key, row[3])
                    decrypted_passcode = decrypt_object.decrypt_password(row[2], key)
                if decrypted_passcode == curr_pass:
                    new_pass = input("Enter the new password ")
                    salt = bcrypt.gensalt()
                    key = encrypt_object.get_encryption_key(_master_key, salt)  # generating encryption key with master_key + salt

                    encrypted_passcode = encrypt_object.encrypt_password(new_pass, key)  # encrypting password with encryption key
                    mysql_cur.execute("UPDATE password_keeper.password_info SET passcode = %s, salt = %s WHERE link = %s AND email = %s",[encrypted_passcode,salt,website_link,_email])
                else:
                    print("The current password entered is wrong, hence cannot update the password")
                    exit(1)

                mysql_con.commit()
                mysql_con.close()