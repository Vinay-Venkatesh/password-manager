import string
import random
import base64
from getpass import getpass
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import uuid
import mysql.connector
import re
import bcrypt

def db_connector():
    mydb_connector = mysql.connector.connect(
        host="localhost",
        user="root",
        password="root",
        database="password_keeper",
        auth_plugin='mysql_native_password'
    )
    return mydb_connector

## Generate encryption key
def get_encryption_key(master_password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=1000000,
        backend=default_backend()
    )

    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return key

## Password encryption
def encrypt_password(password, key):
    fernet = Fernet(key)
    encrypted_password = fernet.encrypt(password.encode())
    return encrypted_password

## Password decryption
def decrypt_password(encrypted_password, key):
    fernet = Fernet(key)
    decrypted_password = fernet.decrypt(encrypted_password).decode()
    return decrypted_password

## To generate random passwords
def generate_randam_password(length=12):
    char_pool = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(char_pool) for char in range(length))
    return password

def get_uuid():
    return uuid.uuid4()

def validate_inputs(_email,_password):

    _email_present = validate_email(_email)
    if _email_present:
        print("email is present")
        if validate_master_password(_email,_password):
            return True
        else:
            return False
    else:
        print("email {0} is not present, signup if new user".format(_email))
        exit(1)


def validate_email(_email):
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
    mysql_con = db_connector()
    mysql_cur = mysql_con.cursor()
    mysql_cur.execute("select uuid from password_keeper.user_info where email = %s", [_email])
    _present = mysql_cur.fetchone()
    mysql_con.close()
    if _present:
        return True
    else:
        return False

def validate_master_password(_email,_password):
    # Checks if the password matches
    # returns true or false

    # mysql connection
    mysql_con = db_connector()
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

# def generate_secure_password(_password):
#     salt = os.urandom(16)
#     iterations = 100_000
#     hash_value = hashlib.pbkdf2_hmac(
#         'sha256',
#         _password.encode('utf-8'),
#         salt,
#         iterations
#     )
#     password_hash = salt + hash_value
#     return password_hash

def generate_secure_password(_password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(_password.encode('utf-8'), salt)
    return hashed

## persist new user details
def user_signup(_email, _password):
    if not validate_email(_email):

        uuid = str(get_uuid())
        password_hash = generate_secure_password(_password)

        # Split hash into components
        # salt, key = password_hash[:16], password_hash[16:]
        # hash_algo = "sha256"
        # iterations = 100_000

        # mysql connection
        mysql_con = db_connector()
        mysql_cur = mysql_con.cursor()
        sql = "INSERT INTO password_keeper.user_info (uuid, email, master_key) VALUES (%s, %s, %s)"
        val = (uuid,_email,password_hash)

        mysql_cur.execute(sql, val)
        mysql_con.commit()

        print(mysql_cur.rowcount, "record inserted.")
    else:
        print("user with this email is already present , login with the user credentials..")
        exit(1)

def validate_link(_passlink):
    # mysql connection
    mysql_con = db_connector()
    mysql_cur = mysql_con.cursor()
    mysql_cur.execute("select link from password_keeper.password_info where link = %s", [_passlink])
    _present = mysql_cur.fetchone()
    mysql_con.close()
    if _present:
        return True
    else:
        return False

#### New password entry.
def add_password(_email, _master_key):
    print("*********************************")
    print("ADD NEW PASSWORD FOR A WEBSITE")
    print("*********************************")
    website_link = input("Enter the link or name of website which uses this password ")
    _is_present = validate_link(website_link)
    if _is_present:
        print("An entry for this link or name of website is already present ")
        exit(1)
    else:
        passcode = getpass("Enter the password for above link or name of website ")
        salt = bcrypt.gensalt()
        key = get_encryption_key(_master_key, salt) # generating encryption key with master_key + salt

        encrypted_passcode = encrypt_password(passcode, key) # encrypting password with encryption key

        # mysql connection
        mysql_con = db_connector()
        mysql_cur = mysql_con.cursor()
        sql = "INSERT INTO password_keeper.password_info (email, link, passcode, salt) VALUES (%s, %s, %s, %s)"
        val = (_email, website_link, encrypted_passcode, salt)

        mysql_cur.execute(sql, val)
        mysql_con.commit()

        print(mysql_cur.rowcount, "record inserted.")

def list_passwords(_email, _master_key):
    print("******************************************************")
    print("LIST OF PASSWORDS FOR THE USER - {0} ".format(_email))
    print("******************************************************")

    # mysql connection
    mysql_con = db_connector()
    mysql_cur = mysql_con.cursor()
    mysql_cur.execute("select * from password_keeper.password_info where email = %s",[_email])
    res = mysql_cur.fetchall()
    if res is None:
        print("No records found")
    else:
        for row in res:
            key = get_encryption_key(_master_key, row[3])
            decrypted_passcode = decrypt_password(row[2], key)
            print("Link - " + row[1])
            print("Password - " + decrypted_passcode)

    mysql_con.close()

## delete password
def delete_password():
    print("*********************************")
    print("DELETE PASSWORD FOR A WEBSITE")
    print("*********************************")
    website_link = input("Enter the link or name of website to be deleted ")
    _is_present = validate_link(website_link)
    if not _is_present:
        print("An entry for this link or name of website does not exists")
        exit(1)
    else:
        # mysql connection
        mysql_con = db_connector()
        mysql_cur = mysql_con.cursor()
        mysql_cur.execute("DELETE FROM password_keeper.password_info where link = %s",[website_link])
        mysql_con.commit()
        mysql_con.close()

        print(mysql_cur.rowcount, "record deleted.")

## update password
def update_password(_email,_master_key):
    print("*********************************")
    print("UPDATE PASSWORD FOR A WEBSITE")
    print("*********************************")
    website_link = input("Enter the link or name of website to be deleted ")
    _is_present = validate_link(website_link)
    if not _is_present:
        print("An entry for this link or name of website does not exists ")
        exit(1)
    else:
        curr_pass = input("Enter the current password ")
        decrypted_passcode = ""
        # mysql connection
        mysql_con = db_connector()
        mysql_cur = mysql_con.cursor()
        mysql_cur.execute(
            "select * from password_keeper.password_info p, password_keeper.user_info u where p.email = u.email and link = %s",[website_link])
        res = mysql_cur.fetchall()
        if res is None:
            print("No records found")
        else:
            for row in res:
                key = get_encryption_key(_master_key, row[3])
                decrypted_passcode = decrypt_password(row[2], key)
            if decrypted_passcode == curr_pass:
                new_pass = input("Enter the new password ")
                salt = bcrypt.gensalt()
                key = get_encryption_key(_master_key, salt)  # generating encryption key with master_key + salt

                encrypted_passcode = encrypt_password(new_pass, key)  # encrypting password with encryption key
                mysql_cur.execute("UPDATE password_keeper.password_info SET passcode = %s, salt = %s WHERE link = %s AND email = %s",[encrypted_passcode,salt,website_link,_email])
            else:
                print("The current password entered is wrong, hence cannot update the password")
                exit(1)

            mysql_con.commit()
            mysql_con.close()


def main():
    # global variables
    _is_valid = False
    _email = ""
    _master_key = ""

    print("*******************************")
    print("1. SignUp - For new user ")
    print("2. Login - For existing user")
    print("*******************************")
    login_opts = str(input("Enter one of the above options "))
    if login_opts == "1":
        user_email = input("Enter the new email id ")
        _master_key  = getpass("Enter the new master password ")
        user_signup(user_email,_master_key)
    elif login_opts == "2":
        _email = input("Enter the email id ")
        master_password = getpass("Enter the master password ")
        _is_valid = validate_inputs(_email, master_password)
        print("valid - {0}".format(_is_valid))
    else:
        print("Wrong input")
        exit(1)

    if _is_valid:
        print("********************************************")
        print("Main Menu")
        print("********************************************")
        print("1. View passwords")
        print("2. Add new password")
        print("3. Delete password")
        print("4. Update existing password")
        _options = str(input("Enter one of the above option "))

        if _options == "1":
            list_passwords(_email, _master_key)
        elif _options == "2":
            add_password(_email, _master_key)
        elif _options == "3":
            delete_password()
        elif _options == "4":
            update_password(_email,_master_key)
        else:
            print("wrong input")
            exit(1)

main()

