from user_operations import UserMgmt, PasswordMgmt
from validator import Validator

def main():
    # global variables
    _is_valid = False
    _email = ""
    _master_key = ""

    # Instance of classes
    user_object = UserMgmt()
    password_object = PasswordMgmt()
    validator_object = Validator()

    print("*******************************")
    print("1. SignUp - For new user ")
    print("2. Login - For existing user")
    print("*******************************")
    login_opts = str(input("Enter one of the above options "))
    if login_opts == "1":
        user_email = input("Enter the new email id ")
        _master_key  = input("Enter the new master password ")
        user_object.user_signup(user_email,_master_key)
    elif login_opts == "2":
        _email = input("Enter the email id ")
        master_password = input("Enter the master password ")
        _is_valid = validator_object.validate_inputs(_email, master_password)
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
            password_object.list_passwords(_email, _master_key)
        elif _options == "2":
            password_object.add_password(_email, _master_key)
        elif _options == "3":
            password_object.delete_password()
        elif _options == "4":
            password_object.update_password(_email,_master_key)
        else:
            print("wrong input")
            exit(1)

if __name__ == "__main__":
    main()

