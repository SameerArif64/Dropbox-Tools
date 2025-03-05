from typing import Optional, Union
import dropbox
from dropbox.exceptions import AuthError
import requests
from advance_selenium_chrome import AdvanceSeleniumChrome
from json_as_dict import JsonAsDict
import time


class DropboxTools:
    def __init__(self, app_name:str, dropbox_auth: Union[dict, str], user_data_dir: str = "C:\\ChromeRemoteDebug\\Headless"):
        self.app_name = app_name
        self.user_data_dir = user_data_dir
        self.dropbox_auth_json = None

        if isinstance(dropbox_auth, dict):
            self.auth_json = dropbox_auth
        elif isinstance(dropbox_auth, str) and dropbox_auth.endswith('.json'):
            self.dropbox_auth_json = JsonAsDict('dropbox_auth.json', lock=False)
            self.auth_json = self.dropbox_auth_json.get(app_name, {})
        else:
            raise Exception("'dropbox_auth' can be either file_path or dict_data.")

        if not self.auth_json:
            self.auth_json['email'] = input("Enter Account Email: ")
            self.auth_json['password'] = input("Enter Account Password: ")
            self.auth_json["app_key"] = input("Enter App Key: ")
            self.auth_json["app_secret"] = input("Enter App Secret: ")
            self.auth_json['access_token'] = None
            if self.dropbox_auth_json is not None:
                self.dropbox_auth_json[self.app_name] = self.auth_json

        self.email = self.auth_json['email']
        self.password = self.auth_json['password']
        self.app_key = self.auth_json['app_key']
        self.app_secret = self.auth_json['app_secret']
        self.access_token = self.auth_json['access_token']

        if not self.access_token:
            self.renew_access_token()
        

    def renew_access_token(self):
        self.auth_json['access_token'] = self.get_refresh_token().get('access_token')
        self.access_token = self.auth_json['access_token']
        if self.dropbox_auth_json is not None:
            self.dropbox_auth_json[self.app_name] = self.auth_json

    def get_auth_code(self):
        driver = AdvanceSeleniumChrome(headless=True, user_data_dir=self.user_data_dir)

        driver.get(f'https://www.dropbox.com/oauth2/authorize?client_id={self.app_key}&token_access_type=offline&response_type=code')

        # Deny cookies
        if iframe := driver.wait_for_element("ccpa-iframe", "id", timeout=2, suppress=True):
            driver.switch_to.frame(iframe)
            driver.click_element("decline_cookies_button", 'id')
            driver.switch_to.default_content()

        # input('Log in or sign up to Dropbox' in driver.page_source)
        # print(driver.page_source)
        while 'Before you connect this app...' not in driver.page_source and 'Log in or sign up to Dropbox' not in driver.page_source:
            time.sleep(1)

        # input('Log in or sign up to Dropbox' in driver.page_source)
        if 'Log in or sign up to Dropbox' in driver.page_source:
            # Email and Password
            driver.send_keys_to_element("susi_email", self.email, "name")
            driver.click_element("email-submit-button", "class name")

            driver.send_keys_to_element("login_password", self.password, "name")
            driver.click_element('[data-testid="login-form-submit-button"]', 'css selector')

            # Authenticate using 6-digit code
            while 'Before you connect this app...' not in driver.page_source and 'Additional authentication is required' not in driver.page_source:
                time.sleep(1)
            if 'Additional authentication is required' in driver.page_source:
                code = input("Type six digit code from email here: ")
                driver.send_keys_to_element("code", code, "name")
                driver.click_element('[data-testid="auth_checkbox"]', 'css selector', immediate=True)
                driver.click_element('[data-uxa-log="2fa_form_submit_button"]', 'css selector')
                while 'Before you connect this app...' not in driver.page_source:
                    time.sleep(1)
            
        # Connect this app
        while 'Before you connect this app...' in driver.page_source:
            driver.click_element('warning-button-continue', 'id')
            time.sleep(1)

        # Permission
        while 'would like to:' in driver.page_source:
            driver.click_element("auth-button-allow", 'class name')
            time.sleep(1)

        # Authetication Code
        input_field = driver.wait_for_element("auth-code-input", 'id')
        auth_code = input_field.get_attribute("value")
        
        return auth_code

    def get_refresh_token(self):
        url = "https://api.dropbox.com/oauth2/token"
        data = {
            "grant_type": "authorization_code",
            "code": self.get_auth_code(),
            "client_id": self.app_key,
            "client_secret": self.app_secret
        }
        response = requests.post(url, data=data)
        data = response.json()

        if error := data.get('error'):
            if error == 'invalid_grant':
                self.get_refresh_token()
            else:
                raise Exception(data)

        return data

    def handle_auth_error(self, func, *args, **kwargs):
        """
        Helper function to handle AuthError, refresh token, and retry the operation.
        """
        try:
            return func(*args, **kwargs)
        except AuthError as e:
            if e.error.is_expired_access_token():
                print("Access token expired. Refreshing token...")
                self.renew_access_token()
                # Retry the operation after refreshing the token
                return func(*args, **kwargs)
            else:
                print(f"Authentication error: {e}")
                raise e
        except Exception as e:
            print(f"Error: {e}")
            raise e

    def upload(self, dropbox_destination: str, local_file_path: Optional[str] = None, file_data: Optional[str] = None):
        # Use a variable to store the final file data (if it's not passed in, load it from a file)
        def upload_operation(file_data):
            dbx = dropbox.Dropbox(self.access_token)

            # If file_data is None, we will read the file from local_file_path
            if file_data is None:
                if local_file_path:
                    with open(local_file_path, "rb") as file:
                        file_data = file.read()
                else:
                    raise ValueError("No file data or local file path provided.")

            if isinstance(file_data, str):
                file_data = file_data.encode('utf-8')

            # Proceed with the upload once file_data is correctly assigned
            dbx.files_upload(file_data, dropbox_destination, mode=dropbox.files.WriteMode("overwrite"))
            print(f"File uploaded to {dropbox_destination}")

        # Handle any AuthError and retry if necessary
        return self.handle_auth_error(upload_operation, file_data)

    def read(self, dropbox_file_path: str):
        def read_operation():
            dbx = dropbox.Dropbox(self.access_token)
            _, res = dbx.files_download(dropbox_file_path)
            content = res.content.decode("utf-8")
            # print(f"File content:\n{content}")
            return content
        
        # Handle any AuthError and retry if necessary
        return self.handle_auth_error(read_operation)

    def list_files(self, folder_path: str = ""):
        def list_files_operation():
            dbx = dropbox.Dropbox(self.access_token)
            files = dbx.files_list_folder(folder_path).entries
            file_names = [file.name for file in files]
            print(f"Files in '{self.app_name}/{folder_path}': {file_names}")
            return file_names
        
        # Handle any AuthError and retry if necessary
        return self.handle_auth_error(list_files_operation)