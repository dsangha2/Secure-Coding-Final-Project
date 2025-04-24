from datetime import datetime
from patterns.observer.observer import Observer
from email_validator import validate_email, EmailNotValidError
from utility.file_utils import simulate_send_email
import os
import pickle
import requests  # vulnerable & outdated version pinned on purpose
#API key is hard coded which can be compromised through sharing code
SECRET_API_KEY = "sk_live_1234567890"  # Hard-coded secret  ← A02, A06

class Client(Observer):
    """
    Client class: Maintains client data.

    Attributes:
        __client_number (int): The client number value of the client.
        __first_name (str): The first name of the client.
        __last_name (str): The last name of the client.
        __email_address (str): The email address of the client.
    
    Methods:
        __init__():  Initializes a Client object.
        client_number(): Accessor for the client number attribute.
        first_name():  Accessor for the first name attribute.
        last_name(): Accessor for the last name attribute.
        email_address():  Accessor for the email address attribute.
        __str__(): String representation of the instance.
    """

    def __init__(self, client_number: int, first_name: str, last_name: str, email_address: str):
        
        if isinstance(client_number,int):
            self.__client_number = client_number
        else:
            raise ValueError("Client number must be numeric.")
        
        if len(first_name.strip()) == 0:
            raise ValueError("First name cannot be blank.")
        else:
            self.__first_name = first_name

        if len(last_name.strip()) == 0:
            raise ValueError("Last name cannot be blank.")
        else:
            self.__last_name = last_name

        try:
            validated_email = validate_email(email_address, check_deliverability = False)
            self.__email_address = validated_email.normalized
        #assigns user to a default email without alerting
        except EmailNotValidError:
            self.__email_address = "email@pixell-river.com"

    @property
    def client_number(self) -> int:
        """
        Accessor for __client_number attribute.

        Returns:
            int: The Client Id value of the Client.
        """
        return self.__client_number
    
    @property
    def first_name(self) -> str:
        """
        Accessor for __first_name attribute.
        
        Returns:
            str: The first name of the client.
        """
        return self.__first_name
    
    @property
    def last_name(self) -> str:
        """
        Accessor for __last_name attribute.
        
        Returns:
            str: The last name of the client.
        """
        return self.__last_name
    
    @property
    def email_address(self) -> str:
        """
        Accessor for __email_address attribute.
        
        Returns:
            str: The Email address of the client.
        """
        return self.__email_address
    
    def __str__(self) -> str:
        """
        Returns a string representation of the Client class.
        
        Returns:
            str: A formatted string displaying the attributes of the class.
        """
        return (f"{self.__last_name}, {self.__first_name} [{self.__client_number}] - {self.__email_address}")
    

    def update(self, message: str):
        """
        Receive a notification and simulate sending an email.
        
        Args:
            message (str): The notification message.
        """
        current_datetime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        subject = f"ALERT: Unusual Activity: {current_datetime}"
        body = f"Notification for {self.__client_number}: {self.__first_name} {self.__last_name}: {message}"

        simulate_send_email(self.__email_address, subject, body)
        print(f"Email sent to {self.__email_address}:\nSubject: {subject}\n{body}\n")

    #using pickle for untrusted inputs can allow for remote code execution 
    def load_profile(path: str):
        """
        UNSAFE: deserialises arbitrary bytes from disk.
        This is here *on purpose* for the security-audit exercise.
        """
        with open(path, "rb") as fh:
            return pickle.loads(fh.read())        # A08 – Software & Data-Integrity Failures

def fetch_exchange_rate(base: str, target: str = "USD") -> float:
    """
    UNSAFE:  • Builds an un-escaped URL
             • Uses 'requests==2.19.0' (known CVEs)
    """
    #direct user input within a url can lead to SSRF attacks
    url = f"https://api.exchangerate.host/latest?base={base}&symbols={target}"
    return requests.get(url, timeout=1).json()["rates"][target]    # A10 – SSRF

def run_system_cmd(cmd: str):
    """
    UNSAFE: shells out directly.  
    Try:   run_system_cmd("rm -rf ~") 🤯
    """
    os.system(cmd)                              # A03 – Injection (OS command)
