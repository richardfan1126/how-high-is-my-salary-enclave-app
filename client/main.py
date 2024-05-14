import configparser
import base64
import random
import string
import json

import requests
import inquirer
from termcolor import colored

from attestation_doc_helper import verify_attestation_doc, get_pub_key, get_user_data
from encryption_helper import generate_session_key, encrypt, decrypt

config = configparser.ConfigParser()
config.read("config.ini")

PCR0 = config['default']['PCR0']
ENCLAVE_ENDPOINT = config['default']['EnclaveEndpoint']

def generate_nonce():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k = 8))

def get_attestation(nonce):
    r = requests.post(f"http://{ENCLAVE_ENDPOINT}/get-attestation", json = {
        "nonce": nonce
    })

    return r.json()['attestation_doc']

def send_request(url, public_key, encrypted_payload, encrypted_nonce):
    r = requests.post(f"http://{ENCLAVE_ENDPOINT}/{url}", json = {
        "public_key": public_key,
        "encrypted_payload": encrypted_payload,
        "encrypted_nonce": encrypted_nonce
    })

    return r.json()['attestation_doc']

def clear_records():
    requests.post(f"http://{ENCLAVE_ENDPOINT}/clear")

def main():
    menu_question = [
        inquirer.List(
            "option",
            message = "Please choose your action",
            choices=['See my salary position', 'Add my salary', 'Clear records', 'Exit']
        ),
    ]

    # Get the root cert PEM content
    with open('root.pem', 'r') as file:
        root_cert_pem = file.read()

    #############################################
    # Step 1: Verify enclave and get public key #
    #############################################
    pcrs = {
        0: PCR0
    }

    nonce = generate_nonce()
    attestation_doc_b64 = get_attestation(nonce)
    attestation_doc = base64.b64decode(attestation_doc_b64)
    
    try:
        verify_attestation_doc(attestation_doc, pcrs = pcrs, root_cert_pem = root_cert_pem, expected_nonce = nonce)
    except:
        print("\n\n❌ " + colored("Cannot validate attestation, exit now!!", "red", attrs=["bold"]) + "\n\n")
        exit()

    print("\n\n✅ " + colored("Enclave attestation verified: ", "green") + colored(f"{PCR0}", "green", attrs=["bold"]) + "\n")

    enclave_public_key = get_pub_key(attestation_doc)
    print("\n✅ " + colored("Encryption key obtained from enclave", "green") + "\n\n")

    while True:
        answers = inquirer.prompt(menu_question)
        option = answers['option']

        if option == "Add my salary":
            #########################################
            # Encrypt my salary and send to enclave #
            #########################################
            # Input salary
            questions = [
                inquirer.Text("salary", message="What is your monthly salary?"),
            ]
            answers = inquirer.prompt(questions)
            salary = answers['salary']

            # Generate session key
            session_key, my_public_key_bytes = generate_session_key(enclave_public_key)
            my_public_key_b64 = base64.b64encode(my_public_key_bytes).decode()

            # Encrypt my salary using public key in attestation document
            ciphertext_bundle = encrypt(session_key, salary)

            # Generate encrypted nonce for enclave to put into attestation document
            nonce = generate_nonce()
            encrypted_nonce = encrypt(session_key, nonce)

            # Send my encrypted salary to the enclave
            response_attestation_b64 = send_request("add", my_public_key_b64, ciphertext_bundle, encrypted_nonce)

            response_attestation = base64.b64decode(response_attestation_b64)
            verify_attestation_doc(response_attestation, pcrs = pcrs, root_cert_pem = root_cert_pem, expected_nonce = nonce)
            encrypted_uuid = get_user_data(response_attestation)

            uuid = decrypt(encrypted_uuid, session_key)

            print("\n\n" + colored("This is your unique entry ID: ", "light_blue") + colored(f"{uuid}", "light_blue", attrs=["bold", "underline"]) + "\n\n")
        
        elif option == "See my salary position":
            ######################################
            # Use UUID to see my salary position #
            ######################################
            # Input entry UUID
            questions = [
                inquirer.Text("uuid", message="What is your entry UUID?"),
            ]
            answers = inquirer.prompt(questions)
            uuid = answers['uuid']

            # Generate session key
            session_key, my_public_key_bytes = generate_session_key(enclave_public_key)
            my_public_key_b64 = base64.b64encode(my_public_key_bytes).decode()

            # Encrypt the entry UUID using session key
            ciphertext_bundle = encrypt(session_key, uuid)
            
            # Encrypt the nonce for enclave to put into attestation document
            nonce = generate_nonce()
            encrypted_nonce = encrypt(session_key, nonce)

            # Send the encrypted UUID to the enclave
            response_attestation_b64 = send_request("get-position", my_public_key_b64, ciphertext_bundle, encrypted_nonce)

            response_attestation = base64.b64decode(response_attestation_b64)
            verify_attestation_doc(response_attestation, pcrs = pcrs, root_cert_pem = root_cert_pem, expected_nonce = nonce)
            encrypted_position_and_total_json = get_user_data(response_attestation)

            position_and_total_json = decrypt(encrypted_position_and_total_json, session_key)

            position_and_total = json.loads(position_and_total_json)

            print("\n\n" + colored("Your salary is ranked ", "light_blue") + colored(f"{position_and_total['position']}/{position_and_total['total']}", "light_blue", attrs=["bold"]) + "\n\n")
            
        elif option == "Clear records":
            clear_records()

        elif option == "Exit":
            break

if __name__ == "__main__":
    main()
