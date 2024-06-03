import requests


def get_account_info(server_ip: str, token: str):
    response = requests.get(
        f"http://{server_ip}/basic_info", headers={"Authorization": f"bearer {token}"}
    )
    if response.status_code != 200:
        return None
    return response.json()


def get_balance(server_ip: str, token: str, iban: str):
    response = requests.get(
        f"http://{server_ip}/balance/{iban}",
        headers={"Authorization": f"bearer {token}"},
    )
    if response.status_code != 200:
        return None
    return response.json()


def get_movements(server_ip: str, token: str, iban: str):
    response = requests.get(
        f"http://{server_ip}/movements/{iban}",
        headers={"Authorization": f"bearer {token}"},
    )
    if response.status_code != 200:
        return None
    return response.json()


def get_loans(server_ip: str, token: str):
    response = requests.get(
        f"http://{server_ip}/loans", headers={"Authorization": f"bearer {token}"}
    )
    if response.status_code != 200:
        return None
    return response.json()


def post_transfer(
    server_ip: str, token: str, from_iban: str, to_iban: str, amount: float
):
    response = requests.post(
        f"http://{server_ip}/transfer",
        headers={"Authorization": f"bearer {token}"},
        data={"from": from_iban, "to": to_iban, "amount": amount},
    )
    if response.status_code != 200:
        return True
    return False
