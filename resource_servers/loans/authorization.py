# Basic authorization based on the information in the JWT
def is_authorized(user_info: dict , my_id: int, endpoint: str):
    try:
        if my_id in user_info.get("access_whitelist"):
            return True
        return False
    except:
        return False