#role based masking for sensitive visitor fields

def mask_id_number(id_number, role):
    if not id_number:
        return None

    if role == "admin":
        return id_number

    elif role == "manager":
        return "*" * (len(id_number) - 4) + id_number[-4:]
    else:
        return "********"


def mask_phone(phone, role):
    if not phone:
        return None
    
    if role == "admin":
        return phone
    else:
        return "*" * (len(phone) - 4) + phone[-4:]
