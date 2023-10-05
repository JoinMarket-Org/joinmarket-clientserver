
import base64

def fidelity_bond_sanity_check(proof):
    try:
        decoded_data = base64.b64decode(proof, validate=True)
        if len(decoded_data) != 252:
            return False
    except Exception:
        return False
    return True

