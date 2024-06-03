import PyKCS11
import sys

def load_pkcs11_lib():
    lib = "/usr/local/lib/libpteidpkcs11.so"
    pkcs11 = PyKCS11.PyKCS11Lib()
    pkcs11.load(lib)
    return pkcs11


def sign_message(message):
    pkcs11 = load_pkcs11_lib()

    try:
        slots = pkcs11.getSlotList(tokenPresent=True)
        if slots == []:
            return 1, None

        slot = slots[0]
        session = pkcs11.openSession(slot)
        mechanism = PyKCS11.Mechanism(PyKCS11.CKM_SHA1_RSA_PKCS, None)

        certificate_attr = session.findObjects(
            [
                (PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE),
                (PyKCS11.CKA_LABEL, "CITIZEN AUTHENTICATION CERTIFICATE"),
            ]
        )[0]

        cert = bytes(certificate_attr.to_dict()["CKA_VALUE"])
        private_key = session.findObjects(
            [
                (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
                (PyKCS11.CKA_LABEL, "CITIZEN AUTHENTICATION KEY"),
            ]
        )[0]

        text = bytes(message, sys.getdefaultencoding())
        signature = bytes(session.sign(private_key, text, mechanism))  # sign

        signature_str = signature.hex()
        return signature_str, cert.hex()
    except Exception:
        return None, None