import base64
import secrets
from cryptography.hazmat.primitives.twofactor import totp as crypto_totp
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from oslo_utils import timeutils

SECRETS = "HUSLDQ5D5CTST3JNJ6VHACTSTRVWZ7MWMHVC4KYUU7LCW6RRFMWQ"

PASSCODE_LENGTH = 6
PASSCODE_TIME_PERIOD = 30

def utf8len(s):
  return len(s.encode('utf-8'))

def _gen_secrets():
  blob = base64.b32encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
  return blob

def _generate_totp_passcodes(secret, included_previous_windows=0):
    """Generate TOTP passcode.
    :param bytes secret: A base32 encoded secret for the TOTP authentication
    :returns: totp passcode as bytes
    """
    if isinstance(secret, str):
        # NOTE(dstanek): since this may be coming from the JSON stored in the
        # database it may be UTF-8 encoded
        secret = secret.encode('utf-8')

    # NOTE(nonameentername): cryptography takes a non base32 encoded value for
    # TOTP. Add the correct padding to be able to base32 decode
    while len(secret) % 8 != 0:
        secret = secret + b'='

    decoded = base64.b32decode(secret)
    # NOTE(lhinds) This is marked as #nosec since bandit will see SHA1
    # which is marked as insecure. In this instance however, keystone uses
    # HMAC-SHA1 when generating the TOTP, which is currently not insecure but
    # will still trigger when scanned by bandit.
    totp = crypto_totp.TOTP(
        decoded, PASSCODE_LENGTH, hashes.SHA1(), PASSCODE_TIME_PERIOD,  # nosec
        backend=default_backend())

    passcode_ts = timeutils.utcnow_ts(microsecond=True)
    passcodes = [totp.generate(passcode_ts).decode('utf-8')]

    for i in range(included_previous_windows):
        # NOTE(adriant): we move back the timestamp the number of seconds in
        # PASSCODE_TIME_PERIOD each time.
        passcode_ts -= PASSCODE_TIME_PERIOD
        passcodes.append(totp.generate(passcode_ts).decode('utf-8'))
    return passcodes

# print(_generate_totp_passcodes(SECRETS))
# print(_gen_secrets())