import datetime
import os
from base64 import b64encode

import jwt

from jmbase.support import bintohex


class InvalidScopeError(Exception):
    pass


class ExpiredSignatureError(jwt.exceptions.ExpiredSignatureError):
    pass


def get_random_key(size: int = 16) -> str:
    """Create a random key has an hexadecimal string."""
    return bintohex(os.urandom(size))


def b64str(s: str) -> str:
    return b64encode(s.encode()).decode()

class JMTokenAuthority:
    """Manage authorization tokens."""

    SESSION_VALIDITY = {
        "access": datetime.timedelta(minutes=30),
        "refresh": datetime.timedelta(hours=4),
    }
    SIGNATURE_ALGORITHM = "HS256"

    def __init__(self, *wallet_names: str):
        self.signature_key = {
            "access": get_random_key(),
            "refresh": get_random_key(),
        }
        self._scope = {"walletrpc"}
        for wallet_name in wallet_names:
            self.add_to_scope(wallet_name)

    def verify(self, token: str, *, token_type: str = "access"):
        """Verify JWT token.

        Token must have a valid signature and its scope must contain both scopes in
        arguments and wallet_name property.
        """
        try:
            claims = jwt.decode(
                token,
                self.signature_key[token_type],
                algorithms=self.SIGNATURE_ALGORITHM,
                leeway=10,
            )
        except jwt.exceptions.ExpiredSignatureError:
            raise ExpiredSignatureError

        token_claims = set(claims.get("scope", []).split())
        if not self._scope <= token_claims:
            raise InvalidScopeError

    def add_to_scope(self, *args: str, encoded: bool = True):
        for arg in args:
            self._scope.add(b64str(arg) if encoded else arg)

    def discard_from_scope(self, *args: str, encoded: bool = True):
        for arg in args:
            self._scope.discard(b64str(arg) if encoded else arg)

    @property
    def scope(self):
        return " ".join(self._scope)

    def _issue(self, token_type: str) -> str:
        return jwt.encode(
            {
                "exp": datetime.datetime.utcnow() + self.SESSION_VALIDITY[token_type],
                "scope": self.scope,
            },
            self.signature_key[token_type],
            algorithm=self.SIGNATURE_ALGORITHM,
        )

    def issue(self) -> dict:
        """Issue a new access and refresh token.
        Previously issued refresh token is invalidated.
        """
        self.signature_key["refresh"] = get_random_key()
        return {
            "token": self._issue("access"),
            "token_type": "bearer",
            "expires_in": int(self.SESSION_VALIDITY["access"].total_seconds()),
            "scope": self.scope,
            "refresh_token": self._issue("refresh"),
        }

    def reset(self):
        """Invalidate all previously issued tokens by creating new signature keys."""
        self.signature_key = {
            "access": get_random_key(),
            "refresh": get_random_key(),
        }
