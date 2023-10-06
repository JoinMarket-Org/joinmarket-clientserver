"""test auth module."""

import copy
import datetime

import jwt
import pytest

from jmclient.auth import (
    ExpiredSignatureError,
    InvalidScopeError,
    JMTokenAuthority,
    b64str,
)


class TestJMTokenAuthority:
    wallet_name = "dummywallet"
    token_auth = JMTokenAuthority(wallet_name)

    access_sig = copy.copy(token_auth.signature_key["access"])
    refresh_sig = copy.copy(token_auth.signature_key["refresh"])

    validity = datetime.timedelta(hours=1)
    scope = f"walletrpc {b64str(wallet_name)}"

    @pytest.mark.parametrize(
        "sig, token_type", [(access_sig, "access"), (refresh_sig, "refresh")]
    )
    def test_verify_valid(self, sig, token_type):
        token = jwt.encode(
            {"exp": datetime.datetime.utcnow() + self.validity, "scope": self.scope},
            sig,
            algorithm=self.token_auth.SIGNATURE_ALGORITHM,
        )

        try:
            self.token_auth.verify(token, token_type=token_type)
        except Exception as e:
            print(e)
            pytest.fail("Token verification failed, token is valid.")

    def test_verify_expired(self):
        token = jwt.encode(
            {"exp": datetime.datetime.utcnow() - self.validity, "scope": self.scope},
            self.access_sig,
            algorithm=self.token_auth.SIGNATURE_ALGORITHM,
        )

        with pytest.raises(ExpiredSignatureError):
            self.token_auth.verify(token)

    def test_verify_non_scoped(self):
        token = jwt.encode(
            {"exp": datetime.datetime.utcnow() + self.validity, "scope": "wrong"},
            self.access_sig,
            algorithm=self.token_auth.SIGNATURE_ALGORITHM,
        )

        with pytest.raises(InvalidScopeError):
            self.token_auth.verify(token)

    def test_issue(self):
        def scope_equals(scope):
            return set(scope.split(" ")) == set(self.scope.split(" "))

        token_response = self.token_auth.issue()

        assert token_response.pop("expires_in") == int(
            self.token_auth.SESSION_VALIDITY["access"].total_seconds()
        )
        assert token_response.pop("token_type") == "bearer"
        assert scope_equals(token_response.pop("scope"))

        try:
            for k, v in token_response.items():
                claims = jwt.decode(
                    v,
                    self.token_auth.signature_key["refresh"]
                    if k == "refresh_token"
                    else self.token_auth.signature_key["access"],
                    algorithms=self.token_auth.SIGNATURE_ALGORITHM,
                )
                assert scope_equals(claims.get("scope"))
            assert self.token_auth.signature_key["refresh"] != self.refresh_sig
        except jwt.exceptions.InvalidTokenError:
            pytest.fail("An invalid token was issued.")

    def test_scope_operation(self):
        assert "walletrpc" in self.token_auth._scope
        assert b64str(self.wallet_name) in self.token_auth._scope

        scope = copy.copy(self.token_auth._scope)
        s = "new_wallet"

        self.token_auth.add_to_scope(s)
        assert scope < self.token_auth._scope
        assert b64str(s) in self.token_auth._scope

        self.token_auth.discard_from_scope(s)
        self.token_auth.discard_from_scope("walletrpc", encoded=False)
        assert scope > self.token_auth._scope
        assert b64str(s) not in self.token_auth._scope
