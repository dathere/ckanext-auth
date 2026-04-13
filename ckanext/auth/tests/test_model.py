from __future__ import annotations

from datetime import datetime as dt
from datetime import timezone as tz
from typing import cast
from urllib import parse

import pyotp
import pytest

import ckan.plugins.toolkit as tk

from ckanext.auth import config as auth_config
from ckanext.auth.exceptions import ReplayAttackError
from ckanext.auth.model import UserSecret

CODE_LENGTH = 6


@pytest.mark.usefixtures("with_plugins", "clean_db")
class TestUserSecretModel:
    def test_get_secret_for_user_missing(self, user):
        assert not UserSecret.get_for_user(user["name"])

    def test_create_for_user(self, user):
        secret = UserSecret.create_for_user(user["name"])

        assert secret.user_id == user["id"]
        assert secret.secret
        assert secret.last_access is None

    def test_get_secret_for_user(self, user):
        """The secret can be retrieved by user name or user ID."""
        secret = UserSecret.create_for_user(user["name"])

        assert UserSecret.get_for_user(user["name"]) == secret
        assert UserSecret.get_for_user(user["id"]) == secret

    def test_calling_create_again_rotates_the_secret(self, user):
        secret = UserSecret.create_for_user(user["name"])
        old_secret = secret.secret
        secret = UserSecret.create_for_user(user["name"])
        assert secret.secret != old_secret

    def test_create_for_missing_user(self):
        with pytest.raises(tk.ObjectNotFound):
            UserSecret.create_for_user("missing")

    def test_get_code(self, user):
        secret = UserSecret.create_for_user(user["name"])

        code = secret.get_code()

        assert code
        assert len(code) == CODE_LENGTH
        assert code.isdigit()

    def test_check_code(self, user):
        secret = UserSecret.create_for_user(user["name"])
        code = secret.get_code()

        assert secret.check_code(code)
        assert not secret.check_code("invalid")

    def test_check_code_updated_last_access(self, user):
        secret = UserSecret.create_for_user(user["name"])
        code = secret.get_code()

        assert not secret.last_access
        secret.check_code(code)
        assert secret.last_access

    def test_check_code_verify_only_once(self, user):
        """We use it for test verify on the user 2MA configure page."""
        secret = UserSecret.create_for_user(user["name"])
        code = secret.get_code()

        assert not secret.last_access
        assert secret.check_code(code, verify_only=True)
        assert not secret.last_access

    def test_provisioning_uri(self, user):
        secret = UserSecret.create_for_user(user["name"])

        assert secret.provisioning_uri
        assert "otpauth://totp" in secret.provisioning_uri
        assert user["name"] in secret.provisioning_uri
        assert cast(str, secret.secret) in secret.provisioning_uri
        assert parse.quote_plus(tk.config["ckan.site_url"]) in secret.provisioning_uri


@pytest.mark.usefixtures("with_plugins", "clean_db")
@pytest.mark.ckan_config(auth_config.CONF_2FA_METHOD, auth_config.METHOD_AUTHENTICATOR)
class TestTOTPReplayDetection:
    def test_first_login_no_replay(self, user):
        """First login should succeed without replay detection."""
        secret = UserSecret.create_for_user(user["name"])
        totp = pyotp.TOTP(cast(str, secret.secret))
        code = totp.now()

        assert secret.last_access is None
        assert secret.check_code(code)
        assert secret.last_access is not None

    def test_replay_same_code_raises_error(self, user):
        """Using the same code twice should raise ReplayAttackError."""
        secret = UserSecret.create_for_user(user["name"])
        totp = pyotp.TOTP(cast(str, secret.secret))
        code = totp.now()

        assert secret.check_code(code)

        with pytest.raises(ReplayAttackError):
            secret.check_code(code)

    def test_new_counter_succeeds_after_last_access(self, user):
        """A code from a future counter should not be flagged as replay."""
        secret = UserSecret.create_for_user(user["name"])
        totp = pyotp.TOTP(cast(str, secret.secret))

        # Simulate a past login by setting last_access to a past time
        past_time = dt(2020, 1, 1, 0, 0, 0, tzinfo=tz.utc)
        secret.last_access = past_time

        code = totp.now()
        assert secret.check_code(code)

    def test_verify_only_then_full_check_succeeds(self, user):
        """A verify_only check followed by a full check with the same code
        should not raise ReplayAttackError (mirrors the AJAX pre-validation
        followed by form submission login flow)."""
        secret = UserSecret.create_for_user(user["name"])
        totp = pyotp.TOTP(cast(str, secret.secret))
        code = totp.now()

        # First call: AJAX pre-validation (verify_only=True)
        assert secret.check_code(code, verify_only=True)
        assert secret.last_access is None

        # Second call: actual form-based login (verify_only=False)
        assert secret.check_code(code)
        assert secret.last_access is not None

    def test_naive_last_access_treated_as_utc(self, user):
        """A naive last_access datetime should be treated as UTC and not
        cause false positive replay detection."""
        secret = UserSecret.create_for_user(user["name"])
        totp = pyotp.TOTP(cast(str, secret.secret))

        # Set last_access as a naive datetime (as the DB might return)
        past_time = dt(2020, 1, 1, 0, 0, 0)  # naive, no tzinfo
        secret.last_access = past_time

        code = totp.now()
        assert secret.check_code(code)
