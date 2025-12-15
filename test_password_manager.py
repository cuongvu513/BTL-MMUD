import pytest
from json.decoder import JSONDecodeError

from password_manager import Keychain
from util import decode_bytes, json_str_to_dict

MASTER_PASSWORD = "password"

TEST_ENTRIES = {
    "admin1": "password1",
    "admin2": "password2",
    "admin3": "password3"
}


def create_filled_keychain():
    kc = Keychain.new(MASTER_PASSWORD)
    for domain, pwd in TEST_ENTRIES.items():
        kc.set(domain, pwd)
    return kc


class TestKeychainBasic:
    def test_create_keychain(self):
        kc = Keychain.new(MASTER_PASSWORD)
        assert kc is not None

    def test_single_set_get(self):
        kc = Keychain.new(MASTER_PASSWORD)
        kc.set("example.com", "secret")
        assert kc.get("example.com") == "secret"

    def test_multiple_entries(self):
        kc = create_filled_keychain()
        for domain, pwd in TEST_ENTRIES.items():
            assert kc.get(domain) == pwd

    def test_missing_entry_returns_none(self):
        kc = create_filled_keychain()
        assert kc.get("unknown.com") is None

    def test_remove_entry(self):
        kc = create_filled_keychain()
        assert kc.remove("admin1") is True
        assert kc.get("admin1") is None

    def test_remove_non_existing(self):
        kc = create_filled_keychain()
        assert kc.remove("ghost") is False


class TestSerialization:
    def test_dump_and_load(self):
        kc = create_filled_keychain()
        dump, checksum = kc.dump()
        restored = Keychain.load(MASTER_PASSWORD, dump, checksum)

        for domain, pwd in TEST_ENTRIES.items():
            assert restored.get(domain) == pwd

        try:
            json_str_to_dict(dump)
        except JSONDecodeError:
            pytest.fail("Dump output is not valid JSON")

    def test_checksum_mismatch_raises(self):
        kc = create_filled_keychain()
        dump, _ = kc.dump()
        fake_checksum = decode_bytes(
            "3GB6WSm+j+jl8pm4Vo9b9CkO2tZJzChu34VeitrwxXM="
        )
        with pytest.raises(ValueError):
            Keychain.load(MASTER_PASSWORD, dump, fake_checksum)

    def test_wrong_password_rejected(self):
        kc = create_filled_keychain()
        dump, checksum = kc.dump()
        with pytest.raises(ValueError):
            Keychain.load("wrong-password", dump, checksum)


class TestSecurityProperties:
    def test_no_plaintext_leakage(self):
        kc = create_filled_keychain()
        dump, _ = kc.dump()

        assert MASTER_PASSWORD not in dump

        for domain, pwd in TEST_ENTRIES.items():
            assert domain not in dump
            assert pwd not in dump


class TestFormatRequirements:
    def test_kvs_exists_in_dump(self):
        kc = create_filled_keychain()
        dump, _ = kc.dump()
        parsed = json_str_to_dict(dump)

        assert "kvs" in parsed
        assert isinstance(parsed["kvs"], dict)
        assert len(parsed["kvs"]) == len(TEST_ENTRIES)
