"""
Tests for the state class.
"""
import random
import string
from http.cookies import SimpleCookie
from urllib.parse import quote_plus

import pytest

from satosa.state import State, state_to_cookie, cookie_to_state, SATOSAStateError


def get_dict(size, key_prefix, value_preix):
    """
    Creates a dictionary with size numbers of keys.

    :type size: int
    :type key_prefix: str
    :type value_preix: str
    :rtype: dict[str, str]

    :param size: The amout of keys the dictionary must contain.
    :param key_prefix: A value to be added before each key.
    :param value_preix: A value to be added before each value.
    :return: A dictionary.
    """
    my_dict = {}
    for num in range(0, size):
        key = "%s_%s" % (key_prefix, num)
        value = "%s_%s" % (value_preix, num)
        my_dict[key] = value
    return my_dict


def get_str(length):
    """
    Creates a string of a given length.

    :type length: int
    :rtype: str

    :param length: The length of the string.
    :return: A string with the assigned length.
    """
    return ''.join(random.choice(string.ascii_lowercase) for x in range(length))


class TestState:
    def test_urlstate_length_should_fit_in_browser_cookie(self):
        """
        Performs a test that the state class works as intended.

        :return:
        """
        enc_key = "Ireallyliketoencryptthisdictionary!"
        state = State()
        my_dict_frontend = get_dict(11, get_str(10), get_str(10))
        my_dict_consent = get_dict(1, get_str(10), get_str(100))
        my_dict_hash = get_dict(1, get_str(10), get_str(15))
        my_dict_router = get_dict(1, get_str(10), get_str(10))
        my_dict_backend = get_dict(10, get_str(10), get_str(10))
        state["my_dict_frontend"] = my_dict_frontend
        state["my_dict_consent"] = my_dict_consent
        state["my_dict_hash"] = my_dict_hash
        state["my_dict_router"] = my_dict_router
        state["my_dict_backend"] = my_dict_backend
        urlstate = state.urlstate(enc_key)
        # Some browsers only support 2000bytes, and since state is not the only parameter it should
        # not be greater then half that size.
        urlstate_len = len(quote_plus(urlstate))
        print("Size of state on the url is:%s" % urlstate_len)
        assert urlstate_len < 1000, "Urlstate is way to long!"
        state = State(urlstate, enc_key)
        assert state["my_dict_frontend"] == my_dict_frontend
        assert state["my_dict_consent"] == my_dict_consent
        assert state["my_dict_hash"] == my_dict_hash
        assert state["my_dict_router"] == my_dict_router
        assert state["my_dict_backend"] == my_dict_backend

    def test_contains(self):
        state = State()
        state["foo"] = "bar"
        assert "foo" in state
        del state["foo"]
        assert "foo" not in state


class TestStateAsCookie:
    def test_encode_decode_of_state(self):
        """
        Test that the state can be converted between cookie and state
        """
        state_key = "27614gjkrn"
        saved_data = "data"
        state = State()
        state[state_key] = saved_data

        cookie_name = "state_cookie"
        path = "/"
        encrypt_key = "2781y4hef90"

        cookie = state_to_cookie(state, name=cookie_name, path=path, encryption_key=encrypt_key)
        cookie_str = cookie[cookie_name].OutputString()
        loaded_state = cookie_to_state(cookie_str, cookie_name, encrypt_key)

        assert loaded_state[state_key] == saved_data

    def test_state_to_cookie_produces_cookie_without_max_age_for_state_that_should_be_deleted(self):
        state_key = "27614gjkrn"
        saved_data = "data"
        state = State()
        state[state_key] = saved_data
        state.delete = True

        cookie_name = "state_cookie"
        path = "/"
        encrypt_key = "2781y4hef90"

        cookie = state_to_cookie(state, name=cookie_name, path=path, encryption_key=encrypt_key)
        cookie_str = cookie[cookie_name].OutputString()

        parsed_cookie = SimpleCookie(cookie_str)
        assert not parsed_cookie[cookie_name].value
        assert parsed_cookie[cookie_name]["max-age"] == '0'

    @pytest.mark.parametrize("cookie_str, name, encryption_key, expected_exception", [
        (  # Test wrong encryption_key
                'Set-Cookie: state_cookie="_Td6WFoAAATm1rRGAgAhARYAAAB0L-WjAQCXYWt4NU9ZLWF5amdVVDdSUjhWdnkyUHE5MFhJV0J4Uzg5di1EVW1nNTR0WHZKakFsaWJmN2JMOUtlNEltMkJ0dmxOakRyUDJXZE53d0dwSGNqYnBzVng5YjVVeUYyUzkwcWVSMU42U2VNNHZDQTktUXdCQWx0WUh6LVBPX1pBYnZ1M1RsV09Qc2lKS3VpelB5a0FsMG93PT0AmlSCX0Pk2WoAAbABmAEAAGRNyZ2xxGf7AgAAAAAEWVo="; Max-Age=600; Path=/; Secure',
                "state_cookie",
                "wrong_encrypt_key",
                Exception,
        ),
        (  # Test wrong cookie_name
                'Set-Cookie: state_cookie="_Td6WFoAAATm1rRGAgAhARYAAAB0L-WjAQCXYWt4NU9ZLWF5amdVVDdSUjhWdnkyUHE5MFhJV0J4Uzg5di1EVW1nNTR0WHZKakFsaWJmN2JMOUtlNEltMkJ0dmxOakRyUDJXZE53d0dwSGNqYnBzVng5YjVVeUYyUzkwcWVSMU42U2VNNHZDQTktUXdCQWx0WUh6LVBPX1pBYnZ1M1RsV09Qc2lKS3VpelB5a0FsMG93PT0AmlSCX0Pk2WoAAbABmAEAAGRNyZ2xxGf7AgAAAAAEWVo="; Max-Age=600; Path=/; Secure',
                "wrong_name",
                "2781y4hef90",
                SATOSAStateError,
        ),
        (  # Test bad cookie str
                'not_a_cookie',
                "state_cookie",
                "2781y4hef90",
                SATOSAStateError,
        ),
    ])
    def test_cookie_to_state_handle_broken_cookies(self, cookie_str, name, encryption_key, expected_exception):
        """
        Test that the cookie_to_state raises exception if the input is bad
        """
        with pytest.raises(expected_exception):
            cookie_to_state(cookie_str, name, encryption_key)
