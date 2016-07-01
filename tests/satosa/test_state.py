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


def compare_dict(dict1, dict2, stop=False):
    """
    Compares that two directories are identical.

    :type dict1: dict[str,str]
    :type dict2: dict[str,str]
    :type stop: bool

    :param dict1: A dictionary to be compared.
    :param dict2: A dictionary to be compared.
    :param stop: True if the function should stop and not call itself, otherwise False.
    """
    assert len(dict1) == len(dict2), "Both dictionaries must be of equal length!"
    for tmp_key in dict1:
        assert tmp_key in dict2, "All keys must exist in both dictionaries!"
        assert dict1[tmp_key] == dict2[tmp_key], "Values must be the same!"
    if not stop:
        compare_dict(dict2, dict1, True)


def test_simple_test():
    """
    Performs a test that the state class works as intended.

    :return:
    """
    enc_key = "Ireallyliketoencryptthisdictionary!"
    state = State()
    my_dict_frontend = get_dict(10, get_str(10), get_str(10))
    my_dict_frontend["resp_attr"] = get_str(100)
    assert len(my_dict_frontend) == 11, "The dictionary is not correct!"
    my_dict_consent = get_dict(1, get_str(10), get_str(100))
    assert len(my_dict_consent) == 1, "The dictionary is not correct!"
    my_dict_hash = get_dict(1, get_str(10), get_str(15))
    assert len(my_dict_hash) == 1, "The dictionary is not correct!"
    my_dict_router = get_dict(1, get_str(10), get_str(10))
    assert len(my_dict_router) == 1, "The dictionary is not correct!"
    my_dict_backend = get_dict(10, get_str(10), get_str(10))
    assert len(my_dict_backend) == 10, "The dictionary is not correct!"
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
    tmp_dict_frontend = state["my_dict_frontend"]
    tmp_dict_consent = state["my_dict_consent"]
    tmp_dict_hash = state["my_dict_hash"]
    tmp_dict_router = state["my_dict_router"]
    tmp_dict_backend = state["my_dict_backend"]
    compare_dict(tmp_dict_frontend, my_dict_frontend)
    compare_dict(tmp_dict_consent, my_dict_consent)
    compare_dict(tmp_dict_hash, my_dict_hash)
    compare_dict(tmp_dict_router, my_dict_router)
    compare_dict(tmp_dict_backend, my_dict_backend)


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

        cookie = state_to_cookie(state, cookie_name, path, encrypt_key)
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

        cookie = state_to_cookie(state, cookie_name, path, encrypt_key)
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
