"""
Tests for the state class.
"""
import random
import string
from urllib.parse import quote_plus
from satosa.state import State

__author__ = 'haho0032'


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
    my_dict_frontend["resp_attr"] = get_str(150)
    assert len(my_dict_frontend) == 11, "The dictionary is not correct!"
    my_dict_consent = get_dict(1, get_str(10), get_str(150))
    assert len(my_dict_consent) == 1, "The dictionary is not correct!"
    my_dict_hash = get_dict(1, get_str(10), get_str(15))
    assert len(my_dict_hash) == 1, "The dictionary is not correct!"
    my_dict_router = get_dict(1, get_str(10), get_str(20))
    assert len(my_dict_router) == 1, "The dictionary is not correct!"
    my_dict_backend = get_dict(10, get_str(10), get_str(20))
    assert len(my_dict_backend) == 10, "The dictionary is not correct!"
    state.add("my_dict_frontend", my_dict_frontend)
    state.add("my_dict_consent", my_dict_consent)
    state.add("my_dict_hash", my_dict_hash)
    state.add("my_dict_router", my_dict_router)
    state.add("my_dict_backend", my_dict_backend)
    urlstate = state.urlstate(enc_key)
    #Some browsers only support 2000bytes, and since state is not the only parameter it should
    #not be greater then half that size.
    urlstate_len = len(quote_plus(urlstate))
    print("Size of state on the url is:%s" % urlstate_len)
    assert urlstate_len < 1000, "Urlstate is way to long!"
    state = State(urlstate, enc_key)
    tmp_dict_frontend = state.get("my_dict_frontend")
    tmp_dict_consent = state.get("my_dict_consent")
    tmp_dict_hash = state.get("my_dict_hash")
    tmp_dict_router = state.get("my_dict_router")
    tmp_dict_backend = state.get("my_dict_backend")
    compare_dict(tmp_dict_frontend, my_dict_frontend)
    compare_dict(tmp_dict_consent, my_dict_consent)
    compare_dict(tmp_dict_hash, my_dict_hash)
    compare_dict(tmp_dict_router, my_dict_router)
    compare_dict(tmp_dict_backend, my_dict_backend)
