"""
Python package file for util functions.
"""
import hashlib
import logging
import random
import string
from typing import Any
from typing import Mapping


logger = logging.getLogger(__name__)


def hash_data(salt, value, hash_alg=None):
    """
    Hashes a value together with a salt with the given hash algorithm.

    :type salt: str
    :type hash_alg: str
    :type value: str
    :param salt: hash salt
    :param hash_alg: the hash algorithm to use (default: SHA512)
    :param value: value to hash together with the salt
    :return: hashed value
    """
    hash_alg = hash_alg or 'sha512'
    hasher = hashlib.new(hash_alg)
    hasher.update(value.encode('utf-8'))
    hasher.update(salt.encode('utf-8'))
    value_hashed = hasher.hexdigest()
    return value_hashed


def check_set_dict_defaults(dic, spec):
    for path, value in spec.items():
        keys = path.split('.')
        try:
            _val = _dict_get_nested(dic, keys)
        except KeyError:
            if type(value) is list:
                value_default = value[0]
            else:
                value_default = value
            _dict_set_nested(dic, keys, value_default)
        else:
            if type(value) is list:
                is_value_valid = _val in value
            elif type(value) is dict:
                # do not validate dict
                is_value_valid = bool(_val)
            else:
                is_value_valid = _val == value
            if not is_value_valid:
                logline = (
                    "Incompatible configuration value '{value}' for '{path}'. "
                    "Value shoud be: {expected}"
                ).format(value=_val, path=path, expected=value)
                logger.warning(logline)
    return dic


def _dict_set_nested(dic, keys, value):
    for key in keys[:-1]:
        dic = dic.setdefault(key, {})
    dic[keys[-1]] = value


def _dict_get_nested(dic, keys):
    for key in keys[:-1]:
        dic = dic.setdefault(key, {})
    return dic[keys[-1]]


def get_dict_defaults(d, *keys):
    for key in keys:
        d = d.get(key, d.get("", d.get("default", {})))
    return d


def rndstr(size=16, alphabet=""):
    """
    Returns a string of random ascii characters or digits
    :type size: int
    :type alphabet: str
    :param size: The length of the string
    :param alphabet: A string with characters.
    :return: string
    """
    rng = random.SystemRandom()
    if not alphabet:
        alphabet = string.ascii_letters[0:52] + string.digits
    return type(alphabet)().join(rng.choice(alphabet) for _ in range(size))


_MISSING = object()


def resolve_nested_key(key: str, data: Mapping, separator: str = ".") -> Any:
    """
    Resolve a value in nested data using a separator-joined key path.

    Handles cases where the separator appears as a literal character in keys;
    a path like "foo.bar.abc.xyz" may resolve through the key "bar.abc" as
    well as through "bar" then "abc".

    The whole key is first tried as a single literal key of the top-level
    mapping, and the traversal then prefers the deepest match, consuming as
    few parts per step as possible. Longer keys are only considered when the
    deeper path leads to a dead end, and resolution backtracks, so a
    resolvable path is found whenever one exists.

    Example of candidate keys that will be tried in order with key "foo.bar.abc.xyz":
      1. foo.bar.abc.xyz        # top-level whole-key fast path
      2. foo | bar | abc | xyz  # then, pre-order DFS
      3. foo | bar | abc.xyz
      4. foo | bar.abc | xyz
      5. foo | bar.abc.xyz
      6. foo.bar | abc | xyz
      7. foo.bar | abc.xyz
      8. foo.bar.abc | xyz
      9. foo.bar.abc.xyz

    Args:
        key: The key path (e.g., "foo.bar.abc.xyz")
        data: The nested mapping to traverse
        separator: The key path separator (default: ".")

    Returns:
        The resolved value, or None if the key path cannot be resolved.

    Examples:
        >>> data = {'foo': {'bar.abc': {'xyz': 123}}}
        >>> resolve_nested_key('foo.bar.abc.xyz', data)
        123

        >>> data = {'foo': {'bar.abc': {'xyz': 123}, 'bar': {'abc': {'xyz': 456}}}}
        >>> resolve_nested_key('foo.bar.abc.xyz', data)  # Prefers the deepest match
        456

        >>> data = {'foo': {'bar.abc': {'xyz': 123}, 'bar': {'abc': {'nope': 1}}}}
        >>> resolve_nested_key('foo.bar.abc.xyz', data)  # Backtracks to "bar.abc"
        123

        >>> data = {'foo.bar': 1, 'foo': {'bar': 2}}
        >>> resolve_nested_key('foo.bar', data)  # Whole key wins at the top level
        1
    """
    # The whole key as a single literal key of the top-level mapping wins
    # outright, before any traversal
    if isinstance(data, Mapping) and key in data:
        return data[key]

    parts = key.split(separator)

    def resolve(current_data: Any, remaining_parts: list[str]) -> Any:
        # Base case: successfully consumed all parts
        if not remaining_parts:
            return current_data

        if not isinstance(current_data, Mapping):
            return _MISSING

        # Consume as few parts as possible first, to prefer the deepest match,
        # falling back to longer literal keys when the deeper path leads nowhere
        for num_parts in range(1, len(remaining_parts) + 1):
            potential_key = separator.join(remaining_parts[:num_parts])
            if potential_key not in current_data:
                continue

            value = resolve(current_data[potential_key], remaining_parts[num_parts:])
            if value is not _MISSING:
                return value

        # No valid path found
        return _MISSING

    value = resolve(data, parts)
    return None if value is _MISSING else value
