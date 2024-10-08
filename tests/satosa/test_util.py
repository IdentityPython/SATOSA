import itertools
from collections import OrderedDict
from types import MappingProxyType

import pytest

from satosa.util import resolve_nested_key


def _compositions(segments, separator="."):
    """
    Every way to split segments into consecutive non-empty groups.

    For ["a", "b", "c"] this yields the 4 key paths that all render back to
    "a.b.c": ("a", "b", "c"), ("a.b", "c"), ("a", "b.c") and ("a.b.c",).
    """
    count = len(segments)
    compositions = []
    for mask in range(1 << (count - 1)):
        groups = []
        group = [segments[0]]
        for index in range(count - 1):
            if mask & (1 << index):
                groups.append(group)
                group = [segments[index + 1]]
            else:
                group.append(segments[index + 1])
        groups.append(group)
        compositions.append(tuple(separator.join(g) for g in groups))
    return compositions


def _build_data(numbered_paths):
    """Build a mapping holding every given key path, each with its own value."""
    data = {}
    for value, path in numbered_paths:
        node = data
        for key in path[:-1]:
            node = node.setdefault(key, {})
        node[path[-1]] = value
    return data


def _every_data_shape(segments):
    """Every mapping built from a non-empty subset of the key paths for segments."""
    compositions = list(enumerate(_compositions(segments), start=1))
    for size in range(1, len(compositions) + 1):
        for subset in itertools.combinations(compositions, size):
            yield _build_data(subset)


class TestResolveNestedKey:
    def test_flat_key(self):
        assert resolve_nested_key("foo", {"foo": 1, "bar": 2}) == 1

    def test_nested_key(self):
        assert resolve_nested_key("foo.bar", {"foo": {"bar": 1}}) == 1

    def test_deeply_nested_key(self):
        data = {"foo": {"bar": {"abc": {"xyz": 1}}}}
        assert resolve_nested_key("foo.bar.abc.xyz", data) == 1

    def test_key_path_resolving_to_a_mapping(self):
        data = {"foo": {"bar": {"abc": 1}}}
        assert resolve_nested_key("foo.bar", data) == {"abc": 1}

    def test_custom_separator(self):
        data = {"foo": {"bar": 1}}
        assert resolve_nested_key("foo/bar", data, separator="/") == 1

    def test_separator_that_is_not_present_in_the_key(self):
        data = {"foo.bar": {"baz": 1}}
        assert resolve_nested_key("foo.bar/baz", data, separator="/") == 1

    def test_long_key_path(self):
        segments = [f"k{index}" for index in range(10)]
        data = value = {"leaf": 1}
        for segment in reversed(segments):
            data = {segment: data}
        assert resolve_nested_key(".".join(segments), data) == value

    @pytest.mark.parametrize("mapping_type", [dict, OrderedDict, MappingProxyType])
    def test_any_mapping_type_is_traversed(self, mapping_type):
        data = mapping_type({"foo": mapping_type({"bar": 1})})
        assert resolve_nested_key("foo.bar", data) == 1


class TestResolveNestedKeyWithLiteralSeparator:
    def test_whole_key_as_a_literal_key(self):
        assert resolve_nested_key("foo.bar", {"foo.bar": 1}) == 1

    def test_literal_separator_below_the_top_level(self):
        data = {"foo": {"bar.abc": {"xyz": 1}}}
        assert resolve_nested_key("foo.bar.abc.xyz", data) == 1

    def test_literal_separator_in_the_last_key(self):
        data = {"foo": {"bar.abc": 1}}
        assert resolve_nested_key("foo.bar.abc", data) == 1

    def test_several_literal_separators(self):
        data = {"foo.bar": {"abc.xyz": 1}}
        assert resolve_nested_key("foo.bar.abc.xyz", data) == 1


class TestResolveNestedKeyPreferenceOrder:
    """
    The resolution order is fixed by compatibility with the legacy
    implementation: the whole key as a literal key of the top-level mapping
    first, and the deepest match after that.
    """

    def test_whole_key_wins_over_the_nested_path(self):
        data = {"foo.bar": 1, "foo": {"bar": 2}}
        assert resolve_nested_key("foo.bar", data) == 1

    def test_whole_key_only_wins_at_the_top_level(self):
        data = {"foo": {"bar.abc": 1, "bar": {"abc": 2}}}
        assert resolve_nested_key("foo.bar.abc", data) == 2

    def test_deepest_match_is_preferred(self):
        data = {"foo": {"bar.abc": {"xyz": 1}, "bar": {"abc": {"xyz": 2}}}}
        assert resolve_nested_key("foo.bar.abc.xyz", data) == 2

    def test_deepest_match_is_preferred_over_a_shallower_one(self):
        data = {"foo.bar": {"abc": {"xyz": 1}}, "foo": {"bar": {"abc": {"xyz": 2}}}}
        assert resolve_nested_key("foo.bar.abc.xyz", data) == 2


class TestResolveNestedKeyBacktracking:
    def test_backtracks_when_the_deepest_match_dead_ends(self):
        data = {"foo": {"bar": {"abc": {"nope": 1}}, "bar.abc": {"xyz": 2}}}
        assert resolve_nested_key("foo.bar.abc.xyz", data) == 2

    def test_backtracks_over_several_levels(self):
        data = {
            "foo": {"bar": {"abc": {"nope": 1}}, "bar.abc": {"nope": 2}},
            "foo.bar": {"abc": {"xyz": 3}},
        }
        assert resolve_nested_key("foo.bar.abc.xyz", data) == 3

    def test_backtracks_out_of_a_non_mapping_dead_end(self):
        data = {"foo": {"bar": "not-a-mapping"}, "foo.bar": {"abc": 1}}
        assert resolve_nested_key("foo.bar.abc", data) == 1

    def test_backtracks_to_the_whole_key_as_a_last_resort(self):
        data = {"foo": {"bar": {"nope": 1}}, "foo.bar.abc": 2}
        assert resolve_nested_key("foo.bar.abc", data) == 2


class TestResolveNestedKeyUnresolvable:
    @pytest.mark.parametrize(
        "key, data",
        [
            pytest.param("foo", {}, id="empty-data"),
            pytest.param("foo", {"bar": 1}, id="unknown-key"),
            pytest.param("foo.bar", {"foo": {"baz": 1}}, id="unknown-nested-key"),
            pytest.param("foo.bar", {"foo": "a-string"}, id="non-mapping-value"),
            pytest.param("foo.bar.baz", {"foo": {"bar": 1}}, id="key-longer-than-data"),
            pytest.param("foo.bar", {"foo": ["a", "list"]}, id="sequence-value"),
            pytest.param("foo.bar", {"foo": {"bar.baz": 1}}, id="key-shorter-than-data"),
        ],
    )
    def test_returns_none(self, key, data):
        assert resolve_nested_key(key, data) is None

    def test_non_mapping_data(self):
        assert resolve_nested_key("foo.bar", "not-a-mapping") is None


class TestResolveNestedKeyFalsyValues:
    """
    A stored falsy value is a resolved value, not a failure to resolve. The
    legacy implementation got this wrong for a whole-key literal match.
    """

    @pytest.mark.parametrize("value", [0, "", [], {}, False])
    def test_falsy_nested_value_is_returned(self, value):
        assert resolve_nested_key("foo.bar", {"foo": {"bar": value}}) == value

    @pytest.mark.parametrize("value", [0, "", [], {}, False])
    def test_falsy_whole_key_value_is_returned(self, value):
        assert resolve_nested_key("foo.bar", {"foo.bar": value}) == value

    def test_falsy_whole_key_value_wins_over_the_nested_path(self):
        data = {"foo.bar": 0, "foo": {"bar": 2}}
        assert resolve_nested_key("foo.bar", data) == 0

    def test_stored_none_resolves_to_none(self):
        # Indistinguishable from "unresolvable" by design, since both are None
        assert resolve_nested_key("foo.bar", {"foo": {"bar": None}}) is None
