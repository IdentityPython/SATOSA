import pytest
from satosa.util import join_paths


@pytest.mark.parametrize(
    "args, expected",
    [
        (["/foo", "baz", "bar"], "/foo/baz/bar"),
        (["foo", "baz", "bar"], "foo/baz/bar"),
        (["https://foo.baz", "bar"], "https://foo.baz/bar"),
        (["https://foo.baz/", "bar"], "https://foo.baz/bar"),
        (["foo", "/bar"], "foo/bar"),
        (["/foo", "baz", "/bar"], "/foo/baz/bar"),
        (["", "foo", "bar"], "foo/bar"),
        (["", "/foo", "bar"], "/foo/bar"),
        (["", "/foo/", "bar"], "/foo/bar"),
        (["", "", "", "/foo", "bar"], "/foo/bar"),
        (["", "", "/foo/", "", "bar"], "/foo/bar"),
        (["", "", "/foo/", "", "", "bar/"], "/foo/bar/"),
        (["/foo", ""], "/foo/"),
        (["/foo", "", "", ""], "/foo/"),
        (["/foo//", "bar"], "/foo//bar"),
        (["foo"], "foo"),
        ([""], ""),
        (["", ""], ""),
        (["'not ", "sanitized'\0/; rm -rf *"], "'not /sanitized'\0/; rm -rf *"),
        (["foo/", "/bar"], "foo//bar"),
        (["foo", "", "/bar"], "foo//bar"),
        ([b"foo", "bar"], TypeError),
        (["foo", b"bar"], TypeError),
        ([None, "foo"], TypeError),
    ],
)
def test_join_paths(args, expected):
    if isinstance(expected, str):
        assert join_paths(*args) == expected
    else:
        with pytest.raises(expected):
            _ = join_paths(*args)
