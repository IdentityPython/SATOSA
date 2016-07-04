import pytest

from satosa.internal_data import UserIdHashType


class TestUserIdHashType:
    @pytest.mark.parametrize("str_value, expected_value", [
        ("transient", UserIdHashType.transient),
        ("persistent", UserIdHashType.persistent),
        ("pairwise", UserIdHashType.pairwise),
        ("public", UserIdHashType.public)
    ])
    def test_from_string(self, str_value, expected_value):
        assert UserIdHashType.from_string(str_value) == expected_value

    def test_from_string_with_broken_value(self):
        with pytest.raises(ValueError):
            UserIdHashType.from_string("unknown")
