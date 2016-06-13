import base64
from unittest.mock import patch, mock_open

import pytest

from satosa.metadata_creation.image_converter import image_to_base64


class TestImageToBase64(object):
    @pytest.yield_fixture
    def mock_image(self):
        self.image_data = "image data".encode("utf-8")
        with patch("builtins.open", mock_open(read_data=self.image_data)) as mock_file:
            yield mock_file

    def test_with_image(self, mock_image):
        data = image_to_base64("image.jpg")
        mock_image.assert_called_once_with("image.jpg", "rb")
        assert data == "data:image/jpeg;base64,{}".format(base64.b64encode(self.image_data).decode("utf-8"))

    @pytest.mark.parametrize("file_ending", ["jpg", "jpeg", "gif", "png"])
    def test_accepts_supported_file_endings(self, file_ending, mock_image):
        # should not throw an exception
        image_to_base64("image.{}".format(file_ending))

    def test_rejects_unsupported_file_ending(self, mock_image):
        with pytest.raises(ValueError):
            image_to_base64("image.unknown")

    def test_raises_exception_if_file_does_not_exists(self):
        with pytest.raises(IOError):
            image_to_base64("image.jpg")
