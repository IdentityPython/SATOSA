"""
Converter for transforming image files to bas64 raw data
"""
import logging
import os
import base64

from satosa.exception import SATOSAError

__author__ = 'danielevertsson'

LOGGER = logging.getLogger(__name__)


class SATOSAInvalidArgumentType(SATOSAError):
    """
    If the input to the converter is invalid
    """
    pass


class SATOSAUnsupportedImageFormat(SATOSAError):
    """
    If the image format is not supported by the converter.
    """
    pass


def convert_to_base64(image_path):
    """
    Converts an image to base64 raw data

    :type image_path: str
    :rtype: str

    :param image_path: Path to the image file
    :return: base64 data representation of the image
    """
    if not isinstance(image_path, str):
        raise SATOSAInvalidArgumentType()

    filename, file_extension = os.path.splitext(image_path)
    file_extension = file_extension.replace(".", "")
    if file_extension == "jpg":
        file_extension = "jpeg"
    try:
        with open(image_path, "rb") as image_file:
            if file_extension not in ["jpeg", "gif", "png"]:
                raise SATOSAUnsupportedImageFormat()
            encoded_string = base64.b64encode(image_file.read())
            return "data:image/%s;base64,%s" % (file_extension, bytes.decode(encoded_string))
    except FileNotFoundError:
        LOGGER.info("File not found or not a file path")
        return image_path
    except OSError:
        LOGGER.info("File not found or not a file path")
        return image_path
