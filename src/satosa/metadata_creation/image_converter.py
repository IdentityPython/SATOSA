"""
Converter for transforming image files to bas64 raw data
"""
import base64
import logging
import os

logger = logging.getLogger(__name__)


def image_to_base64(image_path):
    """
    Converts an image to base64 raw data

    :type image_path: str
    :rtype: str

    :param image_path: Path to the image file
    :return: base64 data representation of the image
    """
    filename, file_extension = os.path.splitext(image_path)
    file_extension = file_extension.lstrip(".")
    if file_extension == "jpg":
        file_extension = "jpeg"
    if file_extension not in ["jpeg", "gif", "png"]:
        raise ValueError("Image format not supported.")

    try:
        with open(image_path, "rb") as image_file:
            encoded_string = base64.b64encode(image_file.read())
            return "data:image/%s;base64,%s" % (file_extension, encoded_string.decode("utf-8"))
    except IOError as e:
        logger.debug("Image could not be read: %s", str(e))
        raise
