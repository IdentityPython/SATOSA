from .base_processor import BaseProcessor

from enum import Enum, unique


@unique
class Gender(Enum):
    NOT_KNOWN     = 0
    MALE          = 1
    FEMALE        = 2
    NOT_SPECIFIED = 9


class GenderToSchacProcessor(BaseProcessor):
    def process(self, internal_data, attribute, **kwargs):
        attributes = internal_data.attributes
        value = attributes.get(attribute, [None])[0]

        if value:
            representation = getattr(
                Gender, value.upper().replace(' ', '_'), Gender.NOT_KNOWN)
        else:
            representation = Gender.NOT_SPECIFIED

        attributes[attribute][0] = str(representation.value)
