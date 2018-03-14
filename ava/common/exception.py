class AvaException(Exception):
    pass


class InvalidValueException(AvaException):
    pass


class UnknownKeyException(AvaException):
    pass


class InvalidFormatException(AvaException):
    pass


class MissingComponentException(AvaException):
    pass
