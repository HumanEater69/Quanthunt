from sqlalchemy.types import String, Text, TypeDecorator

class EncryptedString(TypeDecorator):
    """Fallback/Stub for Encrypted String"""
    impl = String
    cache_ok = True

class EncryptedText(TypeDecorator):
    """Fallback/Stub for Encrypted Text"""
    impl = Text
    cache_ok = True
