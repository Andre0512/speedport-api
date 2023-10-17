class LoginException(Exception):
    pass


class DecryptionKeyError(PermissionError):
    pass


class LoginPausedError(PermissionError):
    pass
