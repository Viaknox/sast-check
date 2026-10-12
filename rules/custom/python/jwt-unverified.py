import jwt


def bad_options(token):
    # ruleid: sast.python.jwt-unverified
    return jwt.decode(token, options={"verify_signature": False})


def bad_options_with_key(token, key):
    # ruleid: sast.python.jwt-unverified
    return jwt.decode(token, key, algorithms=["HS256"], options={"verify_signature": False, "verify_exp": True})


def bad_old_api(token, key):
    # ruleid: sast.python.jwt-unverified
    return jwt.decode(token, key, verify=False)


def bad_none_alg(token, key):
    # ruleid: sast.python.jwt-unverified
    return jwt.decode(token, key, algorithms=["none"])


def bad_none_in_list(token, key):
    # ruleid: sast.python.jwt-unverified
    return jwt.decode(token, key, algorithms=["HS256", "none"])


def ok_normal(token, key):
    # ok: sast.python.jwt-unverified
    return jwt.decode(token, key, algorithms=["RS256"])


def ok_only_other_option(token, key):
    # ok: sast.python.jwt-unverified
    return jwt.decode(token, key, algorithms=["RS256"], options={"verify_exp": False})


def ok_verify_true(token, key):
    # ok: sast.python.jwt-unverified
    return jwt.decode(token, key, algorithms=["ES256"], options={"verify_signature": True})


def ok_encode(payload, key):
    # ok: sast.python.jwt-unverified
    return jwt.encode(payload, key, algorithm="HS256")
