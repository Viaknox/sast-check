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


def bad_options_via_variable(token):
    opts = {"verify_signature": False}
    # ruleid: sast.python.jwt-unverified
    return jwt.decode(token, options=opts)


def bad_options_via_variable_mixed(token, key):
    opts = {"verify_exp": True, "verify_signature": False}
    # ruleid: sast.python.jwt-unverified
    return jwt.decode(token, key, algorithms=["HS256"], options=opts)


def bad_options_via_dict_call(token):
    opts = dict(verify_signature=False)
    # ruleid: sast.python.jwt-unverified
    return jwt.decode(token, options=opts)


def ok_options_variable_verified(token, key):
    opts = {"verify_signature": True}
    # ok: sast.python.jwt-unverified
    return jwt.decode(token, key, algorithms=["RS256"], options=opts)


def ok_options_variable_other_flag(token, key):
    opts = dict(verify_exp=False)
    # ok: sast.python.jwt-unverified
    return jwt.decode(token, key, algorithms=["RS256"], options=opts)


def ok_unverified_flag_in_other_dict(token, key):
    unrelated = {"verify_signature": False}
    opts = {"verify_exp": True}
    print(unrelated)
    # ok: sast.python.jwt-unverified
    return jwt.decode(token, key, algorithms=["RS256"], options=opts)
