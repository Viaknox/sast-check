from jose import jwt


def bad_claims(token):
    # ruleid: sast.python.jwt-unverified-claims
    claims = jwt.get_unverified_claims(token)
    return claims["sub"]


def bad_claims_in_branch(token):
    # ruleid: sast.python.jwt-unverified-claims
    if jwt.get_unverified_claims(token).get("admin"):
        return True
    return False


def bad_alg_from_header(token, keys):
    # ruleid: sast.python.jwt-unverified-claims
    hdr = jwt.get_unverified_header(token)
    return jwt.decode(token, keys, algorithms=[hdr["alg"]])


def ok_kid_lookup(token, keys):
    hdr = jwt.get_unverified_header(token)
    key = keys[hdr["kid"]]
    # ok: sast.python.jwt-unverified-claims
    return jwt.decode(token, key, algorithms=["RS256"])


def ok_kid_direct(token, keys):
    # ok: sast.python.jwt-unverified-claims
    kid = jwt.get_unverified_header(token)["kid"]
    return keys[kid]


def ok_verified_decode(token, key):
    # ok: sast.python.jwt-unverified-claims
    return jwt.decode(token, key, algorithms=["ES256"])
