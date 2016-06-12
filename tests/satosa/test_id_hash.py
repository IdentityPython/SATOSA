from satosa.internal_data import InternalRequest, UserIdHashType, UserIdHasher
from satosa.state import State

SALT = "asdasdasdasdewr234"


def _get_id(requestor, user_id, hash_type):
    state = State()

    internal_request = InternalRequest(hash_type, requestor)

    UserIdHasher.save_state(internal_request, state)

    return UserIdHasher.hash_id(SALT, user_id, requestor, state)


def test_id_hash_transient():
    requestors = ["test_requestor0", "test_requestor0", "test_requestor2"]
    user_ids = ["userid0", "userid1", "userid2"]
    hash_type = UserIdHashType.transient

    ids = []
    for requestor in requestors:
        for id in user_ids:
            hashed_id = _get_id(requestor, id, hash_type)
            assert hashed_id not in ids
            ids.append(hashed_id)


def test_id_hash_persistent():
    requestors = ["test_requestor0"]
    user_ids = ["userid0", "userid1", "userid2"]
    hash_type = UserIdHashType.persistent

    ids = []
    for requestor in requestors:
        for id in user_ids:
            hashed_id = _get_id(requestor, id, hash_type)
            assert hashed_id == _get_id(requestor, id, hash_type)
            assert hashed_id not in ids
            ids.append(hashed_id)


def test_id_hash_pairwise():
    requestors = ["test_requestor0", "test_requestor1"]
    user_ids = ["userid0", "userid1", "userid2"]
    hash_type = UserIdHashType.pairwise

    ids = []
    for requestor in requestors:
        for id in user_ids:
            hashed_id = _get_id(requestor, id, hash_type)
            assert hashed_id == _get_id(requestor, id, hash_type)
            assert hashed_id not in ids
            ids.append(hashed_id)


def test_id_hash_public():
    requestors = ["test_requestor0", "test_requestor1", "test_requestor2"]
    user_ids = ["userid0", "userid1", "userid2"]
    hash_type = UserIdHashType.public

    ids = []
    for id in user_ids:
        hashed_id = _get_id(requestors[0], id, hash_type)
        assert hashed_id not in ids
        ids.append(hashed_id)

    for requestor in requestors:
        for id in user_ids:
            hashed_id = _get_id(requestor, id, hash_type)
            assert hashed_id in ids
