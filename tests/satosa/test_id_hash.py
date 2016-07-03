from satosa.internal_data import InternalRequest, UserIdHashType, UserIdHasher
from satosa.state import State

SALT = "asdasdasdasdewr234"


def _get_id(requester, user_id, hash_type):
    state = State()

    internal_request = InternalRequest(hash_type, requester)

    UserIdHasher.save_state(internal_request, state)

    return UserIdHasher.hash_id(SALT, user_id, requester, state)


def test_id_hash_transient():
    requesters = ["test_requester0", "test_requester0", "test_requester2"]
    user_ids = ["userid0", "userid1", "userid2"]
    hash_type = UserIdHashType.transient

    ids = []
    for requester in requesters:
        for id in user_ids:
            hashed_id = _get_id(requester, id, hash_type)
            assert hashed_id not in ids
            ids.append(hashed_id)


def test_id_hash_persistent():
    requesters = ["test_requester0"]
    user_ids = ["userid0", "userid1", "userid2"]
    hash_type = UserIdHashType.persistent

    ids = []
    for requester in requesters:
        for id in user_ids:
            hashed_id = _get_id(requester, id, hash_type)
            assert hashed_id == _get_id(requester, id, hash_type)
            assert hashed_id not in ids
            ids.append(hashed_id)


def test_id_hash_pairwise():
    requesters = ["test_requester0", "test_requester1"]
    user_ids = ["userid0", "userid1", "userid2"]
    hash_type = UserIdHashType.pairwise

    ids = []
    for requester in requesters:
        for id in user_ids:
            hashed_id = _get_id(requester, id, hash_type)
            assert hashed_id == _get_id(requester, id, hash_type)
            assert hashed_id not in ids
            ids.append(hashed_id)


def test_id_hash_public():
    requesters = ["test_requester0", "test_requester1", "test_requester2"]
    user_ids = ["userid0", "userid1", "userid2"]
    hash_type = UserIdHashType.public

    ids = []
    for id in user_ids:
        hashed_id = _get_id(requesters[0], id, hash_type)
        assert hashed_id not in ids
        ids.append(hashed_id)

    for requester in requesters:
        for id in user_ids:
            hashed_id = _get_id(requester, id, hash_type)
            assert hashed_id in ids
