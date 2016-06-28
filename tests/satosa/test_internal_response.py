from satosa.internal_data import InternalResponse, UserIdHashType


def test_set_user_id():
    uid = "my_id"
    attributes = {"attr_1": "v1", "attr_2": "v2", "attr_3": "v3"}
    internal_response = InternalResponse(UserIdHashType.persistent)
    internal_response.attributes = attributes
    internal_response.set_user_id(uid)
    assert uid == internal_response.get_user_id()


def test_set_user_id_from_attributes():
    # uid = "my_id"
    attributes = {"attr_1": "v1", "attr_2": "v2", "attr_3": "v3"}
    uid_attributes = ["attr_1", "attr_3"]
    uid = "v1v3"
    internal_response = InternalResponse(UserIdHashType.persistent)
    internal_response.attributes = attributes
    internal_response.set_user_id_from_attr(uid_attributes)
    assert uid == internal_response.get_user_id()
