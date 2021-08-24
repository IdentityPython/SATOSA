from collections import defaultdict


def combine_return_input(values):
    return values


def combine_select_first_value(values):
    return values[0]


def combine_join_by_space(values):
    return " ".join(values)


combine_values_by_claim = defaultdict(
    lambda: combine_return_input,
    {
        "sub": combine_select_first_value,
        "name": combine_select_first_value,
        "given_name": combine_join_by_space,
        "family_name": combine_join_by_space,
        "middle_name": combine_join_by_space,
        "nickname": combine_select_first_value,
        "preferred_username": combine_select_first_value,
        "profile": combine_select_first_value,
        "picture": combine_select_first_value,
        "website": combine_select_first_value,
        "email": combine_select_first_value,
        "email_verified": combine_select_first_value,
        "gender": combine_select_first_value,
        "birthdate": combine_select_first_value,
        "zoneinfo": combine_select_first_value,
        "locale": combine_select_first_value,
        "phone_number": combine_select_first_value,
        "phone_number_verified": combine_select_first_value,
        "address": combine_select_first_value,
        "updated_at": combine_select_first_value,
    },
)


def combine_claim_values(claim_items):
    claims = (
        (name, combine_values_by_claim[name](values)) for name, values in claim_items
    )
    return claims
