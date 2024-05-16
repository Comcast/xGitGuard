from common.logger import create_logger


def query_length_validator(
    search_qualifier, query, limit=170, max_search_qualifier_per_query=10
):
    qualifier_query = ""
    qualifier_query_length = 0
    qualifiers_in_query = 0
    qualifier_string = ""
    for qualifier in search_qualifier:
        if qualifier_query_length + len(qualifier) + 1 <= limit and (
            max_search_qualifier_per_query is None
            or qualifiers_in_query < max_search_qualifier_per_query
        ):
            qualifier_query += f""" {query}:{str(qualifier)}"""
            qualifier_query_length += len(qualifier) + 1
            qualifiers_in_query += 1
        else:
            return -1

    if qualifier_query:
        qualifier_string = qualifier_query.strip()

    return qualifier_string
