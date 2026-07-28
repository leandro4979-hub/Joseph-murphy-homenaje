from carina.policy.models import Scope
from carina.policy.scope_matcher import scope_is_subset


def test_file_and_descendant_are_within_authorized_directory():
    authorized = Scope("filesystem", ("~/Documents/CARINA",))
    assert scope_is_subset(Scope("filesystem", ("~/Documents/CARINA/Architecture.docx",)), authorized)


def test_prefix_and_traversal_cannot_escape_scope():
    authorized = Scope("filesystem", ("/safe/root",))
    assert not scope_is_subset(Scope("filesystem", ("/safe/root-secret/file",)), authorized)
    assert not scope_is_subset(Scope("filesystem", ("/safe/root/../secret",)), authorized)


def test_unknown_scope_kind_fails_closed():
    assert not scope_is_subset(Scope("network", ("example.com",)), Scope("network", ("example.com",)))

