"""Unit tests for the mailbox module."""

import pytest
from hamcrest import (
    assert_that,
    contains_exactly,
    has_properties,
)

from taramail.alias import AliasCreate
from taramail.domain import DomainCreate
from taramail.email import join_email
from taramail.mailbox import (
    MailboxAlreadyExistsError,
    MailboxCreate,
    MailboxNotFoundError,
    MailboxUpdate,
    MailboxValidationError,
)


@pytest.fixture
def domain(domain_manager, unique):
    """Return the domain name for a managed domain."""
    domain = unique("domain")
    domain_create = DomainCreate(domain=domain)
    domain_manager.create_domain(domain_create)

    return domain


def test_mailbox_manager_get_mailbox_details(domain, mailbox_manager, unique):
    """Getting mailbox details should at least include the local part."""
    local_part, password = unique("text"), unique("password")
    mailbox_create = MailboxCreate(
        local_part=local_part,
        domain=domain,
        password=password,
        password2=password,
    )
    mailbox = mailbox_manager.create_mailbox(mailbox_create)
    mailbox_manager.db.flush()

    result = mailbox_manager.get_mailbox_details(mailbox.username)
    assert result.local_part == local_part


def test_mailbox_manager_create_mailbox(domain, mailbox_manager, unique):
    """Creating a mailbox should create a mailbox row."""
    local_part, password = unique("text"), unique("password")
    mailbox_create = MailboxCreate(
        local_part=local_part,
        domain=domain,
        password=password,
        password2=password,
    )
    mailbox = mailbox_manager.create_mailbox(mailbox_create)
    mailbox_manager.db.flush()

    result = mailbox_manager.get_mailbox_details(mailbox.username)
    assert result.domain == domain


def test_mailbox_manager_create_mailbox_twice(domain, mailbox_manager, unique):
    """Creating a mailbox twice should raise."""
    local_part, password = unique("text"), unique("password")
    mailbox_create = MailboxCreate(
        local_part=local_part,
        domain=domain,
        password=password,
        password2=password,
    )
    mailbox_manager.create_mailbox(mailbox_create)
    mailbox_manager.db.flush()

    with pytest.raises(MailboxAlreadyExistsError):
        mailbox_manager.create_mailbox(mailbox_create)


def test_mailbox_manager_update_mailbox(domain, mailbox_manager, unique):
    """Updating a mailbox should return the updated details."""
    local_part, password = unique("text"), unique("password")
    old_name, new_name = unique("text"), unique("text")
    mailbox_create = MailboxCreate(
        local_part=local_part,
        domain=domain,
        password=password,
        password2=password,
        name=old_name,
    )
    mailbox = mailbox_manager.create_mailbox(mailbox_create)
    mailbox_manager.db.flush()
    assert mailbox.name == old_name

    mailbox_update = MailboxUpdate(name=new_name)
    result = mailbox_manager.update_mailbox(mailbox.username, mailbox_update)
    assert result.name == new_name


def test_mailbox_manager_update_mailbox_attributes(domain, mailbox_manager, unique):
    """Updating mailbox attributes should update the user attributes."""
    local_part, password = unique("text"), unique("password")
    mailbox_create = MailboxCreate(
        local_part=local_part,
        domain=domain,
        password=password,
        password2=password,
    )
    mailbox = mailbox_manager.create_mailbox(mailbox_create)
    mailbox_manager.db.flush()

    mailbox_update = MailboxUpdate(sogo_access=False)
    mailbox_manager.update_mailbox(mailbox.username, mailbox_update)
    result = mailbox_manager.get_mailbox_details(mailbox.username)
    assert result.sogo_access is False


@pytest.fixture
def username(domain, mailbox_manager, unique):
    """Return the username for a managed mailbox."""
    password = unique("password")
    mailbox_create = MailboxCreate(
        local_part=unique("text"),
        domain=domain,
        password=password,
        password2=password,
    )
    mailbox = mailbox_manager.create_mailbox(mailbox_create)
    mailbox_manager.db.flush()

    return mailbox.username


def test_mailbox_manager_update_sender_acl_null_alias(domain, username, alias_manager, mailbox_manager, unique):
    """A mailbox should be allowed to send as an alias that discards mail."""
    address = unique("email", domain=domain)
    alias_manager.create_alias(AliasCreate(address=address, goto_null=True))
    alias_manager.db.flush()

    mailbox_manager.update_mailbox(username, MailboxUpdate(sender_acl=[address]))
    result = mailbox_manager.get_mailbox_details(username)
    assert result.sender_acl == [address]
    assert alias_manager.get_alias(address).goto == "null@localhost"


@pytest.mark.parametrize("sender_acl, expected", [
    (["*", "@invalid"], ["*"]),
    (["default"], []),
    ([], []),
])
def test_mailbox_manager_update_sender_acl_special(sender_acl, expected, username, mailbox_manager):
    """Like mailcow, "*" should supersede everything and "default" should reset."""
    mailbox_manager.update_mailbox(username, MailboxUpdate(sender_acl=["*"]))
    mailbox_manager.update_mailbox(username, MailboxUpdate(sender_acl=sender_acl))
    result = mailbox_manager.get_mailbox_details(username)
    assert result.sender_acl == expected


def test_mailbox_manager_update_sender_acl_domain(domain, username, mailbox_manager):
    """A domain should be stored with a leading @ and replace the previous list."""
    mailbox_manager.update_mailbox(username, MailboxUpdate(sender_acl=["*"]))
    mailbox_manager.update_mailbox(username, MailboxUpdate(sender_acl=["default", domain]))
    result = mailbox_manager.get_mailbox_details(username)
    assert result.sender_acl == [f"@{domain}"]


def test_mailbox_manager_update_sender_acl_fixed_alias(domain, username, alias_manager, mailbox_manager, unique):
    """An alias already pointing to the mailbox should not need a sender ACL."""
    address = unique("email", domain=domain)
    alias_manager.create_alias(AliasCreate(address=address, goto=username))
    alias_manager.db.flush()

    mailbox_manager.update_mailbox(username, MailboxUpdate(sender_acl=[address]))
    result = mailbox_manager.get_mailbox_details(username)
    assert result.sender_acl == []


@pytest.mark.parametrize("value", [
    "unknown@example.com",
    "@example.com",
    "not a domain",
])
def test_mailbox_manager_update_sender_acl_invalid(value, username, mailbox_manager):
    """Unknown addresses and non-local domains should be rejected."""
    with pytest.raises(MailboxValidationError):
        mailbox_manager.update_mailbox(username, MailboxUpdate(sender_acl=[value]))


def test_mailbox_manager_update_extended_sender_acl(username, mailbox_manager, unique):
    """External addresses and domains should be stored as external."""
    email = unique("email", domain="example.com")
    mailbox_update = MailboxUpdate(extended_sender_acl=[email, "example.org", ""])
    mailbox_manager.update_mailbox(username, mailbox_update)
    result = mailbox_manager.get_mailbox_details(username)
    assert result.extended_sender_acl == [email, "@example.org"]
    assert result.sender_acl == []


@pytest.mark.parametrize("make_value", [
    lambda domain: f"someone@{domain}",
    lambda domain: f"@{domain}",
    lambda domain: "not a domain",
])
def test_mailbox_manager_update_extended_sender_acl_invalid(make_value, domain, username, mailbox_manager):
    """Local domains and invalid values should be rejected as external senders."""
    mailbox_update = MailboxUpdate(extended_sender_acl=[make_value(domain)])
    with pytest.raises(MailboxValidationError):
        mailbox_manager.update_mailbox(username, mailbox_update)


def test_mailox_manager_delete_mailbox(domain, alias_manager, mailbox_manager, unique):
    """Deleting a domain should delete it from everywhere, including aliases."""
    local_part, password = unique("text"), unique("password")
    mailbox_create = MailboxCreate(
        local_part=local_part,
        domain=domain,
        password=password,
        password2=password,
    )
    mailbox = mailbox_manager.create_mailbox(mailbox_create)
    mailbox_manager.db.flush()

    address, external = unique("email", domain=domain), unique("email")
    goto = join_email(local_part, domain)
    alias_create = AliasCreate(
        address=address,
        goto=",".join([goto, external])
    )
    alias_manager.create_alias(alias_create)
    alias_manager.db.flush()

    mailbox_manager.delete_mailbox(mailbox.username)
    aliases = alias_manager.get_aliases(domain)
    assert_that(aliases, contains_exactly(has_properties(goto=external)))
    with pytest.raises(MailboxNotFoundError):
        mailbox_manager.get_mailbox_details(mailbox.username)
