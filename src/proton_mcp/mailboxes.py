"""Bridge's mailbox layout and what each mailbox is for.

Roles come from LIST's special-use attributes (Bridge sets them on its
system mailboxes); INBOX by name; user folders live under "Folders/",
labels under "Labels/" (both prefixes are \\Noselect parents). "All Mail",
"Starred" and every label are views: the same message appears there under
another UID, so default searches skip them."""

from __future__ import annotations

from dataclasses import dataclass

from .errors import InvalidArgument, NotFound

FOLDER_PREFIX = "Folders/"
LABEL_PREFIX = "Labels/"

_ROLE_ATTRS = {
    "\\drafts": "drafts",
    "\\sent": "sent",
    "\\archive": "archive",
    "\\junk": "spam",
    "\\trash": "trash",
    "\\all": "all",
    "\\flagged": "starred",
}
ROLE_KEYWORDS = ("inbox", "drafts", "sent", "archive", "spam", "trash", "all", "starred", "scheduled")
# Where a message physically lives (one Proton folder each).
REAL_ROLES = ("inbox", "archive", "sent", "drafts", "folder")
MOVE_TARGET_ROLES = ("inbox", "archive", "spam", "trash")


def is_folder(name: str) -> bool:
    return name.startswith(FOLDER_PREFIX) and len(name) > len(FOLDER_PREFIX)


def is_label(name: str) -> bool:
    return name.startswith(LABEL_PREFIX) and len(name) > len(LABEL_PREFIX)


@dataclass(frozen=True)
class Mailbox:
    name: str
    role: str  # inbox drafts sent archive spam trash all starred scheduled folder label other
    selectable: bool
    attributes: tuple[str, ...]

    @property
    def is_view(self) -> bool:
        """Messages here also live in a real folder."""
        return self.role in ("all", "starred", "label", "scheduled")


def _role(attributes: tuple[str, ...], name: str) -> str:
    attrs = {a.lower() for a in attributes}
    if name.upper() == "INBOX":
        return "inbox"
    for attr, role in _ROLE_ATTRS.items():
        if attr in attrs:
            return role
    if name == "Scheduled":
        return "scheduled"
    if is_folder(name):
        return "folder"
    if is_label(name):
        return "label"
    return "other"


class Mailboxes:
    def __init__(self, entries: list[tuple[tuple[str, ...], str]]) -> None:
        self.all: list[Mailbox] = []
        for attributes, name in entries:
            selectable = not any(a.lower() in ("\\noselect", "\\nonexistent") for a in attributes)
            self.all.append(Mailbox(name, _role(attributes, name), selectable, attributes))
        self._by_name = {m.name: m for m in self.all}

    def get(self, name: str) -> Mailbox | None:
        return self._by_name.get(name)

    def by_role(self, role: str) -> Mailbox | None:
        for m in self.all:
            if m.role == role and m.selectable:
                return m
        return None

    def selectable(self) -> list[Mailbox]:
        return [m for m in self.all if m.selectable]

    def resolve(self, spec: str) -> Mailbox:
        """A role keyword (inbox, archive, …) or an exact mailbox name."""
        key = spec.strip()
        if key.lower() in ROLE_KEYWORDS:
            m = self.by_role(key.lower())
            if m is None:
                raise NotFound(f"this account has no {key.lower()} mailbox")
            return m
        m = self.get(key)
        if m is None or not m.selectable:
            raise NotFound(f"no mailbox named {key!r} (list_mailboxes shows the names)")
        return m

    def search_default(self, include_spam_trash: bool) -> list[Mailbox]:
        roles = REAL_ROLES + (("spam", "trash") if include_spam_trash else ())
        return [m for m in self.all if m.selectable and m.role in roles]

    def real(self) -> list[Mailbox]:
        return [m for m in self.all if m.selectable and (m.role in REAL_ROLES or m.role in ("spam", "trash"))]

    def move_target(self, spec: str) -> Mailbox:
        key = spec.strip()
        if key.lower() in MOVE_TARGET_ROLES:
            return self.resolve(key.lower())
        if not is_folder(key):
            raise InvalidArgument("move to inbox, archive, spam, trash or an existing Folders/… mailbox")
        return self.resolve(key)

    def drafts(self) -> Mailbox:
        m = self.by_role("drafts")
        if m is None:
            raise NotFound("this account has no Drafts mailbox")
        return m
