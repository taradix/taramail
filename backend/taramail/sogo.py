"""SOGo functions."""

from functools import partial

from attrs import (
    define,
    field,
)
from sqlalchemy import (
    delete,
    insert,
    select,
)
from sqlalchemy.dialects.mysql import insert as mysql_insert
from sqlalchemy.sql import (
    case,
    func,
)

from taramail.db import (
    DBSession,
    DBUnsupportedDialectError,
    db_transaction,
    get_db_session,
)
from taramail.models import (
    MailboxModel,
    SogoAclModel,
    SogoCacheFolderModel,
    SogoFolderInfoModel,
    SogoQuickAppointmentModel,
    SogoQuickContactModel,
    SogoStaticView,
    SogoStoreModel,
    SogoUserProfileModel,
    UserAttributesModel,
)
from taramail.store import (
    MemcachedStore,
    Store,
)
from taramail.views import (
    GroupedDomainAliasAddressView,
    GroupedMailAliasesView,
    GroupedSenderAclExternalView,
)


@define(frozen=True)
class Sogo:

    db: DBSession
    memcached: Store = field(factory=partial(MemcachedStore.from_host, "memcached"))
    default_password: str = "{SSHA256}A123A123A321A321A321B321B321B123B123B321B432F123E321123123321321"  # noqa: S105

    def update_static_view(self, mailbox: str | None = None) -> None:

        # Conditional password logic
        password_expr = case(
            (
                UserAttributesModel.force_pw_update.is_(False),
                case(
                    (UserAttributesModel.sogo_access.is_(True), MailboxModel.password),
                    else_=self.default_password,
                ),
            ),
            else_=self.default_password,
        )

        # Aliases concatenation
        aliases_concat = func.IFNULL(func.GROUP_CONCAT(GroupedMailAliasesView.aliases), "")
        ad_aliases = func.IFNULL(GroupedDomainAliasAddressView.ad_alias, "")
        ext_acl = func.IFNULL(GroupedSenderAclExternalView.send_as_acl, "")

        select_stmt = (
            select(
                MailboxModel.username,
                MailboxModel.domain,
                MailboxModel.username,
                password_expr,
                MailboxModel.name,
                MailboxModel.username,
                aliases_concat,
                ad_aliases,
                ext_acl,
                MailboxModel.kind,
                MailboxModel.multiple_bookings,
            )
            .select_from(MailboxModel)
            .outerjoin(UserAttributesModel, MailboxModel.username == UserAttributesModel.username)
            .outerjoin(GroupedMailAliasesView, GroupedMailAliasesView.username == MailboxModel.username)
            .outerjoin(GroupedDomainAliasAddressView, MailboxModel.username == GroupedDomainAliasAddressView.username)
            .outerjoin(GroupedSenderAclExternalView, MailboxModel.username == GroupedSenderAclExternalView.username)
            .where(MailboxModel.active.is_(True))
        )

        if mailbox and self.db.scalar(
            select(MailboxModel)
            .where(MailboxModel.username == mailbox)
            .limit(1)
        ):
            select_stmt = select_stmt.where(MailboxModel.username == mailbox)
        else:
            select_stmt = select_stmt.group_by(MailboxModel.username)

        dialect = self.db.connection().dialect.name
        if dialect == "sqlite":
            upsert_stmt = insert(SogoStaticView).from_select(
                [
                    "c_uid",
                    "domain",
                    "c_name",
                    "c_password",
                    "c_cn",
                    "mail",
                    "aliases",
                    "ad_aliases",
                    "ext_acl",
                    "kind",
                    "multiple_bookings",
                ],
                select_stmt,
            ).prefix_with('OR REPLACE')
        elif dialect == "mysql":
            insert_stmt = mysql_insert(SogoStaticView).from_select(
                [
                    "c_uid",
                    "domain",
                    "c_name",
                    "c_password",
                    "c_cn",
                    "mail",
                    "aliases",
                    "ad_aliases",
                    "ext_acl",
                    "kind",
                    "multiple_bookings",
                ],
                select_stmt,
            )
            update_dict = {
                col.name: insert_stmt.inserted[col.name]
                for col in SogoStaticView.__table__.columns
                if not col.primary_key  # Usually you don't update primary keys
            }
            upsert_stmt = insert_stmt.on_duplicate_key_update(**update_dict)
        else:
            raise DBUnsupportedDialectError(f"Unsupported dialect: {dialect}")

        self.db.execute(upsert_stmt)

        self.db.execute(
            delete(SogoStaticView)
            .where(
                SogoStaticView.c_uid.not_in(
                    select(MailboxModel.username)
                    .where(MailboxModel.active == 1),
                ),
            )
        )

        self.memcached.flushall()

    def delete_user(self, username) -> None:
        self.db.execute(delete(SogoUserProfileModel).where(SogoUserProfileModel.c_uid == username))
        self.db.execute(delete(SogoCacheFolderModel).where(SogoCacheFolderModel.c_uid == username))
        # TODO: Also delete by c_object
        self.db.execute(delete(SogoAclModel).where(SogoAclModel.c_uid == username))
        folder_ids = select(SogoFolderInfoModel.c_folder_id).where(SogoFolderInfoModel.c_path2 == username)
        self.db.execute(delete(SogoStoreModel).where(SogoStoreModel.c_folder_id.in_(folder_ids)))
        self.db.execute(delete(SogoQuickContactModel).where(SogoQuickContactModel.c_folder_id.in_(folder_ids)))
        self.db.execute(delete(SogoQuickAppointmentModel).where(SogoQuickAppointmentModel.c_folder_id.in_(folder_ids)))
        self.db.execute(delete(SogoFolderInfoModel).where(SogoFolderInfoModel.c_path2 == username))


def main():
    """Rebuild the SOGo static view on startup."""
    with get_db_session() as db, db_transaction(db):
        Sogo(db).update_static_view()


if __name__ == "__main__":
    main()
