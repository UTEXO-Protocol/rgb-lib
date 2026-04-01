use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(MpcAddress::Table)
                    .if_not_exists()
                    .col(pk_auto(MpcAddress::Idx))
                    .col(string(MpcAddress::Address))
                    .col(string(MpcAddress::ScriptPubkey))
                    .col(string(MpcAddress::SigningKeyId))
                    .col(tiny_unsigned(MpcAddress::Keychain))
                    .col(big_unsigned(MpcAddress::DerivationIndex))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(MpcAddress::Table).to_owned())
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
pub enum MpcAddress {
    Table,
    Idx,
    Address,
    ScriptPubkey,
    SigningKeyId,
    Keychain,
    DerivationIndex,
}
