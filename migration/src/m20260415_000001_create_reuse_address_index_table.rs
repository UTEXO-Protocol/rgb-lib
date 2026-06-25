use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(ReuseAddressIndex::Table)
                    .if_not_exists()
                    .col(tiny_unsigned(ReuseAddressIndex::Keychain).primary_key())
                    .col(big_unsigned(ReuseAddressIndex::DerivationIndex))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(ReuseAddressIndex::Table).to_owned())
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
pub enum ReuseAddressIndex {
    Table,
    Keychain,
    DerivationIndex,
}
