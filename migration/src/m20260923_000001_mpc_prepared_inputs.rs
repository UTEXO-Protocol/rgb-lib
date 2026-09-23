use sea_orm_migration::prelude::*;
#[derive(DeriveMigrationName)]
pub struct Migration;
#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(MpcPreparedInputs::Table)
                    .col(
                        ColumnDef::new(MpcPreparedInputs::Txid)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(MpcPreparedInputs::UnsignedTx)
                            .text()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await
    }
    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(MpcPreparedInputs::Table).to_owned())
            .await
    }
}
#[derive(DeriveIden)]
enum MpcPreparedInputs {
    Table,
    Txid,
    UnsignedTx,
}
