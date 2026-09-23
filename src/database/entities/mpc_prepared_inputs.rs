use sea_orm::entity::prelude::*;
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "mpc_prepared_inputs")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub txid: String,
    pub unsigned_tx: String,
}
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}
impl ActiveModelBehavior for ActiveModel {}
