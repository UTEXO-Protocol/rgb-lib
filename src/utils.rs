//! Utilities.
//!
//! This module defines some utility methods and structures.

use super::*;
#[cfg(any(feature = "electrum", feature = "esplora"))]
use rgbstd::contract::LinkableIssuerWrapper;

const TIMESTAMP_FORMAT: &[time::format_description::BorrowedFormatItem] = time::macros::format_description!(
    "[year]-[month]-[day]T[hour repr:24]:[minute]:[second].[subsecond digits:3]+00"
);

const RGB_RUNTIME_LOCK_FILE: &str = "rgb_runtime.lock";

pub(crate) const RGB_RUNTIME_DIR: &str = "rgb";
pub(crate) const LOG_FILE: &str = "log";

pub(crate) const PURPOSE: u8 = 86;
pub(crate) const COIN_RGB_MAINNET: u32 = 827166;
pub(crate) const COIN_RGB_TESTNET: u32 = 827167;
pub(crate) const ACCOUNT: u8 = 0;
pub(crate) const KEYCHAIN_RGB: u8 = 0;
pub(crate) const KEYCHAIN_BTC: u8 = 0;

#[cfg(any(feature = "electrum", feature = "esplora"))]
pub(crate) const INDEXER_STOP_GAP: usize = 20;
#[cfg(any(feature = "electrum", feature = "esplora"))]
pub(crate) const INDEXER_TIMEOUT: u64 = 10;
#[cfg(any(feature = "electrum", feature = "esplora"))]
pub(crate) const INDEXER_RETRIES: u8 = 3;
#[cfg(feature = "electrum")]
pub(crate) const INDEXER_BATCH_SIZE: usize = 5;
#[cfg(feature = "esplora")]
pub(crate) const INDEXER_PARALLEL_REQUESTS: usize = 5;

#[cfg(any(feature = "electrum", feature = "esplora"))]
const PROXY_PROTOCOL_VERSION: &str = "0.2";

#[cfg(test)]
const LOCK_FILE_TIMEOUT_SECS: f32 = 1.0;
#[cfg(not(test))]
const LOCK_FILE_TIMEOUT_SECS: f32 = 3600.0;

// sea-orm with runtime-tokio-rustls needs a tokio runtime for connection pool management
static TOKIO_RUNTIME: LazyLock<tokio::runtime::Runtime> =
    LazyLock::new(|| tokio::runtime::Runtime::new().expect("failed to create the runtime"));

/// Block on a future, spawning a new thread if already inside a Tokio runtime.
pub fn block_on<F>(future: F) -> F::Output
where
    F: std::future::Future + Send,
    F::Output: Send,
{
    if tokio::runtime::Handle::try_current().is_ok() {
        // avoid blocking the Tokio runtime thread; spawn a new thread
        std::thread::scope(|s| {
            s.spawn(|| TOKIO_RUNTIME.block_on(future))
                .join()
                .expect("rgb-lib block_on thread panicked")
        })
    } else {
        TOKIO_RUNTIME.block_on(future)
    }
}

/// Supported Bitcoin networks.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub enum BitcoinNetwork {
    /// Bitcoin's mainnet
    Mainnet,
    /// Bitcoin's testnet3
    Testnet,
    /// Bitcoin's testnet4
    Testnet4,
    /// Bitcoin's default signet
    Signet,
    /// Bitcoin's regtest
    Regtest,
    /// Bitcoin's custom signet
    SignetCustom,
}

impl BitcoinNetwork {
    pub(crate) fn network_kind(&self) -> NetworkKind {
        match self {
            BitcoinNetwork::Mainnet => NetworkKind::Main,
            _ => NetworkKind::Test,
        }
    }
}

impl fmt::Display for BitcoinNetwork {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl FromStr for BitcoinNetwork {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_lowercase().as_str() {
            "mainnet" | "bitcoin" => BitcoinNetwork::Mainnet,
            "testnet" | "testnet3" => BitcoinNetwork::Testnet,
            "testnet4" => BitcoinNetwork::Testnet4,
            "regtest" => BitcoinNetwork::Regtest,
            "signet" => BitcoinNetwork::Signet,
            "signetcustom" => BitcoinNetwork::SignetCustom,
            _ => {
                return Err(Error::InvalidBitcoinNetwork {
                    network: s.to_string(),
                });
            }
        })
    }
}

impl TryFrom<ChainNet> for BitcoinNetwork {
    type Error = Error;

    fn try_from(x: ChainNet) -> Result<Self, Self::Error> {
        match x {
            ChainNet::BitcoinMainnet => Ok(BitcoinNetwork::Mainnet),
            ChainNet::BitcoinTestnet3 => Ok(BitcoinNetwork::Testnet),
            ChainNet::BitcoinTestnet4 => Ok(BitcoinNetwork::Testnet4),
            ChainNet::BitcoinSignet => Ok(BitcoinNetwork::Signet),
            ChainNet::BitcoinRegtest => Ok(BitcoinNetwork::Regtest),
            ChainNet::BitcoinSignetCustom => Ok(BitcoinNetwork::SignetCustom),
            _ => Err(Error::UnsupportedLayer1 {
                layer_1: x.layer1().to_string(),
            }),
        }
    }
}

impl From<BitcoinNetwork> for bitcoin::Network {
    fn from(x: BitcoinNetwork) -> bitcoin::Network {
        match x {
            BitcoinNetwork::Mainnet => bitcoin::Network::Bitcoin,
            BitcoinNetwork::Testnet => bitcoin::Network::Testnet,
            BitcoinNetwork::Testnet4 => bitcoin::Network::Testnet4,
            BitcoinNetwork::Signet => bitcoin::Network::Signet,
            BitcoinNetwork::Regtest => bitcoin::Network::Regtest,
            BitcoinNetwork::SignetCustom => bitcoin::Network::Signet,
        }
    }
}

impl From<BitcoinNetwork> for NetworkKind {
    fn from(x: BitcoinNetwork) -> Self {
        match x {
            BitcoinNetwork::Mainnet => Self::Main,
            _ => Self::Test,
        }
    }
}

impl From<BitcoinNetwork> for ChainNet {
    fn from(x: BitcoinNetwork) -> ChainNet {
        match x {
            BitcoinNetwork::Mainnet => ChainNet::BitcoinMainnet,
            BitcoinNetwork::Testnet => ChainNet::BitcoinTestnet3,
            BitcoinNetwork::Testnet4 => ChainNet::BitcoinTestnet4,
            BitcoinNetwork::Signet => ChainNet::BitcoinSignet,
            BitcoinNetwork::Regtest => ChainNet::BitcoinRegtest,
            BitcoinNetwork::SignetCustom => ChainNet::BitcoinSignetCustom,
        }
    }
}

#[cfg(not(target_os = "windows"))]
pub(crate) fn adjust_canonicalization<P: AsRef<Path>>(p: P) -> String {
    p.as_ref().display().to_string()
}

#[cfg(target_os = "windows")]
pub(crate) fn adjust_canonicalization<P: AsRef<Path>>(p: P) -> String {
    const VERBATIM_PREFIX: &str = r#"\\?\"#;
    let p = p.as_ref().display().to_string();
    if p.starts_with(VERBATIM_PREFIX) {
        p[VERBATIM_PREFIX.len()..].to_string()
    } else {
        p
    }
}

fn deserialize_str_or_number<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: FromStr + Copy,
    T::Err: fmt::Display,
{
    struct StringOrNumberVisitor<T>(std::marker::PhantomData<T>);

    impl<T> Visitor<'_> for StringOrNumberVisitor<T>
    where
        T: FromStr + Copy,
        T::Err: fmt::Display,
    {
        type Value = Option<T>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a string, a number, or null")
        }

        fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            T::from_str(&value.to_string())
                .map(Some)
                .map_err(de::Error::custom)
        }

        fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            T::from_str(&value.to_string())
                .map(Some)
                .map_err(de::Error::custom)
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            value.parse::<T>().map(Some).map_err(|e| {
                de::Error::invalid_value(Unexpected::Str(value), &e.to_string().as_str())
            })
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(None)
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(None)
        }
    }

    deserializer.deserialize_any(StringOrNumberVisitor(std::marker::PhantomData))
}

pub(crate) fn from_str_or_number_mandatory<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: FromStr + Copy,
    T::Err: fmt::Display,
{
    match deserialize_str_or_number(deserializer)? {
        Some(val) => Ok(val),
        None => Err(de::Error::custom("expected a number but got null")),
    }
}

pub(crate) fn from_str_or_number_optional<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: FromStr + Copy,
    T::Err: fmt::Display,
{
    deserialize_str_or_number(deserializer)
}

pub(crate) fn str_to_xpub(xpub: &str, network_kind: &NetworkKind) -> Result<Xpub, Error> {
    let pubkey_btc = Xpub::from_str(xpub)?;
    let extended_key_btc: ExtendedKey = ExtendedKey::from(pubkey_btc);
    Ok(extended_key_btc.into_xpub(*network_kind, &Secp256k1::new()))
}

pub(crate) fn get_coin_type(bitcoin_network: &BitcoinNetwork, rgb: bool) -> u32 {
    match (bitcoin_network, rgb) {
        (BitcoinNetwork::Mainnet, true) => COIN_RGB_MAINNET,
        (_, true) => COIN_RGB_TESTNET,
        (_, false) => u32::from(*bitcoin_network != BitcoinNetwork::Mainnet),
    }
}

/// Where the two sides of a singlesig wallet live, resolved against the wallet network.
///
/// The default is rgb-lib's standard layout: the colored side on its own coin type
/// (827166' on mainnet, 827167' elsewhere) at keychain 0, the vanilla side on the standard
/// Bitcoin coin type (0'/1') at keychain 0 or the requested `vanilla_keychain`.
///
/// Hosts whose signer can only export the standard BIP-86 account (hardware wallets) can put
/// both sides under that one account by overriding the colored coin type and choosing two
/// distinct keychain indexes (see [`KeychainLayoutOverrides`]). The layout is purely local:
/// invoices, consignments, ACKs and witness transactions never carry derivation paths, so
/// singlesig transfers interoperate with wallets that use the default layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KeychainLayout {
    pub(crate) colored_coin_type: u32,
    pub(crate) vanilla_coin_type: u32,
    pub(crate) colored_keychain: u8,
    pub(crate) vanilla_keychain: u8,
}

impl KeychainLayout {
    pub(crate) fn resolve(
        bitcoin_network: &BitcoinNetwork,
        overrides: &KeychainLayoutOverrides,
        vanilla_keychain: Option<u8>,
    ) -> Result<Self, Error> {
        let layout = Self {
            colored_coin_type: overrides
                .colored_coin_type
                .unwrap_or(get_coin_type(bitcoin_network, true)),
            vanilla_coin_type: overrides
                .vanilla_coin_type
                .unwrap_or(get_coin_type(bitcoin_network, false)),
            colored_keychain: overrides.colored_keychain.unwrap_or(KEYCHAIN_RGB),
            vanilla_keychain: vanilla_keychain.unwrap_or(KEYCHAIN_BTC),
        };
        for (side, coin_type) in [
            ("colored", layout.colored_coin_type),
            ("vanilla", layout.vanilla_coin_type),
        ] {
            if ChildNumber::from_hardened_idx(coin_type).is_err() {
                return Err(Error::InvalidKeychainLayout {
                    details: format!("{side} coin type {coin_type} is not a valid hardened index"),
                });
            }
        }
        if layout.colored_coin_type == layout.vanilla_coin_type
            && layout.colored_keychain == layout.vanilla_keychain
        {
            // one keychain would feed both BDK keychains: colored UTXOs would be spendable as
            // vanilla ones and RGB allocations could be burnt by a plain BTC send
            return Err(Error::InvalidKeychainLayout {
                details: s!("colored and vanilla sides resolve to the same keychain"),
            });
        }
        Ok(layout)
    }
}

pub(crate) fn get_account_derivation_children(
    witness_version: WitnessVersion,
    coin_type: u32,
) -> Vec<ChildNumber> {
    vec![
        ChildNumber::from_hardened_idx(witness_version.purpose()).unwrap(),
        ChildNumber::from_hardened_idx(coin_type).unwrap(),
        ChildNumber::from_hardened_idx(ACCOUNT as u32).unwrap(),
    ]
}

fn derive_account_xprv_from_mnemonic(
    bitcoin_network: &BitcoinNetwork,
    mnemonic: &str,
    coin_type: u32,
    witness_version: WitnessVersion,
) -> Result<(Xpriv, Fingerprint), Error> {
    let account_derivation_children = get_account_derivation_children(witness_version, coin_type);
    let mnemonic = Mnemonic::parse_in(Language::English, mnemonic.to_string())?;
    let master_xprv = Xpriv::new_master(*bitcoin_network, &mnemonic.to_seed("")).unwrap();
    let master_xpub = Xpub::from_priv(&Secp256k1::new(), &master_xprv);
    let master_fingerprint = master_xpub.fingerprint();
    let account_xprv = master_xprv.derive_priv(&Secp256k1::new(), &account_derivation_children)?;
    Ok((account_xprv, master_fingerprint))
}

fn get_xpub_from_xprv(xprv: &Xpriv) -> Xpub {
    Xpub::from_priv(&Secp256k1::new(), xprv)
}

/// Get the account-level xPriv and xPub for the given mnemonic, Bitcoin network and witness
/// version, based on the requested wallet side (colored or vanilla).
pub fn get_account_data(
    bitcoin_network: &BitcoinNetwork,
    mnemonic: &str,
    rgb: bool,
    witness_version: WitnessVersion,
) -> Result<(Xpriv, Xpub, Fingerprint), Error> {
    get_account_data_at_coin_type(
        bitcoin_network,
        mnemonic,
        get_coin_type(bitcoin_network, rgb),
        witness_version,
    )
}

/// Get the account-level xPriv and xPub for the given mnemonic, Bitcoin network, coin type and
/// witness version.
///
/// Use this to prepare [`crate::wallet::SinglesigKeys`] for a non-default keychain layout
/// (see `colored_coin_type` / `vanilla_coin_type`).
pub fn get_account_data_at_coin_type(
    bitcoin_network: &BitcoinNetwork,
    mnemonic: &str,
    coin_type: u32,
    witness_version: WitnessVersion,
) -> Result<(Xpriv, Xpub, Fingerprint), Error> {
    let (account_xprv, master_fingerprint) =
        derive_account_xprv_from_mnemonic(bitcoin_network, mnemonic, coin_type, witness_version)?;
    let account_xpub = get_xpub_from_xprv(&account_xprv);
    Ok((account_xprv, account_xpub, master_fingerprint))
}

pub(crate) fn get_account_xpubs(
    bitcoin_network: &BitcoinNetwork,
    mnemonic: &str,
    witness_version: WitnessVersion,
) -> Result<(Xpub, Xpub), Error> {
    let (_, account_xpub_vanilla, _) =
        get_account_data(bitcoin_network, mnemonic, false, witness_version)?;
    let (_, account_xpub_colored, _) =
        get_account_data(bitcoin_network, mnemonic, true, witness_version)?;
    Ok((account_xpub_vanilla, account_xpub_colored))
}

fn derive_descriptor(
    bitcoin_network: &BitcoinNetwork,
    mnemonic: &str,
    coin_type: u32,
    keychain: u8,
    expected_xpub: &Xpub,
    witness_version: WitnessVersion,
) -> Result<String, Error> {
    let (account_xprv, account_xpub, master_fingerprint) =
        get_account_data_at_coin_type(bitcoin_network, mnemonic, coin_type, witness_version)?;
    if account_xpub != *expected_xpub {
        return Err(Error::InvalidBitcoinKeys);
    }
    calculate_descriptor_from_xprv(
        &master_fingerprint,
        coin_type,
        account_xprv,
        keychain,
        witness_version,
    )
}

pub(crate) fn get_descriptors(
    bitcoin_network: &BitcoinNetwork,
    mnemonic: &str,
    layout: &KeychainLayout,
    expected_xpub_btc: &Xpub,
    expected_xpub_rgb: &Xpub,
    witness_version: WitnessVersion,
) -> Result<WalletDescriptors, Error> {
    let colored = derive_descriptor(
        bitcoin_network,
        mnemonic,
        layout.colored_coin_type,
        layout.colored_keychain,
        expected_xpub_rgb,
        witness_version,
    )?;
    let vanilla = derive_descriptor(
        bitcoin_network,
        mnemonic,
        layout.vanilla_coin_type,
        layout.vanilla_keychain,
        expected_xpub_btc,
        witness_version,
    )?;
    Ok(WalletDescriptors { colored, vanilla })
}

pub(crate) fn get_descriptors_from_xpubs(
    master_fingerprint: &str,
    xpub_rgb: &Xpub,
    xpub_btc: &Xpub,
    layout: &KeychainLayout,
    witness_version: WitnessVersion,
) -> Result<WalletDescriptors, Error> {
    let master_fingerprint =
        Fingerprint::from_str(master_fingerprint).map_err(|_| Error::InvalidFingerprint)?;
    let colored = calculate_descriptor_from_xpub(
        &master_fingerprint,
        layout.colored_coin_type,
        xpub_rgb,
        layout.colored_keychain,
        witness_version,
    )?;
    let vanilla = calculate_descriptor_from_xpub(
        &master_fingerprint,
        layout.vanilla_coin_type,
        xpub_btc,
        layout.vanilla_keychain,
        witness_version,
    )?;
    Ok(WalletDescriptors { colored, vanilla })
}

pub(crate) fn parse_address_str(
    address: &str,
    bitcoin_network: BitcoinNetwork,
) -> Result<BdkAddress, Error> {
    BdkAddress::from_str(address)
        .map_err(|e| Error::InvalidAddress {
            details: e.to_string(),
        })?
        .require_network(bitcoin_network.into())
        .map_err(|_| Error::InvalidAddress {
            details: s!("belongs to another network"),
        })
}

/// Extract the witness script if recipient is a Witness one
pub fn script_buf_from_recipient_id(recipient_id: String) -> Result<Option<ScriptBuf>, Error> {
    let xchainnet_beneficiary =
        XChainNet::<Beneficiary>::from_str(&recipient_id).map_err(|_| Error::InvalidRecipientID)?;
    match xchainnet_beneficiary.into_inner() {
        Beneficiary::WitnessVout(pay_2_vout, _) => {
            let script_buf = pay_2_vout.to_script();
            Ok(Some(script_buf))
        }
        Beneficiary::BlindedSeal(_) => Ok(None),
    }
}

pub(crate) fn beneficiary_from_script_buf(script_buf: ScriptBuf) -> Result<Beneficiary, Error> {
    let address_payload =
        AddressPayload::from_script(&script_buf).map_err(|e| Error::InvalidAddress {
            details: e.to_string(),
        })?;
    Ok(Beneficiary::WitnessVout(
        Pay2Vout::new(address_payload),
        None,
    ))
}

/// Return the recipient ID for a specific script buf
pub fn recipient_id_from_script_buf(
    script_buf: ScriptBuf,
    bitcoin_network: BitcoinNetwork,
) -> Result<String, Error> {
    let beneficiary = beneficiary_from_script_buf(script_buf)?;
    Ok(XChainNet::with(bitcoin_network.into(), beneficiary).to_string())
}

fn get_derivation_path(keychain: u8) -> DerivationPath {
    let derivation_path = vec![ChildNumber::from_normal_idx(keychain as u32).unwrap()];
    DerivationPath::from_iter(derivation_path.clone())
}

pub(crate) fn get_extended_derivation_path(
    mut account_derivation_children: Vec<ChildNumber>,
    keychain: u8,
) -> DerivationPath {
    let keychain_child = ChildNumber::from_normal_idx(keychain as u32).unwrap();
    account_derivation_children.push(keychain_child);
    DerivationPath::from_iter(account_derivation_children.clone())
}

pub(crate) fn calculate_descriptor_from_xprv(
    master_fingerprint: &Fingerprint,
    coin_type: u32,
    xprv: Xpriv,
    keychain: u8,
    witness_version: WitnessVersion,
) -> Result<String, Error> {
    // derive final xpub from account-level xpub
    let path = get_derivation_path(keychain);
    let der_xprv = &xprv
        .derive_priv(&Secp256k1::new(), &path)
        .expect("provided path should be derivable in an xprv");
    // derive descriptor with master fingerprint and full derivation path
    let account_derivation_children = get_account_derivation_children(witness_version, coin_type);
    let full_path = get_extended_derivation_path(account_derivation_children, keychain);
    let origin_prv: KeySource = (*master_fingerprint, full_path.clone());
    let der_xprv_desc_key: DescriptorKey<Segwitv0> = der_xprv
        .into_descriptor_key(Some(origin_prv), DerivationPath::default())
        .expect("should be able to convert xprv in a descriptor key");
    let Secret(key, _, _) = der_xprv_desc_key else {
        unreachable!("into_descriptor_key on an Xpriv always yields a Secret variant")
    };
    Ok(format!("{}({key})", witness_version.descriptor_fn()))
}

pub(crate) fn calculate_descriptor_from_xpub(
    master_fingerprint: &Fingerprint,
    coin_type: u32,
    xpub: &Xpub,
    keychain: u8,
    witness_version: WitnessVersion,
) -> Result<String, Error> {
    // derive final xpub from account-level xpub
    let path = get_derivation_path(keychain);
    let der_xpub = xpub
        .derive_pub(&Secp256k1::new(), &path)
        .expect("provided path should be derivable in an xpub");
    // derive descriptor with master fingerprint and full derivation path
    let account_derivation_children = get_account_derivation_children(witness_version, coin_type);
    let full_path = get_extended_derivation_path(account_derivation_children, keychain);
    let origin_pub: KeySource = (*master_fingerprint, full_path);
    let der_xpub_desc_key: DescriptorKey<Segwitv0> = der_xpub
        .into_descriptor_key(Some(origin_pub), DerivationPath::default())
        .expect("should be able to convert xpub in a descriptor key");
    let Public(key, _, _) = der_xpub_desc_key else {
        unreachable!("into_descriptor_key on an Xpub always yields a Public variant")
    };
    Ok(format!("{}({key})", witness_version.descriptor_fn()))
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
pub(crate) fn check_proxy(proxy_url: &str) -> Result<(), Error> {
    let proxy_client = ProxyClient::new(proxy_url)?;
    let mut err_details = s!("unable to connect to proxy");
    if let Ok(server_info) = proxy_client.get_info() {
        if let Some(info) = server_info.result {
            if info.protocol_version == *PROXY_PROTOCOL_VERSION {
                return Ok(());
            } else {
                return Err(Error::InvalidProxyProtocol {
                    version: info.protocol_version,
                });
            }
        }
        if let Some(err) = server_info.error {
            err_details = err.message;
        }
    };
    Err(Error::Proxy {
        details: err_details,
    })
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
pub(crate) fn get_indexer_and_resolver(
    indexer_url: &str,
    bitcoin_network: BitcoinNetwork,
) -> Result<(Indexer, AnyResolver), Error> {
    // detect indexer type
    let indexer = build_indexer(indexer_url);
    let mut invalid_indexer = true;
    if let Some(ref indexer) = indexer {
        invalid_indexer = indexer.block_hash(0).is_err();
    }
    if invalid_indexer {
        return Err(Error::InvalidIndexer {
            details: s!("not a valid electrum nor esplora server"),
        });
    }
    let indexer = indexer.unwrap();

    let resolver = match indexer {
        #[cfg(feature = "electrum")]
        Indexer::Electrum(_) => {
            let electrum_config = ConfigBuilder::new()
                .retry(INDEXER_RETRIES)
                .timeout(Some(Duration::from_secs(INDEXER_TIMEOUT)))
                .build();
            AnyResolver::electrum_blocking(indexer_url, Some(electrum_config)).expect(
                "electrum_blocking uses the same config as build_indexer which already succeeded",
            )
        }
        #[cfg(feature = "esplora")]
        Indexer::Esplora(_) => {
            let esplora_config = EsploraBuilder::new(indexer_url)
                .max_retries(INDEXER_RETRIES.into())
                .timeout(INDEXER_TIMEOUT);
            AnyResolver::esplora_blocking(esplora_config)
                .expect("esplora_blocking wraps an infallible builder and always returns Ok")
        }
    };

    resolver
        .check_chain_net(bitcoin_network.into())
        .map_err(|e| Error::InvalidIndexer {
            details: e.to_string(),
        })?;

    Ok((indexer, resolver))
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
pub(crate) fn build_indexer(indexer_url: &str) -> Option<Indexer> {
    #[cfg(feature = "electrum")]
    {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let opts = ConfigBuilder::new()
            .retry(INDEXER_RETRIES)
            .timeout(Some(Duration::from_secs(INDEXER_TIMEOUT)))
            .build();
        if let Ok(client) = ElectrumClient::from_config(indexer_url, opts) {
            let client = BdkElectrumClient::new(client);
            let indexer = Indexer::Electrum(Box::new(client));
            return Some(indexer);
        }
    }
    if cfg!(feature = "esplora") {
        #[cfg(feature = "esplora")]
        {
            let opts = EsploraBuilder::new(indexer_url)
                .max_retries(INDEXER_RETRIES.into())
                .timeout(INDEXER_TIMEOUT);
            let client = EsploraClient::from_builder(opts);
            let indexer = Indexer::Esplora(Box::new(client));
            return Some(indexer);
        }
    }
    None
}

pub(crate) fn hash_bytes(data: &[u8]) -> Vec<u8> {
    <sha256::Hash as Sha256Hash>::hash(data)
        .to_byte_array()
        .to_vec()
}

pub(crate) fn hash_bytes_hex(data: &[u8]) -> String {
    hex::encode(hash_bytes(data))
}

/// Derive the proxy routing key for a witness recipient.
///
/// `recipient_id` is the RGB Beneficiary string emitted by the wallet (today,
/// derived from the pinned External script). `nonce` is per-invoice random
/// bytes. When `nonce` is empty, returns `recipient_id` unchanged (legacy
/// path for in-flight transfers issued before this fix).
pub(crate) fn derive_proxy_recipient_id(recipient_id: &str, nonce: &[u8]) -> String {
    if nonce.is_empty() {
        return recipient_id.to_string();
    }
    let mut buf = Vec::with_capacity(recipient_id.len() + nonce.len());
    buf.extend_from_slice(recipient_id.as_bytes());
    buf.extend_from_slice(nonce);
    hash_bytes_hex(&buf)
}

const RECIPIENT_NONCE_PARAM: &str = "rid_nonce";

/// Append the per-invoice `rid_nonce=<hex>` query parameter to a transport
/// endpoint URL. Used by the receiver side when emitting witness invoices.
pub(crate) fn append_recipient_nonce(url: &str, nonce: &[u8]) -> String {
    let separator = if url.contains('?') { '&' } else { '?' };
    format!(
        "{url}{separator}{RECIPIENT_NONCE_PARAM}={}",
        hex::encode(nonce)
    )
}

/// Extract the `rid_nonce` query parameter from a transport endpoint URL.
/// Returns `(bare_url_with_other_params, nonce_bytes_if_present)`.
pub(crate) fn extract_recipient_nonce(url: &str) -> (String, Option<Vec<u8>>) {
    let Some(qpos) = url.find('?') else {
        return (url.to_string(), None);
    };
    let (base, query) = url.split_at(qpos);
    let query = &query[1..];
    let prefix = format!("{RECIPIENT_NONCE_PARAM}=");
    let mut kept: Vec<&str> = Vec::new();
    let mut found: Option<Vec<u8>> = None;
    for pair in query.split('&') {
        if let Some(value) = pair.strip_prefix(prefix.as_str())
            && let Ok(bytes) = hex::decode(value)
        {
            found = Some(bytes);
            continue;
        }
        kept.push(pair);
    }
    let rebuilt = if kept.is_empty() {
        base.to_string()
    } else {
        format!("{base}?{}", kept.join("&"))
    };
    (rebuilt, found)
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
pub(crate) fn hash_file(path: &Path) -> Result<String, Error> {
    let mut file = fs::File::open(path)?;
    let mut engine = sha256::HashEngine::default();
    let mut buffer = [0u8; 8192];
    while let Ok(n) = file.read(&mut buffer) {
        if n == 0 {
            break;
        }
        engine.input(&buffer[..n]);
    }
    Ok(sha256::Hash::from_engine(engine).to_string())
}

fn log_timestamp(io: &mut dyn io::Write) -> io::Result<()> {
    let now: time::OffsetDateTime = now();
    write!(
        io,
        "{}",
        now.format(TIMESTAMP_FORMAT)
            .expect("OffsetDateTime::format with a static format description is infallible")
    )
}

pub(crate) fn setup_logger<P: AsRef<Path>>(
    log_path: P,
    log_name: Option<&str>,
) -> Result<(Logger, AsyncGuard), Error> {
    let log_file = log_name.unwrap_or(LOG_FILE);
    let log_filepath = log_path.as_ref().join(log_file);
    let file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_filepath)?;

    let decorator = PlainDecorator::new(file);
    let drain = FullFormat::new(decorator)
        .use_custom_timestamp(log_timestamp)
        .use_file_location();
    let (drain, async_guard) = slog_async::Async::new(drain.build().fuse()).build_with_guard();
    let logger = Logger::root(drain.fuse(), o!());

    Ok((logger, async_guard))
}

pub(crate) fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

pub(crate) struct DumbResolver;

impl ResolveWitness for DumbResolver {
    fn resolve_witness(&self, _: &PubWitness) -> Result<WitnessStatus, WitnessResolverError> {
        unreachable!()
    }

    fn check_chain_net(&self, _: ChainNet) -> Result<(), WitnessResolverError> {
        Ok(())
    }
}

/// Wrapper for the RGB stock and its lockfile.
#[doc(hidden)]
#[derive(Debug)]
pub struct RgbRuntime {
    /// The RGB stock
    stock: Stock,
    /// The wallet directory, where the lockfile for the runtime is to be held
    wallet_dir: PathBuf,
    /// Whether dropping the runtime should persist the in-memory stock.
    persist_on_drop: bool,
}

impl RgbRuntime {
    /// Opt out of the legacy drop-time persistence path for a mutation whose errors must be
    /// observable by the caller.
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub(crate) fn require_explicit_persistence(&mut self) {
        self.persist_on_drop = false;
    }

    /// Persist the RGB stock and propagate storage failures to the caller.
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub(crate) fn persist(&mut self) -> Result<(), Error> {
        self.persist_on_drop = false;
        self.stock.store().map_err(|error| Error::IO {
            details: error.to_string(),
        })
    }

    pub(crate) fn export_contract(
        &self,
        contract_id: ContractId,
    ) -> Result<RgbContract, InternalError> {
        self.stock
            .export_contract(contract_id)
            .map_err(InternalError::from)
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub(crate) fn accept_transfer<R: ResolveWitness>(
        &mut self,
        contract: ValidTransfer,
        resolver: &R,
    ) -> Result<(), InternalError> {
        self.stock
            .accept_transfer(contract, resolver)
            .map_err(InternalError::from)
    }

    pub(crate) fn consume_fascia(
        &mut self,
        fascia: Fascia,
        witness_ord: Option<WitnessOrd>,
    ) -> Result<(), InternalError> {
        struct FasciaResolver {
            witness_id: RgbTxid,
            witness_ord: WitnessOrd,
        }
        impl WitnessOrdProvider for FasciaResolver {
            fn witness_ord(&self, witness_id: RgbTxid) -> Result<WitnessOrd, WitnessResolverError> {
                debug_assert_eq!(witness_id, self.witness_id);
                Ok(self.witness_ord)
            }
        }

        let resolver = FasciaResolver {
            witness_id: fascia.witness_id(),
            witness_ord: witness_ord.unwrap_or(WitnessOrd::Tentative),
        };

        self.stock
            .consume_fascia(fascia, resolver)
            .map_err(InternalError::from)
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub(crate) fn contracts(&self) -> Result<Vec<ContractInfo>, InternalError> {
        Ok(self
            .stock
            .contracts()
            .map_err(InternalError::from)?
            .collect())
    }

    pub(crate) fn contract_wrapper<C: IssuerWrapper>(
        &self,
        contract_id: ContractId,
    ) -> Result<C::Wrapper<MemContract<&MemContractState>>, InternalError> {
        self.stock
            .contract_wrapper::<C>(contract_id)
            .map_err(InternalError::from)
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub(crate) fn contracts_assigning(
        &self,
        outputs: impl IntoIterator<Item = impl Into<OutPoint>>,
    ) -> Result<BTreeSet<ContractId>, InternalError> {
        Ok(FromIterator::from_iter(
            self.stock
                .contracts_assigning(outputs)
                .map_err(InternalError::from)?,
        ))
    }

    pub(crate) fn genesis(&self, contract_id: ContractId) -> Result<&Genesis, InternalError> {
        self.stock
            .as_stash_provider()
            .genesis(contract_id)
            .map_err(InternalError::from)
    }

    pub(crate) fn import_contract<R: ResolveWitness>(
        &mut self,
        contract: ValidContract,
        resolver: &R,
    ) -> Result<(), InternalError> {
        self.stock
            .import_contract(contract, resolver)
            .map_err(InternalError::from)
    }

    pub(crate) fn import_kit(&mut self, kit: ValidKit) -> Result<Status, InternalError> {
        self.stock.import_kit(kit).map_err(InternalError::from)
    }

    pub(crate) fn contract_assignments_for(
        &self,
        contract_id: ContractId,
        outpoints: impl IntoIterator<Item = impl Into<OutPoint>>,
    ) -> Result<HashMap<OutputSeal, HashMap<Opout, AllocatedState>>, InternalError> {
        self.stock
            .contract_assignments_for(contract_id, outpoints)
            .map_err(InternalError::from)
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub(crate) fn contract_schema(
        &self,
        contract_id: ContractId,
    ) -> Result<&Schema, InternalError> {
        self.stock
            .as_stash_provider()
            .contract_schema(contract_id)
            .map_err(InternalError::from)
    }

    pub(crate) fn schemata(&self) -> Result<Vec<SchemaInfo>, InternalError> {
        Ok(self
            .stock
            .schemata()
            .map_err(InternalError::from)?
            .collect())
    }

    pub(crate) fn seal_secret(
        &mut self,
        secret: SecretSeal,
    ) -> Result<Option<GraphSeal>, InternalError> {
        self.stock
            .as_stash_provider()
            .seal_secret(secret)
            .map_err(InternalError::from)
    }

    pub(crate) fn store_secret_seal(&mut self, seal: GraphSeal) -> Result<bool, InternalError> {
        self.stock
            .store_secret_seal(seal)
            .map_err(InternalError::from)
    }

    pub(crate) fn transfer_from_fascia(
        &self,
        contract_id: ContractId,
        outputs: impl AsRef<[OutputSeal]>,
        secret_seals: impl AsRef<[SecretSeal]>,
        opids: impl IntoIterator<Item = OpId>,
        fascia: &Fascia,
    ) -> Result<RgbTransfer, InternalError> {
        self.stock
            .transfer_from_fascia(contract_id, outputs, secret_seals, opids, fascia)
            .map_err(InternalError::from)
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub(crate) fn transfer_from_fascia_with_dag(
        &self,
        contract_id: ContractId,
        outputs: impl AsRef<[OutputSeal]>,
        secret_seals: impl AsRef<[SecretSeal]>,
        fascia: &Fascia,
    ) -> Result<(RgbTransfer, OpoutsDagData), InternalError> {
        self.stock
            .transfer_from_fascia_with_dag(contract_id, outputs, secret_seals, [], fascia)
            .map_err(InternalError::from)
    }

    pub(crate) fn transition_builder(
        &self,
        contract_id: ContractId,
        transition_name: impl Into<FieldName>,
    ) -> Result<TransitionBuilder, InternalError> {
        self.stock
            .transition_builder(contract_id, transition_name)
            .map_err(InternalError::from)
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub(crate) fn transition_builder_raw(
        &self,
        contract_id: ContractId,
        transition_type: TransitionType,
    ) -> Result<TransitionBuilder, InternalError> {
        self.stock
            .transition_builder_raw(contract_id, transition_type)
            .map_err(InternalError::from)
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub(crate) fn update_witnesses<R: ResolveWitness>(
        &mut self,
        resolver: &R,
        after_height: u32,
        force_witnesses: Vec<RgbTxid>,
    ) -> Result<UpdateRes, InternalError> {
        self.stock
            .update_witnesses(resolver, after_height, force_witnesses)
            .map_err(InternalError::from)
    }

    pub(crate) fn upsert_witness(
        &mut self,
        witness_id: RgbTxid,
        witness_ord: WitnessOrd,
    ) -> Result<(), InternalError> {
        self.stock.upsert_witness(witness_id, witness_ord)?;
        Ok(())
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn validate_contracts_link<Parent: LinkableIssuerWrapper, Child: LinkableIssuerWrapper>(
        &self,
        parent_contract_id: ContractId,
        child_contract_id: ContractId,
    ) -> Result<(), Error> {
        self.stock
            .validate_contracts_link::<Parent, Child>(parent_contract_id, child_contract_id)
            .map_err(InternalError::from)
            .map_err(Error::from)
    }
}

impl Drop for RgbRuntime {
    fn drop(&mut self) {
        if self.persist_on_drop {
            self.stock.store().expect("unable to save stock");
        }
        fs::remove_file(self.wallet_dir.join(RGB_RUNTIME_LOCK_FILE))
            .expect("should be able to drop lockfile")
    }
}

fn write_rgb_runtime_lockfile(wallet_dir: &Path) -> Result<(), Error> {
    let lock_file_path = wallet_dir.join(RGB_RUNTIME_LOCK_FILE);
    let t_0 = OffsetDateTime::now_utc();
    loop {
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(lock_file_path.clone())
        {
            Ok(_) => return Ok(()),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > LOCK_FILE_TIMEOUT_SECS {
                    return Err(Error::Internal {
                        details: s!("unreleased lock file"),
                    });
                } else {
                    std::thread::sleep(std::time::Duration::from_millis(400))
                }
            }
            Err(e) => {
                return Err(Error::IO {
                    details: e.to_string(),
                });
            }
        }
    }
}

pub(crate) fn load_rgb_runtime<P: AsRef<Path>>(wallet_dir: P) -> Result<RgbRuntime, Error> {
    write_rgb_runtime_lockfile(wallet_dir.as_ref())?;

    let rgb_dir = wallet_dir.as_ref().join(RGB_RUNTIME_DIR);
    if !rgb_dir.exists() {
        fs::create_dir_all(&rgb_dir)?;
    }
    let provider = FsBinStore::new(rgb_dir.clone())?;
    let stock = Stock::load(provider.clone(), true).or_else(|err| {
        if err
            .0
            .downcast_ref::<DeserializeError>()
            .map(|e| matches!(e, DeserializeError::Decode(DecodeError::Io(e)) if e.kind() == ErrorKind::NotFound))
            .unwrap_or_default()
        {
            let mut stock = Stock::in_memory();
            stock.make_persistent(provider, true).expect("unable to save stock");
            return Ok(stock)
        }
        Err(Error::IO { details: err.to_string() })
    })?;

    Ok(RgbRuntime {
        stock,
        wallet_dir: wallet_dir.as_ref().to_path_buf(),
        persist_on_drop: true,
    })
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
pub(crate) struct OffchainResolver<'a, 'cons, const TRANSFER: bool> {
    pub(crate) witness_id: RgbTxid,
    pub(crate) consignment: &'cons Consignment<TRANSFER>,
    pub(crate) fallback: &'a AnyResolver,
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
impl<const TRANSFER: bool> ResolveWitness for OffchainResolver<'_, '_, TRANSFER> {
    fn resolve_witness(
        &self,
        pub_witness: &PubWitness,
    ) -> Result<WitnessStatus, WitnessResolverError> {
        let witness_id = pub_witness.txid();
        if witness_id != self.witness_id {
            return self.fallback.resolve_witness(pub_witness);
        }
        self.consignment
            .bundled_witnesses()
            .find(|bw| bw.witness_id() == witness_id)
            .and_then(|p| p.pub_witness.tx().cloned())
            .map_or_else(
                || self.fallback.resolve_witness(pub_witness),
                |tx| Ok(WitnessStatus::Resolved(tx, WitnessOrd::Tentative)),
            )
    }
    fn check_chain_net(&self, chain_net: ChainNet) -> Result<(), WitnessResolverError> {
        self.fallback.check_chain_net(chain_net)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Deserialize)]
    struct MandatoryField {
        #[serde(deserialize_with = "from_str_or_number_mandatory")]
        val: u64,
    }

    #[derive(Debug, Deserialize)]
    struct OptionalField {
        #[serde(deserialize_with = "from_str_or_number_optional")]
        val: Option<u64>,
    }

    #[test]
    fn test_block_on_inside_tokio_runtime() {
        // calling block_on from within an active Tokio runtime takes the thread-spawn path
        // to avoid blocking the runtime thread
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(async { block_on(async { 42u32 }) });
        assert_eq!(result, 42);
    }

    #[test]
    fn test_from_str_or_number_mandatory() {
        // integer value
        let result: MandatoryField = serde_json::from_str(r#"{"val": 42}"#).unwrap();
        assert_eq!(result.val, 42);

        // float value (visit_f64 path)
        let result: MandatoryField = serde_json::from_str(r#"{"val": 42.0}"#).unwrap();
        assert_eq!(result.val, 42);

        // string value
        let result: MandatoryField = serde_json::from_str(r#"{"val": "99"}"#).unwrap();
        assert_eq!(result.val, 99);

        // null -> error
        let err = serde_json::from_str::<MandatoryField>(r#"{"val": null}"#).unwrap_err();
        assert!(
            err.to_string().contains("expected a number but got null"),
            "unexpected error message: {err}"
        );

        // invalid string -> parse error
        let err = serde_json::from_str::<MandatoryField>(r#"{"val": "abc"}"#).unwrap_err();
        assert!(
            err.to_string().contains("invalid value"),
            "unexpected error message: {err}"
        );

        // unexpected type (bool) -> error names the expected types via `expecting`
        let err = serde_json::from_str::<MandatoryField>(r#"{"val": true}"#).unwrap_err();
        assert!(
            err.to_string().contains("a string, a number, or null"),
            "unexpected error message: {err}"
        );
    }

    #[test]
    fn test_from_str_or_number_optional() {
        // integer value
        let result: OptionalField = serde_json::from_str(r#"{"val": 42}"#).unwrap();
        assert_eq!(result.val, Some(42));

        // float value (visit_f64 path)
        let result: OptionalField = serde_json::from_str(r#"{"val": 42.0}"#).unwrap();
        assert_eq!(result.val, Some(42));

        // string value
        let result: OptionalField = serde_json::from_str(r#"{"val": "99"}"#).unwrap();
        assert_eq!(result.val, Some(99));

        // null -> None (visit_unit path)
        let result: OptionalField = serde_json::from_str(r#"{"val": null}"#).unwrap();
        assert_eq!(result.val, None);

        // invalid string -> parse error
        let err = serde_json::from_str::<OptionalField>(r#"{"val": "abc"}"#).unwrap_err();
        assert!(
            err.to_string().contains("invalid value"),
            "unexpected error message: {err}"
        );

        // visit_none path: triggered by deserializer formats that signal absence via visit_none
        // rather than visit_unit (serde_json uses visit_unit for null, but other formats differ)
        struct VisitNoneDeserializer;
        impl<'de> Deserializer<'de> for VisitNoneDeserializer {
            type Error = serde::de::value::Error;
            fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
                visitor.visit_none()
            }
            serde::forward_to_deserialize_any! {
                bool i8 i16 i32 i64 u8 u16 u32 u64 f32 f64 char str string
                bytes byte_buf option unit unit_struct newtype_struct seq tuple
                tuple_struct map struct enum identifier ignored_any
            }
        }
        let result: Option<u64> = from_str_or_number_optional(VisitNoneDeserializer).unwrap();
        assert_eq!(result, None);
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    #[test]
    fn test_check_proxy_json_rpc_error() {
        // server returns HTTP 200 with result=null and a JSON-RPC error field
        let mut server = mockito::Server::new();
        let mock = server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"jsonrpc":"2.0","id":null,"result":null,"error":{"code":-32601,"message":"method not found"}}"#,
            )
            .create();
        let result = check_proxy(&server.url());
        assert_matches!(result, Err(Error::Proxy { details }) if details == "method not found");
        mock.assert();
    }

    #[test]
    fn test_load_rgb_runtime_corrupt_stock() {
        let dir = tempfile::tempdir().unwrap();
        let rgb_dir = dir.path().join(RGB_RUNTIME_DIR);
        fs::create_dir_all(&rgb_dir).unwrap();
        // write garbage to stash.dat: Stock::load fails with a decode error
        fs::write(rgb_dir.join("stash.dat"), b"not valid binary data").unwrap();
        let result = load_rgb_runtime(dir.path());
        assert_matches!(result, Err(Error::IO { .. }));
    }

    #[test]
    fn test_write_rgb_runtime_lockfile_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let lock_path = dir.path().join(RGB_RUNTIME_LOCK_FILE);
        // pre-create the lock file so every open attempt sees AlreadyExists
        fs::File::create(&lock_path).unwrap();
        // with a lower LOCK_FILE_TIMEOUT_SECS in test builds the error is returned immediately
        let result = write_rgb_runtime_lockfile(dir.path());
        assert_matches!(result, Err(Error::Internal { details }) if details == "unreleased lock file");
    }

    // The None return from build_indexer is only reachable when electrum is enabled but esplora
    // is not, and the URL is not a valid electrum server. With esplora enabled the builder is
    // infallible so it would always return Some(Indexer::Esplora) instead.
    #[cfg(all(feature = "electrum", not(feature = "esplora")))]
    #[test]
    fn test_build_indexer_invalid_url_returns_none() {
        let result = build_indexer("not_a_valid_url");
        assert!(result.is_none());
    }

    #[test]
    fn test_bitcoin_network_str_roundtrip() {
        // mainnet
        let network = BitcoinNetwork::Mainnet;
        let network_str = network.to_string();
        let network_from_str = BitcoinNetwork::from_str(&network_str).unwrap();
        assert_eq!(network, network_from_str);

        // testnet3
        let network = BitcoinNetwork::Testnet;
        let network_str = network.to_string();
        let network_from_str = BitcoinNetwork::from_str(&network_str).unwrap();
        assert_eq!(network, network_from_str);

        // testnet4
        let network = BitcoinNetwork::Testnet4;
        let network_str = network.to_string();
        let network_from_str = BitcoinNetwork::from_str(&network_str).unwrap();
        assert_eq!(network, network_from_str);

        // signet
        let network = BitcoinNetwork::Signet;
        let network_str = network.to_string();
        let network_from_str = BitcoinNetwork::from_str(&network_str).unwrap();
        assert_eq!(network, network_from_str);

        // regtest
        let network = BitcoinNetwork::Regtest;
        let network_str = network.to_string();
        let network_from_str = BitcoinNetwork::from_str(&network_str).unwrap();
        assert_eq!(network, network_from_str);

        // signet custom
        let network = BitcoinNetwork::SignetCustom;
        let network_str = network.to_string();
        let network_from_str = BitcoinNetwork::from_str(&network_str).unwrap();
        assert_eq!(network, network_from_str);

        // invalid network
        let network_str = "invalid";
        let result = BitcoinNetwork::from_str(network_str).unwrap_err();
        assert_matches!(result, Error::InvalidBitcoinNetwork { network } if network == "invalid");

        // signet- prefix with invalid hash
        let network_str = "signet-notahash";
        let result = BitcoinNetwork::from_str(network_str).unwrap_err();
        assert_matches!(result, Error::InvalidBitcoinNetwork { network } if network == "signet-notahash");
    }

    #[test]
    fn test_bitcoin_network_chain_net_roundtrip() {
        // mainnet
        let network = BitcoinNetwork::Mainnet;
        let chain_net = ChainNet::BitcoinMainnet;
        let network_from_chain_net = BitcoinNetwork::try_from(chain_net).unwrap();
        assert_eq!(network, network_from_chain_net);
        let chain_net_from_network = ChainNet::from(network);
        assert_eq!(chain_net, chain_net_from_network);

        // testnet3
        let network = BitcoinNetwork::Testnet;
        let chain_net = ChainNet::BitcoinTestnet3;
        let network_from_chain_net = BitcoinNetwork::try_from(chain_net).unwrap();
        assert_eq!(network, network_from_chain_net);
        let chain_net_from_network = ChainNet::from(network);
        assert_eq!(chain_net, chain_net_from_network);

        // testnet4
        let network = BitcoinNetwork::Testnet4;
        let chain_net = ChainNet::BitcoinTestnet4;
        let network_from_chain_net = BitcoinNetwork::try_from(chain_net).unwrap();
        assert_eq!(network, network_from_chain_net);
        let chain_net_from_network = ChainNet::from(network);
        assert_eq!(chain_net, chain_net_from_network);

        // signet
        let network = BitcoinNetwork::Signet;
        let chain_net = ChainNet::BitcoinSignet;
        let network_from_chain_net = BitcoinNetwork::try_from(chain_net).unwrap();
        assert_eq!(network, network_from_chain_net);
        let chain_net_from_network = ChainNet::from(network);
        assert_eq!(chain_net, chain_net_from_network);

        // regtest
        let network = BitcoinNetwork::Regtest;
        let chain_net = ChainNet::BitcoinRegtest;
        let network_from_chain_net = BitcoinNetwork::try_from(chain_net).unwrap();
        assert_eq!(network, network_from_chain_net);
        let chain_net_from_network = ChainNet::from(network);
        assert_eq!(chain_net, chain_net_from_network);

        // signet custom
        let network = BitcoinNetwork::SignetCustom;
        let chain_net = ChainNet::BitcoinSignetCustom;
        let network_from_chain_net = BitcoinNetwork::try_from(chain_net).unwrap();
        assert_eq!(network, network_from_chain_net);
        let chain_net_from_network = ChainNet::from(network);
        assert_eq!(chain_net, chain_net_from_network);

        // invalid chain net
        let chain_net = ChainNet::LiquidMainnet;
        let result = BitcoinNetwork::try_from(chain_net).unwrap_err();
        assert_matches!(result, Error::UnsupportedLayer1 { layer_1 } if layer_1 == "liquid");
    }

    #[test]
    fn test_bitcoin_network_try_from_rust_bitcoin_network() {
        // mainnet
        let network = BitcoinNetwork::Mainnet;
        let rust_bitcoin_network = bitcoin::Network::from(network);
        assert_eq!(rust_bitcoin_network, bitcoin::Network::Bitcoin);

        // testnet3
        let network = BitcoinNetwork::Testnet;
        let rust_bitcoin_network = bitcoin::Network::from(network);
        assert_eq!(rust_bitcoin_network, bitcoin::Network::Testnet);

        // testnet4
        let network = BitcoinNetwork::Testnet4;
        let rust_bitcoin_network = bitcoin::Network::from(network);
        assert_eq!(rust_bitcoin_network, bitcoin::Network::Testnet4);

        // signet
        let network = BitcoinNetwork::Signet;
        let rust_bitcoin_network = bitcoin::Network::from(network);
        assert_eq!(rust_bitcoin_network, bitcoin::Network::Signet);

        // regtest
        let network = BitcoinNetwork::Regtest;
        let rust_bitcoin_network = bitcoin::Network::from(network);
        assert_eq!(rust_bitcoin_network, bitcoin::Network::Regtest);

        // signet custom
        let network = BitcoinNetwork::SignetCustom;
        let rust_bitcoin_network = bitcoin::Network::from(network);
        assert_eq!(rust_bitcoin_network, bitcoin::Network::Signet);
    }
}

#[cfg(test)]
mod tests_proxy_recipient_id {
    use super::*;

    #[test]
    fn legacy_empty_nonce_returns_recipient_id_unchanged() {
        let rid = "wvout:BczOakzm-uHua56v-znf1Q~A-BTRpWDb";
        assert_eq!(derive_proxy_recipient_id(rid, &[]), rid);
    }

    #[test]
    fn nonempty_nonce_returns_64_char_hex_hash() {
        let rid = "wvout:BczOakzm-uHua56v-znf1Q~A-BTRpWDb";
        let nonce = [0u8; 16];
        let out = derive_proxy_recipient_id(rid, &nonce);
        assert_eq!(out.len(), 64);
        assert!(out.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn different_nonces_yield_different_ids() {
        let rid = "wvout:BczOakzm-uHua56v-znf1Q~A-BTRpWDb";
        let a = derive_proxy_recipient_id(rid, &[1u8; 16]);
        let b = derive_proxy_recipient_id(rid, &[2u8; 16]);
        assert_ne!(a, b);
    }

    #[test]
    fn same_inputs_yield_same_id() {
        let rid = "wvout:BczOakzm-uHua56v-znf1Q~A-BTRpWDb";
        let nonce = [7u8; 16];
        assert_eq!(
            derive_proxy_recipient_id(rid, &nonce),
            derive_proxy_recipient_id(rid, &nonce)
        );
    }
}

#[cfg(all(test, any(feature = "electrum", feature = "esplora")))]
mod tests_transport_url_nonce {
    use super::*;

    #[test]
    fn append_to_url_without_query() {
        let url = "rpcs://proxy.example.com/0.2/json-rpc";
        let nonce = [0x01, 0x02, 0x03];
        assert_eq!(
            append_recipient_nonce(url, &nonce),
            "rpcs://proxy.example.com/0.2/json-rpc?rid_nonce=010203"
        );
    }

    #[test]
    fn append_to_url_with_existing_query() {
        let url = "rpcs://proxy.example.com/0.2/json-rpc?foo=bar";
        let nonce = [0xab, 0xcd];
        assert_eq!(
            append_recipient_nonce(url, &nonce),
            "rpcs://proxy.example.com/0.2/json-rpc?foo=bar&rid_nonce=abcd"
        );
    }

    #[test]
    fn extract_returns_bare_url_and_nonce_when_present() {
        let url = "rpcs://proxy.example.com/0.2/json-rpc?rid_nonce=deadbeef";
        let (bare, nonce) = extract_recipient_nonce(url);
        assert_eq!(bare, "rpcs://proxy.example.com/0.2/json-rpc");
        assert_eq!(nonce, Some(vec![0xde, 0xad, 0xbe, 0xef]));
    }

    #[test]
    fn extract_returns_none_when_absent() {
        let url = "rpcs://proxy.example.com/0.2/json-rpc";
        let (bare, nonce) = extract_recipient_nonce(url);
        assert_eq!(bare, url);
        assert_eq!(nonce, None);
    }

    #[test]
    fn extract_preserves_other_query_params() {
        let url = "rpcs://proxy.example.com/0.2/json-rpc?foo=bar&rid_nonce=ab&baz=qux";
        let (bare, nonce) = extract_recipient_nonce(url);
        assert_eq!(
            bare,
            "rpcs://proxy.example.com/0.2/json-rpc?foo=bar&baz=qux"
        );
        assert_eq!(nonce, Some(vec![0xab]));
    }
}

#[cfg(test)]
mod tests_keychain_layout {
    use super::*;
    use crate::keys::generate_keys;
    use crate::wallet::SinglesigKeys;
    use bdk_wallet::descriptor::ExtendedDescriptor;

    fn norm(desc: &str) -> String {
        desc.replace('h', "'")
    }

    // both sides under the standard BIP-86 account at coin type 0, colored on keychain 9 (the
    // vanilla one, 10, is SinglesigKeys::vanilla_keychain)
    fn single_account() -> KeychainLayoutOverrides {
        KeychainLayoutOverrides {
            colored_keychain: Some(9),
            colored_coin_type: Some(0),
            vanilla_coin_type: Some(0),
        }
    }

    #[test]
    fn default_layout_matches_standard_rgb_lib_layout() {
        let none = KeychainLayoutOverrides::default();
        let mainnet = KeychainLayout::resolve(&BitcoinNetwork::Mainnet, &none, None).unwrap();
        assert_eq!(
            mainnet,
            KeychainLayout {
                colored_coin_type: COIN_RGB_MAINNET,
                vanilla_coin_type: 0,
                colored_keychain: KEYCHAIN_RGB,
                vanilla_keychain: KEYCHAIN_BTC,
            }
        );
        let signet = KeychainLayout::resolve(&BitcoinNetwork::Signet, &none, Some(10)).unwrap();
        assert_eq!(signet.colored_coin_type, COIN_RGB_TESTNET);
        assert_eq!(signet.vanilla_coin_type, 1);
        assert_eq!(signet.vanilla_keychain, 10);
    }

    #[test]
    fn layout_rejects_shared_keychain() {
        // colored moved onto the vanilla coin type without a distinct keychain
        let mut overrides = KeychainLayoutOverrides {
            colored_coin_type: Some(0),
            ..Default::default()
        };
        let err = KeychainLayout::resolve(&BitcoinNetwork::Mainnet, &overrides, None).unwrap_err();
        assert!(matches!(err, Error::InvalidKeychainLayout { .. }));
        overrides.colored_keychain = Some(9);
        let err =
            KeychainLayout::resolve(&BitcoinNetwork::Mainnet, &overrides, Some(9)).unwrap_err();
        assert!(matches!(err, Error::InvalidKeychainLayout { .. }));
    }

    #[test]
    fn layout_rejects_non_hardenable_coin_type() {
        let overrides = KeychainLayoutOverrides {
            colored_coin_type: Some(0x8000_0000),
            colored_keychain: Some(9),
            ..Default::default()
        };
        let err =
            KeychainLayout::resolve(&BitcoinNetwork::Mainnet, &overrides, Some(10)).unwrap_err();
        assert!(matches!(err, Error::InvalidKeychainLayout { .. }));
    }

    #[test]
    fn single_account_layout_from_xpubs() {
        // hardware-wallet layout: both sides under the one exported BIP-86 account
        let keys = generate_keys(BitcoinNetwork::Mainnet, WitnessVersion::Taproot);
        let net = BitcoinNetwork::Mainnet;
        let (_, account_xpub, _) =
            get_account_data_at_coin_type(&net, &keys.mnemonic, 0, WitnessVersion::Taproot)
                .unwrap();
        let layout = KeychainLayout::resolve(&net, &single_account(), Some(10)).unwrap();
        let descs = get_descriptors_from_xpubs(
            &keys.master_fingerprint,
            &account_xpub,
            &account_xpub,
            &layout,
            WitnessVersion::Taproot,
        )
        .unwrap();
        let fp = &keys.master_fingerprint;
        assert!(
            norm(&descs.colored).contains(&format!("[{fp}/86'/0'/0'/9]")),
            "{}",
            descs.colored
        );
        assert!(
            norm(&descs.vanilla).contains(&format!("[{fp}/86'/0'/0'/10]")),
            "{}",
            descs.vanilla
        );
        assert_ne!(descs.colored, descs.vanilla);

        // the mnemonic path derives exactly the same descriptors (public parts)
        let with_mnemonic = get_descriptors(
            &net,
            &keys.mnemonic,
            &layout,
            &account_xpub,
            &account_xpub,
            WitnessVersion::Taproot,
        )
        .unwrap();
        assert!(norm(&with_mnemonic.colored).contains(&format!("[{fp}/86'/0'/0'/9]")));
        assert!(norm(&with_mnemonic.vanilla).contains(&format!("[{fp}/86'/0'/0'/10]")));
    }

    #[test]
    fn default_layout_descriptors_unchanged() {
        let keys = generate_keys(BitcoinNetwork::Regtest, WitnessVersion::Taproot);
        let net = BitcoinNetwork::Regtest;
        let nk = net.network_kind();
        let xpub_rgb = str_to_xpub(&keys.account_xpub_colored, &nk).unwrap();
        let xpub_btc = str_to_xpub(&keys.account_xpub_vanilla, &nk).unwrap();
        let layout =
            KeychainLayout::resolve(&net, &KeychainLayoutOverrides::default(), None).unwrap();
        let descs = get_descriptors_from_xpubs(
            &keys.master_fingerprint,
            &xpub_rgb,
            &xpub_btc,
            &layout,
            WitnessVersion::Taproot,
        )
        .unwrap();
        let fp = &keys.master_fingerprint;
        assert!(norm(&descs.colored).contains(&format!("[{fp}/86'/827167'/0'/0]")));
        assert!(norm(&descs.vanilla).contains(&format!("[{fp}/86'/1'/0'/0]")));
    }

    fn inconsistent_xpubs(res: Result<(WalletDescriptors, bool), Error>) -> bool {
        matches!(
            res,
            Err(Error::InvalidKeychainLayout { details })
                if details == "account xpubs are inconsistent with the configured coin types"
        )
    }

    #[test]
    fn account_xpubs_must_match_the_coin_types() {
        for net in [BitcoinNetwork::Mainnet, BitcoinNetwork::Signet] {
            let keys = generate_keys(net, WitnessVersion::Taproot);
            let (_, account_xpub, _) =
                get_account_data_at_coin_type(&net, &keys.mnemonic, 0, WitnessVersion::Taproot)
                    .unwrap();
            let account_xpub = account_xpub.to_string();
            for with_mnemonic in [false, true] {
                let default_keys = if with_mnemonic {
                    SinglesigKeys::from_keys(&keys, None)
                } else {
                    SinglesigKeys::from_keys_no_mnemonic(&keys, None)
                };

                // default layout: two coin types, two account xPubs
                default_keys.build_descriptors(&net).unwrap();

                // both sides under one account: one coin type, the same account xPub twice
                let mut single = default_keys.clone().with_keychain_layout(single_account());
                single.vanilla_keychain = Some(10);
                single.account_xpub_colored = account_xpub.clone();
                single.account_xpub_vanilla = account_xpub.clone();
                single.build_descriptors(&net).unwrap();

                // same xPub for both sides but the colored coin type left to its default: the
                // colored descriptor would claim 827166'/827167' for a key at 0'
                let mut forgot_colored_coin = single.clone();
                forgot_colored_coin.keychain_layout.colored_coin_type = None;
                assert!(inconsistent_xpubs(
                    forgot_colored_coin.build_descriptors(&net)
                ));

                // off mainnet the vanilla default is 1', so the vanilla coin type is needed too
                let mut forgot_vanilla_coin = single.clone();
                forgot_vanilla_coin.keychain_layout.vanilla_coin_type = None;
                let res = forgot_vanilla_coin.build_descriptors(&net);
                if net == BitcoinNetwork::Mainnet {
                    res.unwrap();
                } else {
                    assert!(inconsistent_xpubs(res));
                }

                // default coin types with the same xPub for both sides
                let mut same_xpub = default_keys.clone();
                same_xpub.account_xpub_colored = same_xpub.account_xpub_vanilla.clone();
                assert!(inconsistent_xpubs(same_xpub.build_descriptors(&net)));

                // one coin type, but the colored xPub is still the RGB account's
                let mut other_xpub = single.clone();
                other_xpub.account_xpub_colored = keys.account_xpub_colored.clone();
                assert!(inconsistent_xpubs(other_xpub.build_descriptors(&net)));
            }
        }
    }

    #[test]
    fn account_xpubs_compared_as_keys() {
        let net = BitcoinNetwork::Signet;
        let keys = generate_keys(net, WitnessVersion::Taproot);
        let (_, account_xpub, _) =
            get_account_data_at_coin_type(&net, &keys.mnemonic, 0, WitnessVersion::Taproot)
                .unwrap();
        let mut single = SinglesigKeys::from_keys_no_mnemonic(&keys, Some(10))
            .with_keychain_layout(single_account());
        single.account_xpub_colored = account_xpub.to_string();
        single.account_xpub_vanilla = account_xpub.to_string();
        let (descs, _) = single.build_descriptors(&net).unwrap();

        // the same key encoded with mainnet version bytes (xpub) on one side
        let mut mainnet_encoded = account_xpub;
        mainnet_encoded.network = NetworkKind::Main;
        assert!(mainnet_encoded.to_string().starts_with("xpub"));
        let mut mixed = single.clone();
        mixed.account_xpub_colored = mainnet_encoded.to_string();
        assert_eq!(mixed.build_descriptors(&net).unwrap().0, descs);

        // the same key with other metadata, as a host that only has the public key and chain
        // code would build it: accepted, and it derives the same scripts
        let mut relabelled = account_xpub;
        relabelled.depth = 0;
        relabelled.parent_fingerprint = Fingerprint::default();
        relabelled.child_number = ChildNumber::from_normal_idx(0).unwrap();
        let mut bare = single.clone();
        bare.account_xpub_colored = relabelled.to_string();
        let (bare_descs, _) = bare.build_descriptors(&net).unwrap();
        let script_at = |desc: &str, index: u32| {
            ExtendedDescriptor::from_str(desc)
                .unwrap()
                .at_derivation_index(index)
                .unwrap()
                .script_pubkey()
        };
        for index in [0, 1, 100] {
            assert_eq!(
                script_at(&bare_descs.colored, index),
                script_at(&descs.colored, index)
            );
        }

        // and it is still the same key when the coin types differ
        bare.keychain_layout = KeychainLayoutOverrides::default();
        bare.account_xpub_vanilla = account_xpub.to_string();
        assert!(inconsistent_xpubs(bare.build_descriptors(&net)));
    }

    // Serialized shapes written before SinglesigKeys grouped the overrides into
    // KeychainLayoutOverrides, for the key of "abandon ... about" on signet. The account xPub at
    // m/86'/0'/0' serves both sides of the single-account layout; the other two are the default
    // layout's accounts (m/86'/827167'/0' and m/86'/1'/0').
    const TPUB_COIN_0: &str = "tpubDC3pD7UZXnsgh3EBjbtBQiB1FnLask7UHBSunZ1DPK4dCFFZoFRkgxHB8gt42FvLzx1DpxfHWxAsYaY6b643RVcGjDxXxns7wKKYnnfEcbB";
    const TPUB_COLORED: &str = "tpubDCtpoJs6YJcjLnr9gq6jYriYNMuWEu8mSDvEQU5st3ZkJbFqqzwpHUiPvxqD2366ciFAfpehk1k2d7Tyk7AJEr8uZva7KfnX4RpsiVSoEcZ";
    const TPUB_VANILLA: &str = "tpubDDfvzhdVV4unsoKt5aE6dcsNsfeWbTgmLZPi8LQDYU2xixrYemMfWJ3BaVneH3u7DBQePdTwhpybaKRU95pi6PMUtLPBJLVQRpzEnjfjZzX";

    #[cfg(not(feature = "camel_case"))]
    const KEYS_JSON: &str = r#"{"account_xpub_vanilla":"TPUB","account_xpub_colored":"TPUB","vanilla_keychain":10,"colored_keychain":9,"colored_coin_type":0,"vanilla_coin_type":0,"master_fingerprint":"73c5da0a","mnemonic":null,"witness_version":"Taproot"}"#;
    #[cfg(feature = "camel_case")]
    const KEYS_JSON: &str = r#"{"accountXpubVanilla":"TPUB","accountXpubColored":"TPUB","vanillaKeychain":10,"coloredKeychain":9,"coloredCoinType":0,"vanillaCoinType":0,"masterFingerprint":"73c5da0a","mnemonic":null,"witnessVersion":"Taproot"}"#;
    // the shape before the layout existed at all
    #[cfg(not(feature = "camel_case"))]
    const KEYS_JSON_NO_LAYOUT: &str = r#"{"account_xpub_vanilla":"TPUB_V","account_xpub_colored":"TPUB_C","vanilla_keychain":null,"master_fingerprint":"73c5da0a","mnemonic":null,"witness_version":"Taproot"}"#;
    #[cfg(feature = "camel_case")]
    const KEYS_JSON_NO_LAYOUT: &str = r#"{"accountXpubVanilla":"TPUB_V","accountXpubColored":"TPUB_C","vanillaKeychain":null,"masterFingerprint":"73c5da0a","mnemonic":null,"witnessVersion":"Taproot"}"#;

    #[test]
    fn singlesig_keys_json_keeps_its_flat_shape() {
        let json = KEYS_JSON.replace("TPUB", TPUB_COIN_0);
        let keys: SinglesigKeys = serde_json::from_str(&json).unwrap();
        assert_eq!(keys.keychain_layout, single_account());
        assert_eq!(keys.vanilla_keychain, Some(10));
        keys.build_descriptors(&BitcoinNetwork::Signet).unwrap();
        // written back field for field, byte for byte
        assert_eq!(serde_json::to_string(&keys).unwrap(), json);

        let json = KEYS_JSON_NO_LAYOUT
            .replace("TPUB_V", TPUB_VANILLA)
            .replace("TPUB_C", TPUB_COLORED);
        let keys: SinglesigKeys = serde_json::from_str(&json).unwrap();
        assert_eq!(keys.keychain_layout, KeychainLayoutOverrides::default());
        keys.build_descriptors(&BitcoinNetwork::Signet).unwrap();

        // numeric strings are still accepted inside the flattened struct, and a bad value still
        // fails the whole deserialization instead of falling back to the default layout
        let json = KEYS_JSON.replace("TPUB", TPUB_COIN_0);
        let as_strings = json.replace(":9,", r#":"9","#).replace(":0,", r#":"0","#);
        let keys: SinglesigKeys = serde_json::from_str(&as_strings).unwrap();
        assert_eq!(keys.keychain_layout, single_account());
        let bad = json.replace(":9,", r#":"nine","#);
        assert!(serde_json::from_str::<SinglesigKeys>(&bad).is_err());
    }

    const MANIFEST_JSON: &str = r#"{
  "version": 1,
  "bitcoin_network": "Signet",
  "database_type": "Sqlite",
  "max_allocations_per_utxo": 1,
  "supported_schemas": [
    "Nia"
  ],
  "reuse_addresses": false,
  "account_xpub_vanilla": "TPUB",
  "account_xpub_colored": "TPUB",
  "vanilla_keychain": 10,
  "colored_keychain": 9,
  "colored_coin_type": 0,
  "vanilla_coin_type": 0,
  "master_fingerprint": "73c5da0a",
  "witness_version": "Taproot"
}"#;
    // the four settings apart, so a mix-up between them shows
    const MANIFEST_JSON_DISTINCT: &str = r#"{
  "version": 1,
  "bitcoin_network": "Signet",
  "database_type": "Sqlite",
  "max_allocations_per_utxo": 1,
  "supported_schemas": [
    "Nia"
  ],
  "reuse_addresses": false,
  "account_xpub_vanilla": "TPUB_V",
  "account_xpub_colored": "TPUB_C",
  "vanilla_keychain": 10,
  "colored_keychain": 9,
  "colored_coin_type": 0,
  "vanilla_coin_type": 5,
  "master_fingerprint": "73c5da0a",
  "witness_version": "Taproot"
}"#;
    const MANIFEST_JSON_DEFAULT: &str = r#"{
  "version": 1,
  "bitcoin_network": "Signet",
  "database_type": "Sqlite",
  "max_allocations_per_utxo": 1,
  "supported_schemas": [
    "Nia"
  ],
  "reuse_addresses": false,
  "account_xpub_vanilla": "TPUB_V",
  "account_xpub_colored": "TPUB_C",
  "vanilla_keychain": 0,
  "master_fingerprint": "73c5da0a",
  "witness_version": "Taproot"
}"#;

    #[test]
    fn manifest_keeps_its_shape() {
        use crate::wallet::WalletManifest;

        let json = MANIFEST_JSON.replace("TPUB", TPUB_COIN_0);
        let manifest: WalletManifest = serde_json::from_str(&json).unwrap();
        let (wallet_data, keys) = manifest.into_parts(s!("data_dir"), None);
        assert_eq!(keys.keychain_layout, single_account());
        assert_eq!(keys.vanilla_keychain, Some(10));
        keys.build_descriptors(&wallet_data.bitcoin_network)
            .unwrap();
        let rewritten = WalletManifest::new(&wallet_data, &keys);
        assert_eq!(serde_json::to_string_pretty(&rewritten).unwrap(), json);

        let json = MANIFEST_JSON_DISTINCT
            .replace("TPUB_V", TPUB_VANILLA)
            .replace("TPUB_C", TPUB_COIN_0);
        let manifest: WalletManifest = serde_json::from_str(&json).unwrap();
        let (wallet_data, keys) = manifest.into_parts(s!("data_dir"), None);
        assert_eq!(
            keys.keychain_layout,
            KeychainLayoutOverrides {
                colored_keychain: Some(9),
                colored_coin_type: Some(0),
                vanilla_coin_type: Some(5),
            }
        );
        let rewritten = WalletManifest::new(&wallet_data, &keys);
        assert_eq!(serde_json::to_string_pretty(&rewritten).unwrap(), json);

        let json = MANIFEST_JSON_DEFAULT
            .replace("TPUB_V", TPUB_VANILLA)
            .replace("TPUB_C", TPUB_COLORED);
        let manifest: WalletManifest = serde_json::from_str(&json).unwrap();
        let (wallet_data, keys) = manifest.into_parts(s!("data_dir"), None);
        assert_eq!(keys.keychain_layout, KeychainLayoutOverrides::default());
        keys.build_descriptors(&wallet_data.bitcoin_network)
            .unwrap();
        let rewritten = WalletManifest::new(&wallet_data, &keys);
        assert_eq!(serde_json::to_string_pretty(&rewritten).unwrap(), json);
    }
}
