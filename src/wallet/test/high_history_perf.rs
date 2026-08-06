#![cfg(feature = "esplora")]

use super::*;

use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Instant;

use rgbstd::indexers::esplora_blocking::{
    EsploraClient as RgbEsploraClient, esplora_client::Builder,
};
use rgbstd::validation::{ResolveWitness, WitnessResolverError, WitnessStatus};

use crate::utils::{OperationResolver, prefetch_consignment_witnesses};

const LOCAL_ESPLORA_URL: &str = "http://127.0.0.1:3003";
const LATENT_ESPLORA_URL: &str = "http://127.0.0.1:3010";
const FAILING_ESPLORA_URL: &str = "http://127.0.0.1:3012";
const DEFAULT_TRANSFER_COUNT: usize = 88;

fn fixture_dir() -> PathBuf {
    PathBuf::from("tests/perf-fixture")
}

fn transfer_count() -> usize {
    std::env::var("RGB_PERF_TRANSFERS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(DEFAULT_TRANSFER_COUNT)
}

fn settle_transfer(
    sender: &mut SinglesigParty,
    receiver: &mut SinglesigParty,
    asset_id: &str,
) -> String {
    let receive_data = receiver.blind_receive();
    let recipient_map = HashMap::from([(
        asset_id.to_owned(),
        vec![Recipient {
            assignment: Assignment::Fungible(AMOUNT),
            recipient_id: receive_data.recipient_id,
            witness_data: None,
            transport_endpoints: TRANSPORT_ENDPOINTS.clone(),
        }],
    )]);

    let txid = sender.send_retry(&recipient_map);
    receiver.wait_for_refresh(None);
    sender.wait_for_refresh(Some(asset_id));
    mine(false);
    receiver.wait_for_refresh(Some(asset_id));
    sender.wait_for_refresh(Some(asset_id));
    txid
}

#[test]
#[ignore = "expensive protocol performance fixture"]
fn generate_high_history_fixture() {
    initialize();
    let started = Instant::now();
    let transfers = transfer_count();
    assert!(transfers > 0);

    let mut party_a = get_funded_party!();
    let mut party_b = get_funded_party!();
    party_a.create_utxos(false, Some(20), None, FEE_RATE, Some(20));
    party_b.create_utxos(false, Some(20), None, FEE_RATE, Some(20));
    let asset = party_a.issue_asset_nia(Some(&[AMOUNT]));
    let mut final_txid = String::new();
    let mut final_sender_is_a = true;

    for index in 0..transfers {
        let step_started = Instant::now();
        let sender_is_a = index % 2 == 0;
        final_txid = if sender_is_a {
            settle_transfer(&mut party_a, &mut party_b, &asset.asset_id)
        } else {
            settle_transfer(&mut party_b, &mut party_a, &asset.asset_id)
        };
        final_sender_is_a = sender_is_a;
        println!(
            "PERF_FIXTURE step={} txid={} elapsed_ms={}",
            index + 1,
            final_txid,
            step_started.elapsed().as_millis()
        );
    }

    let sender = if final_sender_is_a {
        &party_a
    } else {
        &party_b
    };
    let source = sender
        .wallet
        .get_send_consignment_path(&asset.asset_id, &final_txid);
    let output_dir = fixture_dir();
    fs::create_dir_all(&output_dir).unwrap();
    let output = output_dir.join("high-history.rgbc");
    fs::copy(&source, &output).unwrap();
    fs::write(output_dir.join("asset-id.txt"), &asset.asset_id).unwrap();
    fs::write(output_dir.join("final-txid.txt"), &final_txid).unwrap();

    let consignment = RgbTransfer::load_file(&output).unwrap();
    let witness_bundles = consignment.bundled_witnesses().count();
    let transitions = consignment
        .bundles
        .iter()
        .map(|bundle| bundle.bundle.known_transitions.len())
        .sum::<usize>();
    println!(
        "PERF_FIXTURE_COMPLETE transfers={} asset_id={} final_txid={} bytes={} witness_bundles={} transitions={} elapsed_ms={}",
        transfers,
        asset.asset_id,
        final_txid,
        fs::metadata(output).unwrap().len(),
        witness_bundles,
        transitions,
        started.elapsed().as_millis()
    );
}

struct TimedResolver<'a> {
    inner: &'a dyn ResolveWitness,
    calls: std::sync::Mutex<Vec<(RgbTxid, u128)>>,
}

struct MemoizingResolver<'a> {
    inner: &'a dyn ResolveWitness,
    cache: std::sync::Mutex<HashMap<RgbTxid, WitnessStatus>>,
}

struct PrefetchedResolver<'a> {
    fallback: &'a dyn ResolveWitness,
    witnesses: HashMap<RgbTxid, WitnessStatus>,
}

impl ResolveWitness for PrefetchedResolver<'_> {
    fn resolve_witness(&self, witness_id: RgbTxid) -> Result<WitnessStatus, WitnessResolverError> {
        self.witnesses
            .get(&witness_id)
            .cloned()
            .map(Ok)
            .unwrap_or_else(|| self.fallback.resolve_witness(witness_id))
    }

    fn check_chain_net(&self, chain_net: ChainNet) -> Result<(), WitnessResolverError> {
        self.fallback.check_chain_net(chain_net)
    }
}

fn prefetch_witnesses(
    indexer_url: &str,
    consignment: &RgbTransfer,
    offchain_witness: RgbTxid,
    workers: usize,
) -> (HashMap<RgbTxid, WitnessStatus>, u128) {
    let witness_ids = consignment
        .bundled_witnesses()
        .map(|bundle| bundle.witness_id())
        .filter(|witness_id| *witness_id != offchain_witness)
        .collect::<HashSet<_>>();
    let queue = std::sync::Arc::new(std::sync::Mutex::new(
        witness_ids.iter().copied().collect::<VecDeque<_>>(),
    ));
    let results = std::sync::Arc::new(std::sync::Mutex::new(HashMap::new()));
    let errors = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let started = Instant::now();

    std::thread::scope(|scope| {
        for _ in 0..workers.min(witness_ids.len()).max(1) {
            let queue = queue.clone();
            let results = results.clone();
            let errors = errors.clone();
            scope.spawn(move || {
                let resolver = RgbEsploraClient {
                    inner: Builder::new(indexer_url).build_blocking(),
                };
                loop {
                    let Some(witness_id) = queue.lock().unwrap().pop_front() else {
                        break;
                    };
                    match resolver.resolve_witness(witness_id) {
                        Ok(status) => {
                            results.lock().unwrap().insert(witness_id, status);
                        }
                        Err(error) => errors.lock().unwrap().push((witness_id, error.to_string())),
                    }
                }
            });
        }
    });

    let errors = std::sync::Arc::try_unwrap(errors)
        .unwrap()
        .into_inner()
        .unwrap();
    assert!(errors.is_empty(), "prefetch failures: {errors:?}");
    let results = std::sync::Arc::try_unwrap(results)
        .unwrap()
        .into_inner()
        .unwrap();
    assert_eq!(results.len(), witness_ids.len());
    (results, started.elapsed().as_millis())
}

impl ResolveWitness for MemoizingResolver<'_> {
    fn resolve_witness(&self, witness_id: RgbTxid) -> Result<WitnessStatus, WitnessResolverError> {
        if let Some(status) = self.cache.lock().unwrap().get(&witness_id).cloned() {
            return Ok(status);
        }
        let status = self.inner.resolve_witness(witness_id)?;
        self.cache
            .lock()
            .unwrap()
            .insert(witness_id, status.clone());
        Ok(status)
    }

    fn check_chain_net(&self, chain_net: ChainNet) -> Result<(), WitnessResolverError> {
        self.inner.check_chain_net(chain_net)
    }
}

fn execute_replay<R: ResolveWitness>(
    receiver: &SinglesigParty,
    consignment: &RgbTransfer,
    resolver: &R,
) -> (u128, u128, u128) {
    let asset_schema: AssetSchema = consignment.schema_id().try_into().unwrap();
    let config = ValidationConfig {
        chain_net: receiver.wallet.chain_net(),
        trusted_typesystem: asset_schema.types(),
        ..Default::default()
    };
    let validate_started = Instant::now();
    let valid = consignment.clone().validate(resolver, &config).unwrap();
    let validate_ms = validate_started.elapsed().as_millis();

    let import_started = Instant::now();
    let mut runtime = receiver.wallet.rgb_runtime().unwrap();
    runtime
        .import_contract(valid.clone().into_valid_contract(), resolver)
        .unwrap();
    let import_ms = import_started.elapsed().as_millis();

    let accept_started = Instant::now();
    runtime.accept_transfer(valid, resolver).unwrap();
    let accept_ms = accept_started.elapsed().as_millis();
    (validate_ms, import_ms, accept_ms)
}

impl ResolveWitness for TimedResolver<'_> {
    fn resolve_witness(&self, witness_id: RgbTxid) -> Result<WitnessStatus, WitnessResolverError> {
        let started = Instant::now();
        let result = self.inner.resolve_witness(witness_id);
        self.calls
            .lock()
            .unwrap()
            .push((witness_id, started.elapsed().as_millis()));
        result
    }

    fn check_chain_net(&self, chain_net: ChainNet) -> Result<(), WitnessResolverError> {
        self.inner.check_chain_net(chain_net)
    }
}

#[test]
#[ignore = "expensive protocol performance replay"]
fn replay_high_history_fixture() {
    initialize();
    let output_dir = fixture_dir();
    let consignment = RgbTransfer::load_file(output_dir.join("high-history.rgbc")).unwrap();
    let final_txid = fs::read_to_string(output_dir.join("final-txid.txt")).unwrap();
    let indexer_url =
        std::env::var("RGB_PERF_ESPLORA_URL").unwrap_or_else(|_| LOCAL_ESPLORA_URL.to_owned());
    assert!(
        indexer_url == LOCAL_ESPLORA_URL
            || indexer_url == LATENT_ESPLORA_URL
            || indexer_url == FAILING_ESPLORA_URL
    );

    let receiver = get_empty_party!(indexer_url.clone());
    let witness_id = RgbTxid::from_str(final_txid.trim()).unwrap();
    let offchain = OffchainResolver {
        witness_id,
        consignment: &consignment,
        fallback: receiver.wallet.blockchain_resolver(),
    };
    let resolver = TimedResolver {
        inner: &offchain,
        calls: Default::default(),
    };
    let memoizing = MemoizingResolver {
        inner: &resolver,
        cache: Default::default(),
    };
    let use_cache = std::env::var("RGB_PERF_CACHE").as_deref() == Ok("1");
    let prefetch_workers = std::env::var("RGB_PERF_PREFETCH")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    let use_production_resolver = std::env::var("RGB_PERF_PRODUCTION").as_deref() == Ok("1");
    let (prefetched, prefetch_ms) = if prefetch_workers > 0 {
        let (witnesses, elapsed) =
            prefetch_witnesses(&indexer_url, &consignment, witness_id, prefetch_workers);
        (Some(witnesses), elapsed)
    } else {
        (None, 0)
    };
    let production_prefetch_started = Instant::now();
    let production_prefetched = if use_production_resolver {
        Some(
            prefetch_consignment_witnesses(
                &indexer_url,
                BitcoinNetwork::Regtest,
                &consignment,
                witness_id,
            )
            .unwrap(),
        )
    } else {
        None
    };
    let production_prefetch_ms = if use_production_resolver {
        production_prefetch_started.elapsed().as_millis()
    } else {
        0
    };
    let (validate_ms, import_ms, accept_ms) = if let Some(witnesses) = production_prefetched {
        let production_resolver = OperationResolver::new(&offchain, witnesses);
        execute_replay(&receiver, &consignment, &production_resolver)
    } else if let Some(witnesses) = prefetched {
        let prefetched_resolver = PrefetchedResolver {
            fallback: &resolver,
            witnesses,
        };
        execute_replay(&receiver, &consignment, &prefetched_resolver)
    } else if use_cache {
        execute_replay(&receiver, &consignment, &memoizing)
    } else {
        execute_replay(&receiver, &consignment, &resolver)
    };

    let calls = resolver.calls.into_inner().unwrap();
    let mut counts = HashMap::new();
    for (txid, _) in &calls {
        *counts.entry(*txid).or_insert(0usize) += 1;
    }
    let resolver_ms = calls.iter().map(|(_, elapsed)| elapsed).sum::<u128>();
    println!(
        "PERF_REPLAY indexer={} cache={} production_resolver={} production_prefetch_ms={} prefetch_workers={} prefetch_ms={} validate_ms={} import_ms={} accept_ms={} fallback_resolver_calls={} fallback_unique_witnesses={} fallback_duplicate_calls={} fallback_resolver_ms={}",
        indexer_url,
        use_cache,
        use_production_resolver,
        production_prefetch_ms,
        prefetch_workers,
        prefetch_ms,
        validate_ms,
        import_ms,
        accept_ms,
        calls.len(),
        counts.len(),
        calls.len() - counts.len(),
        resolver_ms
    );
}

#[test]
#[ignore = "expensive protocol performance persistence replay"]
fn save_high_history_asset_with_production_resolver() {
    initialize();
    let output_dir = fixture_dir();
    let consignment = RgbTransfer::load_file(output_dir.join("high-history.rgbc")).unwrap();
    let asset_id = consignment.contract_id().to_string();
    let final_txid = fs::read_to_string(output_dir.join("final-txid.txt")).unwrap();
    let indexer_url =
        std::env::var("RGB_PERF_ESPLORA_URL").unwrap_or_else(|_| LOCAL_ESPLORA_URL.to_owned());
    let receiver = get_empty_party!(indexer_url.clone());

    let witness_id = RgbTxid::from_str(final_txid.trim()).unwrap();
    let fallback_resolver = OffchainResolver {
        witness_id,
        consignment: &consignment,
        fallback: receiver.wallet.blockchain_resolver(),
    };
    let prefetched = prefetch_consignment_witnesses(
        &indexer_url,
        BitcoinNetwork::Regtest,
        &consignment,
        witness_id,
    )
    .unwrap();
    let resolver = OperationResolver::new(&fallback_resolver, prefetched);
    let asset_schema: AssetSchema = consignment.schema_id().try_into().unwrap();
    let config = ValidationConfig {
        chain_net: receiver.wallet.chain_net(),
        trusted_typesystem: asset_schema.types(),
        ..Default::default()
    };
    let accept_started = Instant::now();
    let valid = consignment.clone().validate(&resolver, &config).unwrap();
    let mut runtime = receiver.wallet.rgb_runtime().unwrap();
    runtime
        .import_contract(valid.clone().into_valid_contract(), &resolver)
        .unwrap();
    runtime.accept_transfer(valid, &resolver).unwrap();
    drop(runtime);
    let accept_elapsed_ms = accept_started.elapsed().as_millis();

    let persist_started = Instant::now();
    receiver
        .wallet
        .save_new_asset(consignment, final_txid.trim().to_owned())
        .unwrap();
    let persist_elapsed_ms = persist_started.elapsed().as_millis();
    let assets = receiver.wallet.list_assets(vec![]).unwrap();
    let persisted = assets
        .nia
        .unwrap_or_default()
        .iter()
        .any(|asset| asset.asset_id == asset_id);
    assert!(persisted);
    println!(
        "PERF_SAVE_NEW_ASSET indexer={} asset_id={} accept_elapsed_ms={} persist_elapsed_ms={} total_elapsed_ms={} persisted={}",
        indexer_url,
        asset_id,
        accept_elapsed_ms,
        persist_elapsed_ms,
        accept_elapsed_ms + persist_elapsed_ms,
        persisted
    );
}

#[test]
#[ignore = "protocol performance fault-injection replay"]
fn prefetch_failure_does_not_mutate_wallet() {
    initialize();
    let output_dir = fixture_dir();
    let consignment = RgbTransfer::load_file(output_dir.join("high-history.rgbc")).unwrap();
    let final_txid = fs::read_to_string(output_dir.join("final-txid.txt")).unwrap();
    let witness_id = RgbTxid::from_str(final_txid.trim()).unwrap();
    let receiver = get_empty_party!(LOCAL_ESPLORA_URL.to_owned());
    let failing_indexer = std::env::var("RGB_PERF_ESPLORA_URL").unwrap();

    let result = prefetch_consignment_witnesses(
        &failing_indexer,
        BitcoinNetwork::Regtest,
        &consignment,
        witness_id,
    );
    assert!(matches!(result, Err(Error::Network { .. })));
    let assets = receiver.wallet.list_assets(vec![]).unwrap();
    assert!(assets.nia.unwrap_or_default().is_empty());
    assert!(
        receiver
            .wallet
            .rgb_runtime()
            .unwrap()
            .contracts()
            .unwrap()
            .is_empty()
    );
    println!(
        "PERF_PREFETCH_FAILURE indexer={} no_assets=true no_contracts=true",
        failing_indexer
    );
}
