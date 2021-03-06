//! Functions for scanning the chain and extracting relevant information.

use ff::{PrimeField, PrimeFieldRepr};
use protobuf::parse_from_bytes;
use rusqlite::{types::ToSql, Connection, NO_PARAMS};
use std::path::Path;
use zcash_client_backend::{
    encoding::decode_extended_full_viewing_key, proto::compact_formats::CompactBlock,
    welding_rig::scan_block,
};
use zcash_primitives::{
    merkle_tree::{CommitmentTree, IncrementalWitness},
    sapling::Node,
    JUBJUB,
};

use crate::{
    error::{Error, ErrorKind},
    HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY, SAPLING_ACTIVATION_HEIGHT,
};

struct CompactBlockRow {
    height: i32,
    data: Vec<u8>,
}

#[derive(Clone)]
struct WitnessRow {
    id_note: i64,
    witness: IncrementalWitness<Node>,
}

/// Scans new blocks added to the cache for any transactions received by the tracked
/// accounts.
///
/// This function pays attention only to cached blocks with heights greater than the
/// highest scanned block in `db_data`. Cached blocks with lower heights are not verified
/// against previously-scanned blocks. In particular, this function **assumes** that the
/// caller is handling rollbacks.
///
/// For brand-new light client databases, this function starts scanning from the Sapling
/// activation height. This height can be fast-forwarded to a more recent block by calling
/// [`init_blocks_table`] before this function.
///
/// Scanned blocks are required to be height-sequential. If a block is missing from the
/// cache, an error will be returned with kind [`ErrorKind::InvalidHeight`].
///
/// # Examples
///
/// ```
/// use zcash_client_sqlite::scan::scan_cached_blocks;
///
/// scan_cached_blocks("/path/to/cache.db", "/path/to/data.db");
/// ```
///
/// [`init_blocks_table`]: crate::init::init_blocks_table
pub fn scan_cached_blocks<P: AsRef<Path>, Q: AsRef<Path>>(
    db_cache: P,
    db_data: Q,
) -> Result<(), Error> {
    let cache = Connection::open(db_cache)?;
    let data = Connection::open(db_data)?;

    // Recall where we synced up to previously.
    // If we have never synced, use sapling activation height to select all cached CompactBlocks.
    let mut last_height = data.query_row("SELECT MAX(height) FROM blocks", NO_PARAMS, |row| {
        row.get(0).or(Ok(SAPLING_ACTIVATION_HEIGHT - 1))
    })?;

    // Fetch the CompactBlocks we need to scan
    let mut stmt_blocks = cache
        .prepare("SELECT height, data FROM compactblocks WHERE height > ? ORDER BY height ASC")?;
    let rows = stmt_blocks.query_map(&[last_height], |row| {
        Ok(CompactBlockRow {
            height: row.get(0)?,
            data: row.get(1)?,
        })
    })?;

    // Fetch the ExtendedFullViewingKeys we are tracking
    let mut stmt_fetch_accounts =
        data.prepare("SELECT extfvk FROM accounts ORDER BY account ASC")?;
    let extfvks = stmt_fetch_accounts.query_map(NO_PARAMS, |row| {
        row.get(0).map(|extfvk: String| {
            decode_extended_full_viewing_key(HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY, &extfvk)
        })
    })?;
    // Raise SQL errors from the query, IO errors from parsing, and incorrect HRP errors.
    let extfvks: Vec<_> = extfvks
        .collect::<Result<Result<Option<_>, _>, _>>()??
        .ok_or(Error(ErrorKind::IncorrectHRPExtFVK))?;

    // Get the most recent CommitmentTree
    let mut stmt_fetch_tree = data.prepare("SELECT sapling_tree FROM blocks WHERE height = ?")?;
    let mut tree = stmt_fetch_tree
        .query_row(&[last_height], |row| {
            row.get(0).map(|data: Vec<_>| {
                CommitmentTree::read(&data[..]).unwrap_or_else(|_| CommitmentTree::new())
            })
        })
        .unwrap_or_else(|_| CommitmentTree::new());

    // Get most recent incremental witnesses for the notes we are tracking
    let mut stmt_fetch_witnesses =
        data.prepare("SELECT note, witness FROM sapling_witnesses WHERE block = ?")?;
    let witnesses = stmt_fetch_witnesses.query_map(&[last_height], |row| {
        let id_note = row.get(0)?;
        let data: Vec<_> = row.get(1)?;
        Ok(IncrementalWitness::read(&data[..]).map(|witness| WitnessRow { id_note, witness }))
    })?;
    let mut witnesses: Vec<_> = witnesses.collect::<Result<Result<_, _>, _>>()??;

    // Get the nullifiers for the notes we are tracking
    let mut stmt_fetch_nullifiers =
        data.prepare("SELECT id_note, nf, account FROM received_notes WHERE spent IS NULL")?;
    let nullifiers = stmt_fetch_nullifiers.query_map(NO_PARAMS, |row| {
        let nf: Vec<_> = row.get(1)?;
        let account: i64 = row.get(2)?;
        Ok((nf, account as usize))
    })?;
    let mut nullifiers: Vec<_> = nullifiers.collect::<Result<_, _>>()?;

    // Prepare per-block SQL statements
    let mut stmt_insert_block = data.prepare(
        "INSERT INTO blocks (height, hash, time, sapling_tree)
        VALUES (?, ?, ?, ?)",
    )?;
    let mut stmt_update_tx = data.prepare(
        "UPDATE transactions
        SET block = ?, tx_index = ? WHERE txid = ?",
    )?;
    let mut stmt_insert_tx = data.prepare(
        "INSERT INTO transactions (txid, block, tx_index)
        VALUES (?, ?, ?)",
    )?;
    let mut stmt_select_tx = data.prepare("SELECT id_tx FROM transactions WHERE txid = ?")?;
    let mut stmt_mark_spent_note =
        data.prepare("UPDATE received_notes SET spent = ? WHERE nf = ?")?;
    let mut stmt_insert_note = data.prepare(
        "INSERT INTO received_notes (tx, output_index, account, diversifier, value, rcm, nf, is_change)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )?;
    let mut stmt_insert_witness = data.prepare(
        "INSERT INTO sapling_witnesses (note, block, witness)
        VALUES (?, ?, ?)",
    )?;
    let mut stmt_prune_witnesses = data.prepare("DELETE FROM sapling_witnesses WHERE block < ?")?;
    let mut stmt_update_expired = data.prepare(
        "UPDATE received_notes SET spent = NULL WHERE EXISTS (
            SELECT id_tx FROM transactions
            WHERE id_tx = received_notes.spent AND block IS NULL AND expiry_height < ?
        )",
    )?;

    for row in rows {
        let row = row?;

        // Start an SQL transaction for this block.
        data.execute("BEGIN IMMEDIATE", NO_PARAMS)?;

        // Scanned blocks MUST be height-sequential.
        if row.height != (last_height + 1) {
            return Err(Error(ErrorKind::InvalidHeight(last_height + 1, row.height)));
        }
        last_height = row.height;

        let block: CompactBlock = parse_from_bytes(&row.data)?;
        let block_hash = block.hash.clone();
        let block_time = block.time;

        let txs = {
            let nf_refs: Vec<_> = nullifiers.iter().map(|(nf, acc)| (&nf[..], *acc)).collect();
            let mut witness_refs: Vec<_> = witnesses.iter_mut().map(|w| &mut w.witness).collect();
            scan_block(
                block,
                &extfvks[..],
                &nf_refs,
                &mut tree,
                &mut witness_refs[..],
            )
        };

        // Enforce that all roots match. This is slow, so only include in debug builds.
        #[cfg(debug_assertions)]
        {
            let cur_root = tree.root();
            for row in &witnesses {
                if row.witness.root() != cur_root {
                    return Err(Error(ErrorKind::InvalidWitnessAnchor(
                        row.id_note,
                        last_height,
                    )));
                }
            }
            for tx in &txs {
                for output in tx.shielded_outputs.iter() {
                    if output.witness.root() != cur_root {
                        return Err(Error(ErrorKind::InvalidNewWitnessAnchor(
                            output.index,
                            tx.txid,
                            last_height,
                            output.witness.root(),
                        )));
                    }
                }
            }
        }

        // Insert the block into the database.
        let mut encoded_tree = Vec::new();
        tree.write(&mut encoded_tree)
            .expect("Should be able to write to a Vec");
        stmt_insert_block.execute(&[
            row.height.to_sql()?,
            block_hash.to_sql()?,
            block_time.to_sql()?,
            encoded_tree.to_sql()?,
        ])?;

        for tx in txs {
            // First try update an existing transaction in the database.
            let txid = tx.txid.0.to_vec();
            let tx_row = if stmt_update_tx.execute(&[
                row.height.to_sql()?,
                (tx.index as i64).to_sql()?,
                txid.to_sql()?,
            ])? == 0
            {
                // It isn't there, so insert our transaction into the database.
                stmt_insert_tx.execute(&[
                    txid.to_sql()?,
                    row.height.to_sql()?,
                    (tx.index as i64).to_sql()?,
                ])?;
                data.last_insert_rowid()
            } else {
                // It was there, so grab its row number.
                stmt_select_tx.query_row(&[txid], |row| row.get(0))?
            };

            // Mark notes as spent and remove them from the scanning cache
            for spend in &tx.shielded_spends {
                stmt_mark_spent_note.execute(&[tx_row.to_sql()?, spend.nf.to_sql()?])?;
            }
            nullifiers = nullifiers
                .into_iter()
                .filter(|(nf, _acc)| {
                    tx.shielded_spends
                        .iter()
                        .find(|spend| &spend.nf == nf)
                        .is_none()
                })
                .collect();

            for output in tx.shielded_outputs {
                let mut rcm = [0; 32];
                output.note.r.into_repr().write_le(&mut rcm[..])?;
                let nf = output.note.nf(
                    &extfvks[output.account].fvk.vk,
                    output.witness.position() as u64,
                    &JUBJUB,
                );

                // Insert received note into the database.
                // Assumptions:
                // - A transaction will not contain more than 2^63 shielded outputs.
                // - A note value will never exceed 2^63 zatoshis.
                stmt_insert_note.execute(&[
                    tx_row.to_sql()?,
                    (output.index as i64).to_sql()?,
                    (output.account as i64).to_sql()?,
                    output.to.diversifier.0.to_sql()?,
                    (output.note.value as i64).to_sql()?,
                    rcm.to_sql()?,
                    nf.to_sql()?,
                    output.is_change.to_sql()?,
                ])?;
                let note_row = data.last_insert_rowid();

                // Save witness for note.
                witnesses.push(WitnessRow {
                    id_note: note_row,
                    witness: output.witness,
                });

                // Cache nullifier for note (to detect subsequent spends in this scan).
                nullifiers.push((nf, output.account));
            }
        }

        // Insert current witnesses into the database.
        let mut encoded = Vec::new();
        for witness_row in witnesses.iter() {
            encoded.clear();
            witness_row
                .witness
                .write(&mut encoded)
                .expect("Should be able to write to a Vec");
            stmt_insert_witness.execute(&[
                witness_row.id_note.to_sql()?,
                last_height.to_sql()?,
                encoded.to_sql()?,
            ])?;
        }

        // Prune the stored witnesses (we only expect rollbacks of at most 100 blocks).
        stmt_prune_witnesses.execute(&[last_height - 100])?;

        // Update now-expired transactions that didn't get mined.
        stmt_update_expired.execute(&[last_height])?;

        // Commit the SQL transaction, writing this block's data atomically.
        data.execute("COMMIT", NO_PARAMS)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use tempfile::NamedTempFile;
    use zcash_primitives::{
        block::BlockHash,
        transaction::components::Amount,
        zip32::{ExtendedFullViewingKey, ExtendedSpendingKey},
    };

    use super::scan_cached_blocks;
    use crate::{
        init::{init_accounts_table, init_cache_database, init_data_database},
        query::get_balance,
        tests::{fake_compact_block, fake_compact_block_spending, insert_into_cache},
        SAPLING_ACTIVATION_HEIGHT,
    };

    #[test]
    fn scan_cached_blocks_requires_sequential_blocks() {
        let cache_file = NamedTempFile::new().unwrap();
        let db_cache = cache_file.path();
        init_cache_database(&db_cache).unwrap();

        let data_file = NamedTempFile::new().unwrap();
        let db_data = data_file.path();
        init_data_database(&db_data).unwrap();

        // Add an account to the wallet
        let extsk = ExtendedSpendingKey::master(&[]);
        let extfvk = ExtendedFullViewingKey::from(&extsk);
        init_accounts_table(&db_data, &[extfvk.clone()]).unwrap();

        // Create a block with height SAPLING_ACTIVATION_HEIGHT
        let value = Amount::from_u64(50000).unwrap();
        let (cb1, _) = fake_compact_block(
            SAPLING_ACTIVATION_HEIGHT,
            BlockHash([0; 32]),
            extfvk.clone(),
            value,
        );
        insert_into_cache(db_cache, &cb1);
        scan_cached_blocks(db_cache, db_data).unwrap();
        assert_eq!(get_balance(db_data, 0).unwrap(), value);

        // We cannot scan a block of height SAPLING_ACTIVATION_HEIGHT + 2 next
        let (cb2, _) = fake_compact_block(
            SAPLING_ACTIVATION_HEIGHT + 1,
            cb1.hash(),
            extfvk.clone(),
            value,
        );
        let (cb3, _) = fake_compact_block(
            SAPLING_ACTIVATION_HEIGHT + 2,
            cb2.hash(),
            extfvk.clone(),
            value,
        );
        insert_into_cache(db_cache, &cb3);
        match scan_cached_blocks(db_cache, db_data) {
            Ok(_) => panic!("Should have failed"),
            Err(e) => assert_eq!(
                e.to_string(),
                format!(
                    "Expected height of next CompactBlock to be {}, but was {}",
                    SAPLING_ACTIVATION_HEIGHT + 1,
                    SAPLING_ACTIVATION_HEIGHT + 2
                )
            ),
        }

        // If we add a block of height SAPLING_ACTIVATION_HEIGHT + 1, we can now scan both
        insert_into_cache(db_cache, &cb2);
        scan_cached_blocks(db_cache, db_data).unwrap();
        assert_eq!(
            get_balance(db_data, 0).unwrap(),
            Amount::from_u64(150_000).unwrap()
        );
    }

    #[test]
    fn scan_cached_blocks_finds_received_notes() {
        let cache_file = NamedTempFile::new().unwrap();
        let db_cache = cache_file.path();
        init_cache_database(&db_cache).unwrap();

        let data_file = NamedTempFile::new().unwrap();
        let db_data = data_file.path();
        init_data_database(&db_data).unwrap();

        // Add an account to the wallet
        let extsk = ExtendedSpendingKey::master(&[]);
        let extfvk = ExtendedFullViewingKey::from(&extsk);
        init_accounts_table(&db_data, &[extfvk.clone()]).unwrap();

        // Account balance should be zero
        assert_eq!(get_balance(db_data, 0).unwrap(), Amount::zero());

        // Create a fake CompactBlock sending value to the address
        let value = Amount::from_u64(5).unwrap();
        let (cb, _) = fake_compact_block(
            SAPLING_ACTIVATION_HEIGHT,
            BlockHash([0; 32]),
            extfvk.clone(),
            value,
        );
        insert_into_cache(db_cache, &cb);

        // Scan the cache
        scan_cached_blocks(db_cache, db_data).unwrap();

        // Account balance should reflect the received note
        assert_eq!(get_balance(db_data, 0).unwrap(), value);

        // Create a second fake CompactBlock sending more value to the address
        let value2 = Amount::from_u64(7).unwrap();
        let (cb2, _) = fake_compact_block(SAPLING_ACTIVATION_HEIGHT + 1, cb.hash(), extfvk, value2);
        insert_into_cache(db_cache, &cb2);

        // Scan the cache again
        scan_cached_blocks(db_cache, db_data).unwrap();

        // Account balance should reflect both received notes
        assert_eq!(get_balance(db_data, 0).unwrap(), value + value2);
    }

    #[test]
    fn scan_cached_blocks_finds_change_notes() {
        let cache_file = NamedTempFile::new().unwrap();
        let db_cache = cache_file.path();
        init_cache_database(&db_cache).unwrap();

        let data_file = NamedTempFile::new().unwrap();
        let db_data = data_file.path();
        init_data_database(&db_data).unwrap();

        // Add an account to the wallet
        let extsk = ExtendedSpendingKey::master(&[]);
        let extfvk = ExtendedFullViewingKey::from(&extsk);
        init_accounts_table(&db_data, &[extfvk.clone()]).unwrap();

        // Account balance should be zero
        assert_eq!(get_balance(db_data, 0).unwrap(), Amount::zero());

        // Create a fake CompactBlock sending value to the address
        let value = Amount::from_u64(5).unwrap();
        let (cb, nf) = fake_compact_block(
            SAPLING_ACTIVATION_HEIGHT,
            BlockHash([0; 32]),
            extfvk.clone(),
            value,
        );
        insert_into_cache(db_cache, &cb);

        // Scan the cache
        scan_cached_blocks(db_cache, db_data).unwrap();

        // Account balance should reflect the received note
        assert_eq!(get_balance(db_data, 0).unwrap(), value);

        // Create a second fake CompactBlock spending value from the address
        let extsk2 = ExtendedSpendingKey::master(&[0]);
        let to2 = extsk2.default_address().unwrap().1;
        let value2 = Amount::from_u64(2).unwrap();
        insert_into_cache(
            db_cache,
            &fake_compact_block_spending(
                SAPLING_ACTIVATION_HEIGHT + 1,
                cb.hash(),
                (nf, value),
                extfvk,
                to2,
                value2,
            ),
        );

        // Scan the cache again
        scan_cached_blocks(db_cache, db_data).unwrap();

        // Account balance should equal the change
        assert_eq!(get_balance(db_data, 0).unwrap(), value - value2);
    }
}
