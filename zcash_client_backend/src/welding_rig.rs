//! Tools for scanning a compact representation of the Zcash block chain.

use ff::{PrimeField, PrimeFieldRepr};
use pairing::bls12_381::{Bls12, Fr, FrRepr};
use std::collections::HashSet;
use zcash_primitives::{
    jubjub::{edwards, fs::Fs},
    merkle_tree::{CommitmentTree, IncrementalWitness},
    note_encryption::try_sapling_compact_note_decryption,
    sapling::Node,
    transaction::TxId,
    zip32::ExtendedFullViewingKey,
    JUBJUB,
};

use crate::proto::compact_formats::{CompactBlock, CompactOutput};
use crate::wallet::{WalletShieldedOutput, WalletShieldedSpend, WalletTx};

/// Scans a [`CompactOutput`] with a set of [`ExtendedFullViewingKey`]s.
///
/// Returns a [`WalletShieldedOutput`] and corresponding [`IncrementalWitness`] if this
/// output belongs to any of the given [`ExtendedFullViewingKey`]s.
///
/// The given [`CommitmentTree`] and existing [`IncrementalWitness`]es are incremented
/// with this output's commitment.
fn scan_output(
    (index, output): (usize, CompactOutput),
    ivks: &[Fs],
    spent_from_accounts: &HashSet<usize>,
    tree: &mut CommitmentTree<Node>,
    existing_witnesses: &mut [&mut IncrementalWitness<Node>],
    new_witnesses: &mut [IncrementalWitness<Node>],
) -> Option<(WalletShieldedOutput, IncrementalWitness<Node>)> {
    let mut repr = FrRepr::default();
    if repr.read_le(&output.cmu[..]).is_err() {
        return None;
    }
    let cmu = match Fr::from_repr(repr) {
        Ok(cmu) => cmu,
        Err(_) => return None,
    };

    let epk = match edwards::Point::<Bls12, _>::read(&output.epk[..], &JUBJUB) {
        Ok(p) => match p.as_prime_order(&JUBJUB) {
            Some(epk) => epk,
            None => return None,
        },
        Err(_) => return None,
    };

    let ct = output.ciphertext;

    // Increment tree and witnesses
    let node = Node::new(cmu.into_repr());
    for witness in existing_witnesses {
        witness.append(node).unwrap();
    }
    for witness in new_witnesses {
        witness.append(node).unwrap();
    }
    tree.append(node).unwrap();

    for (account, ivk) in ivks.iter().enumerate() {
        let (note, to) = match try_sapling_compact_note_decryption(ivk, &epk, &cmu, &ct) {
            Some(ret) => ret,
            None => continue,
        };

        // A note is marked as "change" if the account that received it
        // also spent notes in the same transaction. This will catch,
        // for instance:
        // - Change created by spending fractions of notes.
        // - Notes created by consolidation transactions.
        // - Notes sent from one account to itself.
        let is_change = spent_from_accounts.contains(&account);

        return Some((
            WalletShieldedOutput {
                index,
                cmu,
                epk,
                account,
                note,
                to,
                is_change,
            },
            IncrementalWitness::from_tree(tree),
        ));
    }
    None
}

/// Scans a [`CompactBlock`] with a set of [`ExtendedFullViewingKey`]s.
///
/// Returns a vector of [`WalletTx`]s belonging to any of the given
/// [`ExtendedFullViewingKey`]s, and the corresponding new [`IncrementalWitness`]es.
///
/// The given [`CommitmentTree`] and existing [`IncrementalWitness`]es are
/// incremented appropriately.
pub fn scan_block(
    block: CompactBlock,
    extfvks: &[ExtendedFullViewingKey],
    nullifiers: &[(&[u8], usize)],
    tree: &mut CommitmentTree<Node>,
    existing_witnesses: &mut [&mut IncrementalWitness<Node>],
) -> Vec<(WalletTx, Vec<IncrementalWitness<Node>>)> {
    let mut wtxs = vec![];
    let ivks: Vec<_> = extfvks.iter().map(|extfvk| extfvk.fvk.vk.ivk()).collect();

    for tx in block.vtx.into_iter() {
        let num_spends = tx.spends.len();
        let num_outputs = tx.outputs.len();

        // Check for spent notes
        let shielded_spends: Vec<_> =
            tx.spends
                .into_iter()
                .enumerate()
                .filter_map(|(index, spend)| {
                    if let Some(account) = nullifiers.iter().find_map(|&(nf, acc)| {
                        if nf == &spend.nf[..] {
                            Some(acc)
                        } else {
                            None
                        }
                    }) {
                        Some(WalletShieldedSpend {
                            index,
                            nf: spend.nf,
                            account,
                        })
                    } else {
                        None
                    }
                })
                .collect();

        // Collect the set of accounts that were spent from in this transaction
        let spent_from_accounts: HashSet<_> =
            shielded_spends.iter().map(|spend| spend.account).collect();

        // Check for incoming notes while incrementing tree and witnesses
        let mut shielded_outputs = vec![];
        let mut new_witnesses = vec![];
        for to_scan in tx.outputs.into_iter().enumerate() {
            if let Some((output, new_witness)) = scan_output(
                to_scan,
                &ivks,
                &spent_from_accounts,
                tree,
                existing_witnesses,
                &mut new_witnesses,
            ) {
                shielded_outputs.push(output);
                new_witnesses.push(new_witness);
            }
        }

        if !(shielded_spends.is_empty() && shielded_outputs.is_empty()) {
            let mut txid = TxId([0u8; 32]);
            txid.0.copy_from_slice(&tx.hash);
            wtxs.push((
                WalletTx {
                    txid,
                    num_spends,
                    num_outputs,
                    shielded_spends,
                    shielded_outputs,
                },
                new_witnesses,
            ));
        }
    }

    wtxs
}

#[cfg(test)]
mod tests {
    use ff::{Field, PrimeField, PrimeFieldRepr};
    use pairing::bls12_381::{Bls12, Fr};
    use rand_core::RngCore;
    use rand_os::OsRng;
    use zcash_primitives::{
        jubjub::{fs::Fs, FixedGenerators, JubjubParams, ToUniform},
        merkle_tree::CommitmentTree,
        note_encryption::{Memo, SaplingNoteEncryption},
        primitives::Note,
        transaction::components::Amount,
        zip32::{ExtendedFullViewingKey, ExtendedSpendingKey},
        JUBJUB,
    };

    use super::scan_block;
    use crate::proto::compact_formats::{CompactBlock, CompactOutput, CompactSpend, CompactTx};

    fn random_compact_tx<R: RngCore>(rng: &mut R) -> CompactTx {
        let fake_nf = {
            let mut nf = vec![0; 32];
            rng.fill_bytes(&mut nf);
            nf
        };
        let fake_cmu = {
            let fake_cmu = Fr::random(rng);
            let mut bytes = vec![];
            fake_cmu.into_repr().write_le(&mut bytes).unwrap();
            bytes
        };
        let fake_epk = {
            let mut buffer = vec![0; 64];
            rng.fill_bytes(&mut buffer);
            let fake_esk = Fs::to_uniform(&buffer[..]);
            let fake_epk = JUBJUB
                .generator(FixedGenerators::SpendingKeyGenerator)
                .mul(fake_esk, &JUBJUB);
            let mut bytes = vec![];
            fake_epk.write(&mut bytes).unwrap();
            bytes
        };
        let mut cspend = CompactSpend::new();
        cspend.set_nf(fake_nf);
        let mut cout = CompactOutput::new();
        cout.set_cmu(fake_cmu);
        cout.set_epk(fake_epk);
        cout.set_ciphertext(vec![0; 52]);
        let mut ctx = CompactTx::new();
        let mut txid = vec![0; 32];
        rng.fill_bytes(&mut txid);
        ctx.set_hash(txid);
        ctx.spends.push(cspend);
        ctx.outputs.push(cout);
        ctx
    }

    /// Create a fake CompactBlock at the given height, with a transaction containing a
    /// single spend of the given nullifier and a single output paying the given address.
    /// Returns the CompactBlock.
    fn fake_compact_block(
        height: i32,
        nf: [u8; 32],
        extfvk: ExtendedFullViewingKey,
        value: Amount,
    ) -> CompactBlock {
        let to = extfvk.default_address().unwrap().1;

        // Create a fake Note for the account
        let mut rng = OsRng;
        let note = Note {
            g_d: to.diversifier.g_d::<Bls12>(&JUBJUB).unwrap(),
            pk_d: to.pk_d.clone(),
            value: value.into(),
            r: Fs::random(&mut rng),
        };
        let encryptor = SaplingNoteEncryption::new(
            extfvk.fvk.ovk,
            note.clone(),
            to.clone(),
            Memo::default(),
            &mut rng,
        );
        let mut cmu = vec![];
        note.cm(&JUBJUB).into_repr().write_le(&mut cmu).unwrap();
        let mut epk = vec![];
        encryptor.epk().write(&mut epk).unwrap();
        let enc_ciphertext = encryptor.encrypt_note_plaintext();

        // Create a fake CompactBlock containing the note
        let mut cb = CompactBlock::new();
        cb.set_height(height as u64);

        // Add a random Sapling tx before ours
        cb.vtx.push(random_compact_tx(&mut rng));

        let mut cspend = CompactSpend::new();
        cspend.set_nf(nf.to_vec());
        let mut cout = CompactOutput::new();
        cout.set_cmu(cmu);
        cout.set_epk(epk);
        cout.set_ciphertext(enc_ciphertext[..52].to_vec());
        let mut ctx = CompactTx::new();
        let mut txid = vec![0; 32];
        rng.fill_bytes(&mut txid);
        ctx.set_hash(txid);
        ctx.spends.push(cspend);
        ctx.outputs.push(cout);
        cb.vtx.push(ctx);

        cb
    }

    #[test]
    fn scan_block_with_my_tx() {
        let extsk = ExtendedSpendingKey::master(&[]);
        let extfvk = ExtendedFullViewingKey::from(&extsk);

        let cb = fake_compact_block(1, [0; 32], extfvk.clone(), Amount::from_u64(5).unwrap());
        assert_eq!(cb.vtx.len(), 2);

        let mut tree = CommitmentTree::new();
        let txs = scan_block(cb, &[extfvk], &[], &mut tree, &mut []);
        assert_eq!(txs.len(), 1);

        let (tx, new_witnesses) = &txs[0];
        assert_eq!(tx.num_spends, 1);
        assert_eq!(tx.num_outputs, 1);
        assert_eq!(tx.shielded_spends.len(), 0);
        assert_eq!(tx.shielded_outputs.len(), 1);
        assert_eq!(tx.shielded_outputs[0].index, 0);
        assert_eq!(tx.shielded_outputs[0].account, 0);
        assert_eq!(tx.shielded_outputs[0].note.value, 5);

        // Check that the witness root matches
        assert_eq!(new_witnesses.len(), 1);
        assert_eq!(new_witnesses[0].root(), tree.root());
    }

    #[test]
    fn scan_block_with_my_spend() {
        let extsk = ExtendedSpendingKey::master(&[]);
        let extfvk = ExtendedFullViewingKey::from(&extsk);
        let nf = [7; 32];
        let account = 12;

        let cb = fake_compact_block(1, nf, extfvk, Amount::from_u64(5).unwrap());
        assert_eq!(cb.vtx.len(), 2);

        let mut tree = CommitmentTree::new();
        let txs = scan_block(cb, &[], &[(&nf, account)], &mut tree, &mut []);
        assert_eq!(txs.len(), 1);

        let (tx, new_witnesses) = &txs[0];
        assert_eq!(tx.num_spends, 1);
        assert_eq!(tx.num_outputs, 1);
        assert_eq!(tx.shielded_spends.len(), 1);
        assert_eq!(tx.shielded_outputs.len(), 0);
        assert_eq!(tx.shielded_spends[0].index, 0);
        assert_eq!(tx.shielded_spends[0].nf, nf);
        assert_eq!(tx.shielded_spends[0].account, account);
        assert_eq!(new_witnesses.len(), 0);
    }
}