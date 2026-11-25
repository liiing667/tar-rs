extern crate tar;
extern crate tempfile;

use std::fs;
use std::path::{Path, PathBuf};
use tar::{Archive, Builder, EntryType, Header};

#[derive(Clone, Debug)]
enum E {
    Symlink(&'static str, &'static str),
    Reg(&'static str, &'static [u8]),
    Dir(&'static str),
    Hard(&'static str, &'static str),
}

fn build(entries: &[E]) -> Vec<u8> {
    let mut ar = Builder::new(Vec::new());
    for e in entries {
        let mut h = Header::new_gnu();
        h.set_size(0);
        match *e {
            E::Symlink(p, t) => {
                h.set_entry_type(EntryType::Symlink);
                h.set_path(p).unwrap();
                h.set_link_name(t).unwrap();
            }
            E::Reg(p, d) => {
                h.set_entry_type(EntryType::Regular);
                h.set_path(p).unwrap();
                h.set_size(d.len() as u64);
            }
            E::Dir(p) => {
                h.set_entry_type(EntryType::Directory);
                h.set_path(p).unwrap();
                h.set_mode(0o755);
            }
            E::Hard(p, t) => {
                h.set_entry_type(EntryType::Link);
                h.set_path(p).unwrap();
                h.set_link_name(t).unwrap();
            }
        }
        h.set_cksum();
        match *e {
            E::Reg(_, d) => ar.append(&h, d).unwrap(),
            _ => ar.append(&h, &[][..]).unwrap(),
        }
    }
    ar.finish().unwrap();
    ar.into_inner().unwrap()
}

fn walk_outside(dir: &Path, root: &Path, found: &mut Vec<PathBuf>) {
    for ent in fs::read_dir(dir).unwrap() {
        let ent = ent.unwrap();
        let p = ent.path();
        if p == root { continue; }
        let ft = ent.file_type().unwrap();
        if ft.is_dir() {
            walk_outside(&p, root, found);
        } else if p.file_name().map(|n| n != "victim").unwrap_or(true) {
            found.push(p);
        }
    }
}

fn victim_ok(td: &Path) -> bool {
    let victim = td.join("out").join("victim");
    match fs::read(&victim) {
        Ok(v) => v == b"victim",
        Err(_) => false,
    }
}

#[test]
fn probe_escape() {
    let paths = ["a", "b", "a/b", "b/a", "sub"];
    let targets = ["a", "b", ".", "..", "../out", "../../out", "../victim", "/tmp/absout"];
    let mut entries: Vec<E> = Vec::new();
    for &p in &paths {
        entries.push(E::Symlink(p, targets[0]));
    }
    let mut cases: Vec<Vec<E>> = Vec::new();
    // 2-entry: symlink then regular/dir/hard/symlink
    for &sp in &paths {
        for &t in &targets {
            for &p2 in &paths {
                cases.push(vec![E::Symlink(sp, t), E::Reg(p2, b"x")]);
                cases.push(vec![E::Symlink(sp, t), E::Dir(p2)]);
                cases.push(vec![E::Symlink(sp, t), E::Hard(p2, "a")]);
                for &t2 in &targets {
                    cases.push(vec![E::Symlink(sp, t), E::Symlink(p2, t2)]);
                }
            }
        }
    }
    // 3-entry: dir/symlink, symlink, regular
    for &d in &paths {
        for &sp in &paths {
            for &t in &targets {
                for &p3 in &paths {
                    cases.push(vec![E::Dir(d), E::Symlink(sp, t), E::Reg(p3, b"x")]);
                }
            }
        }
    }
    let mut hits = 0;
    let mut cases_with_escape = 0;
    for case in cases {
        let td = tempfile::Builder::new().prefix("probe").tempdir().unwrap();
        fs::create_dir(td.path().join("out")).unwrap();
        fs::write(td.path().join("out").join("victim"), b"victim").unwrap();
        let root = td.path().join("extract");
        let bytes = build(&case);
        let mut ar = Archive::new(&bytes[..]);
        let res = ar.unpack(&root);
        let mut found = Vec::new();
        walk_outside(td.path(), &root, &mut found);
        if (!found.is_empty() || !victim_ok(td.path())) && td.path().join("out/victim").exists() {
            cases_with_escape += 1;
        }
        if !found.is_empty() || !victim_ok(td.path()) {
            hits += 1;
            if hits < 20 {
                println!("HIT {:?} res={:?} found={:?} victim={}", case, res.is_ok(), found, victim_ok(td.path()));
            }
        }
    }
    println!("total hits: {} escapes: {}", hits, cases_with_escape);
}
