use std::fs;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use casc_lib::blte::encryption::TactKeyStore;
use casc_lib::config::build_config::parse_build_config;
use casc_lib::config::build_info::parse_build_info;
use casc_lib::encoding::parser::EncodingFile;
use casc_lib::extract::CascStorage;
use casc_lib::listfile::parser::Listfile;
use casc_lib::root::parser::RootFile;
use casc_lib::storage::data::{DATA_HEADER_SIZE, DataStore};
use casc_lib::storage::index::{CascIndex, bucket_index};
use md5::{Digest, Md5};

struct ArchiveDirectory(PathBuf);

impl ArchiveDirectory {
    fn new() -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        loop {
            let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("casc-archive-reads-{}-{id}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("create archive fixture directory: {error}"),
            }
        }
    }
}

impl Drop for ArchiveDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn encoding_file(ckey: &[u8; 16], ekey: &[u8; 16], file_size: u64) -> EncodingFile {
    let mut page = vec![0; 1024];
    page[0] = 1; // One EKey for this CKey.
    page[1..6].copy_from_slice(&file_size.to_be_bytes()[3..]);
    page[6..22].copy_from_slice(ckey);
    page[22..38].copy_from_slice(ekey);

    let mut data = Vec::new();
    data.extend_from_slice(b"EN");
    data.extend_from_slice(&[1, 16, 16]); // Version and hash widths.
    data.extend_from_slice(&1u16.to_be_bytes()); // CE page size in KiB.
    data.extend_from_slice(&1u16.to_be_bytes()); // ESpec page size in KiB.
    data.extend_from_slice(&1u32.to_be_bytes()); // One CE page.
    data.extend_from_slice(&0u32.to_be_bytes()); // No ESpec pages.
    data.push(0); // Flags.
    data.extend_from_slice(&0u32.to_be_bytes()); // Empty ESpec string block.
    data.extend_from_slice(ckey); // First CKey in the page index.
    data.extend_from_slice(&Md5::digest(&page));
    data.extend_from_slice(&page);
    EncodingFile::parse(&data).unwrap()
}

#[test]
fn read_by_ckey_decodes_entry_after_archive_header_at_indexed_offset() {
    let directory = ArchiveDirectory::new();
    let expected = b"archive payload\0with binary bytes\xff\x80\n";
    let ckey: [u8; 16] = Md5::digest(expected).into();
    let mut blte = b"BLTE\0\0\0\0N".to_vec();
    blte.extend_from_slice(expected);
    let ekey: [u8; 16] = Md5::digest(&blte).into();
    let entry_size = (DATA_HEADER_SIZE + blte.len()) as u32;
    let archive_number = 7u32;
    let archive_offset = 128u64;

    let mut header = [0; DATA_HEADER_SIZE];
    let mut reversed_ekey = ekey;
    reversed_ekey.reverse();
    header[..16].copy_from_slice(&reversed_ekey);
    header[16..20].copy_from_slice(&entry_size.to_le_bytes());

    let mut archive = vec![0xa5; archive_offset as usize];
    archive.extend_from_slice(&header);
    archive.extend_from_slice(&blte);
    archive.extend_from_slice(b"outside the indexed entry");
    fs::write(directory.0.join("data.007"), archive).unwrap();

    // Index offsets point to the archive header; sizes include that header.
    let bucket = bucket_index(&ekey);
    let mut index = vec![0; 0x28];
    index[..4].copy_from_slice(&0x10u32.to_le_bytes());
    index[8..10].copy_from_slice(&7u16.to_le_bytes());
    index[10] = bucket;
    index[12..16].copy_from_slice(&[4, 5, 9, 30]);
    index[0x20..0x24].copy_from_slice(&18u32.to_le_bytes());
    index.extend_from_slice(&ekey[..9]);
    let packed_offset = (u64::from(archive_number) << 30) | archive_offset;
    index.extend_from_slice(&packed_offset.to_be_bytes()[3..]);
    index.extend_from_slice(&entry_size.to_le_bytes());
    fs::write(directory.0.join(format!("{bucket:02x}00000001.idx")), index).unwrap();

    // Drop the storage's memory maps before removing the directory, including on panic.
    {
        let storage = CascStorage {
            build_info: parse_build_info("Product!STRING:0|Active!DEC:1\nwow|1\n")
                .unwrap()
                .remove(0),
            build_config: parse_build_config("").unwrap(),
            index: CascIndex::load(&directory.0).unwrap(),
            data: DataStore::open(&directory.0).unwrap(),
            encoding: encoding_file(&ckey, &ekey, expected.len() as u64),
            root: RootFile::parse(&[0; 12]).unwrap(),
            listfile: Listfile::parse(""),
            keystore: TactKeyStore::new(),
        };

        assert_eq!(storage.read_by_ckey(&ckey).unwrap(), expected);
    }
}
