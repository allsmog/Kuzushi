use super::*;
use crate::read_capability::ReadRootCapability;

#[test]
fn receipt_count_limit_accepts_exact_bound_then_rejects_overflow() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::create_dir(temp.path().join("child")).unwrap();
    let capability = ReadRootCapability::new([temp.path().to_path_buf()]).unwrap();
    let root = capability.authorize_directory(temp.path()).unwrap();
    let entries = root.entries(4).unwrap();
    let mut revisions = AuthorizedDirectoryRevisions::with_limits(&root, 1, usize::MAX);

    revisions.retain(&root, &entries).unwrap();
    let error = revisions.retain(&root, &entries).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("1-directory revision receipt limit"),
        "{error:#}"
    );
}

#[test]
fn receipt_path_limit_accepts_exact_bound_then_rejects_overflow() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::create_dir(temp.path().join("abc")).unwrap();
    std::fs::create_dir(temp.path().join("z")).unwrap();
    let capability = ReadRootCapability::new([temp.path().to_path_buf()]).unwrap();
    let root = capability.authorize_directory(temp.path()).unwrap();
    let children = root.entries(4).unwrap();
    let child = |name: &str| {
        let entry = children
            .iter()
            .find(|entry| entry.name() == std::ffi::OsStr::new(name))
            .unwrap();
        let super::super::directory::AuthorizedChild::Directory(child) =
            root.open_child(entry).unwrap()
        else {
            panic!("test child was not a directory")
        };
        child
    };
    let abc = child("abc");
    let z = child("z");
    let path_limit = encoded_path_len(&abc.relative).unwrap();
    let mut revisions = AuthorizedDirectoryRevisions::with_limits(&root, 3, path_limit);

    revisions.retain(&root, &children).unwrap();
    revisions.retain(&abc, &abc.entries(1).unwrap()).unwrap();
    let error = revisions.retain(&z, &z.entries(1).unwrap()).unwrap_err();

    assert!(
        error
            .to_string()
            .contains(&format!("{path_limit}-byte directory revision path limit")),
        "{error:#}"
    );
}

#[test]
fn receipt_constructor_rejects_entry_limit_overflow() {
    let temp = tempfile::tempdir().unwrap();
    let capability = ReadRootCapability::new([temp.path().to_path_buf()]).unwrap();
    let root = capability.authorize_directory(temp.path()).unwrap();

    let error = AuthorizedDirectoryRevisions::new(&root, usize::MAX).unwrap_err();

    assert!(
        error.to_string().contains("receipt limit overflow"),
        "{error:#}"
    );
}

#[cfg(windows)]
#[test]
fn entry_fingerprint_rejects_restored_subset_with_restored_timestamps() {
    let temp = tempfile::tempdir().unwrap();
    let tree = temp.path().join("tree");
    let omitted = tree.join("omitted");
    let retained = temp.path().join("retained");
    std::fs::create_dir(&tree).unwrap();
    std::fs::write(tree.join("included"), "included").unwrap();
    std::fs::write(&omitted, "omitted").unwrap();
    std::fs::rename(&omitted, &retained).unwrap();
    let capability = ReadRootCapability::new([tree.clone()]).unwrap();
    let root = capability.authorize_directory(&tree).unwrap();
    let entries = root.entries(2).unwrap();
    let mut revisions = AuthorizedDirectoryRevisions::new(&root, 2).unwrap();
    revisions.retain(&root, &entries).unwrap();
    let attributes = WindowsBasicAttributes::capture(&tree);

    std::fs::rename(&retained, &omitted).unwrap();
    attributes.restore();

    verify_revision(&root.file, &root.identity, &root.path).unwrap();
    let error = revisions.verify_all_unchanged().unwrap_err();
    assert!(
        error.to_string().contains("directory entries changed"),
        "{error:#}"
    );
}

#[cfg(windows)]
struct WindowsBasicAttributes {
    path: PathBuf,
    info: windows_sys::Win32::Storage::FileSystem::FILE_BASIC_INFO,
}

#[cfg(windows)]
impl WindowsBasicAttributes {
    fn capture(path: &Path) -> Self {
        let file = open_windows_attribute_handle(path);
        let info = query_windows_basic_attributes(&file);
        Self {
            path: path.to_path_buf(),
            info,
        }
    }

    fn restore(&self) {
        use std::mem::size_of;
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            FileBasicInfo, SetFileInformationByHandle, FILE_BASIC_INFO,
        };

        let file = open_windows_attribute_handle(&self.path);
        // SAFETY: the handle grants FILE_WRITE_ATTRIBUTES and `self.info`
        // exactly matches the fixed FileBasicInfo information class.
        let succeeded = unsafe {
            SetFileInformationByHandle(
                file.as_raw_handle(),
                FileBasicInfo,
                std::ptr::from_ref(&self.info).cast(),
                size_of::<FILE_BASIC_INFO>() as u32,
            )
        };
        assert_ne!(succeeded, 0, "{}", std::io::Error::last_os_error());
    }
}

#[cfg(windows)]
fn open_windows_attribute_handle(path: &Path) -> std::fs::File {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_ATTRIBUTES, OPEN_EXISTING,
    };

    let mut path = path.as_os_str().encode_wide().collect::<Vec<_>>();
    path.push(0);
    // SAFETY: `path` is NUL-terminated and a successful fresh handle is
    // transferred directly into `File` ownership.
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            std::ptr::null_mut(),
        )
    };
    assert_ne!(handle, INVALID_HANDLE_VALUE);
    // SAFETY: CreateFileW returned a fresh, valid, owned handle.
    unsafe { std::fs::File::from_raw_handle(handle) }
}

#[cfg(windows)]
fn query_windows_basic_attributes(
    file: &std::fs::File,
) -> windows_sys::Win32::Storage::FileSystem::FILE_BASIC_INFO {
    use std::mem::{size_of, MaybeUninit};
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FileBasicInfo, GetFileInformationByHandleEx, FILE_BASIC_INFO,
    };

    let mut info = MaybeUninit::<FILE_BASIC_INFO>::zeroed();
    // SAFETY: `info` is writable for the exact fixed-size information class.
    let succeeded = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileBasicInfo,
            info.as_mut_ptr().cast(),
            size_of::<FILE_BASIC_INFO>() as u32,
        )
    };
    assert_ne!(succeeded, 0, "{}", std::io::Error::last_os_error());
    // SAFETY: the successful API call initialized the complete structure.
    unsafe { info.assume_init() }
}
