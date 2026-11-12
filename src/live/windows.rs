use std::ffi::OsString;
use std::mem::size_of;
use std::os::windows::ffi::OsStringExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

use anyhow::{Context, Result, bail, ensure};
use windows_sys::Win32::Foundation::{
    ERROR_FILE_INVALID, ERROR_INVALID_PARAMETER, ERROR_NO_MORE_FILES, FILETIME,
    INVALID_HANDLE_VALUE, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_MAPPED, MEMORY_BASIC_INFORMATION, PAGE_READWRITE, VirtualQueryEx,
};
use windows_sys::Win32::System::ProcessStatus::K32GetMappedFileNameW;
use windows_sys::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_SYNCHRONIZE, PROCESS_VM_READ,
    QueryFullProcessImageNameW, WaitForSingleObject,
};

use super::*;
use crate::cancellation::is_cancellation_error;

const MAX_REGIONS: usize = 1_000_000;
const PATH_CAPACITY: usize = 32_768;
const MIN_VMEM_BYTES: u64 = 16 * 1024 * 1024;
const MAX_VMEM_BYTES: u64 = 1024 * 1024 * 1024 * 1024;

pub(super) mod display;

struct WindowsProcess {
    handle: OwnedHandle,
    pid: u32,
}

impl WindowsProcess {
    fn open(pid: u32) -> Result<Self> {
        ensure!(usize::BITS == 64, "VMware 实时读取需要 64 位 Windows 进程");
        // Only query, read and exit detection; no VM write/operation/debug rights.
        let raw = unsafe {
            OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_SYNCHRONIZE,
                0,
                pid,
            )
        };
        ensure!(
            !raw.is_null(),
            "无法只读打开 PID {pid}：{}；请核对虚拟机是否运行以及当前权限，必要时在提升权限的终端重试",
            std::io::Error::last_os_error()
        );
        // SAFETY: OpenProcess returned a new non-null handle owned by this object.
        Ok(Self {
            handle: unsafe { OwnedHandle::from_raw_handle(raw) },
            pid,
        })
    }

    fn check_running(&self) -> Result<()> {
        // SAFETY: the owned handle remains valid for this call; this is a poll.
        match unsafe { WaitForSingleObject(self.handle.as_raw_handle(), 0) } {
            WAIT_TIMEOUT => Ok(()),
            WAIT_OBJECT_0 => bail!("目标 VMware 进程已退出"),
            _ => Err(std::io::Error::last_os_error()).context("无法确认 VMware 进程存活状态"),
        }
    }

    fn identity(&self) -> Result<VmwareProcessIdentity> {
        self.check_running()?;
        let mut path = vec![0u16; PATH_CAPACITY];
        let mut length = path.len() as u32;
        let mut created = FILETIME::default();
        let mut exited = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        // SAFETY: both output buffers and all FILETIME values are valid and sized.
        ensure!(
            unsafe {
                QueryFullProcessImageNameW(
                    self.handle.as_raw_handle(),
                    0,
                    path.as_mut_ptr(),
                    &mut length,
                )
            } != 0,
            "查询进程路径失败：{}",
            std::io::Error::last_os_error()
        );
        ensure!((length as usize) < path.len(), "进程路径被截断");
        ensure!(
            unsafe {
                GetProcessTimes(
                    self.handle.as_raw_handle(),
                    &mut created,
                    &mut exited,
                    &mut kernel,
                    &mut user,
                )
            } != 0,
            "查询进程创建时间失败：{}",
            std::io::Error::last_os_error()
        );
        Ok(VmwareProcessIdentity {
            pid: self.pid,
            created_filetime: (u64::from(created.dwHighDateTime) << 32)
                | u64::from(created.dwLowDateTime),
            executable: PathBuf::from(OsString::from_wide(&path[..length as usize])),
        })
    }

    fn query(&self, address: usize) -> Result<Option<MEMORY_BASIC_INFORMATION>> {
        let mut info = MEMORY_BASIC_INFORMATION::default();
        // SAFETY: VirtualQueryEx treats address as a remote address, not a local
        // dereference; info is a correctly sized initialized output structure.
        let read = unsafe {
            VirtualQueryEx(
                self.handle.as_raw_handle(),
                address as *const _,
                &mut info,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if read == 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_INVALID_PARAMETER as i32) {
                return Ok(None);
            }
            return Err(error).context("查询 VMware 进程地址空间失败");
        }
        ensure!(
            read == size_of::<MEMORY_BASIC_INFORMATION>(),
            "VirtualQueryEx 返回的结构不完整"
        );
        Ok(Some(info))
    }

    fn mapped_region(&self, info: &MEMORY_BASIC_INFORMATION) -> Result<Option<VmwareRegion>> {
        if info.State != MEM_COMMIT || info.Type != MEM_MAPPED {
            return Ok(None);
        }
        let mut path = vec![0u16; PATH_CAPACITY];
        // SAFETY: the destination is PATH_CAPACITY UTF-16 units; BaseAddress is
        // used only as a remote address by the OS.
        let length = unsafe {
            K32GetMappedFileNameW(
                self.handle.as_raw_handle(),
                info.BaseAddress,
                path.as_mut_ptr(),
                path.len() as u32,
            )
        } as usize;
        if length == 0 {
            let error = std::io::Error::last_os_error();
            // Pagefile-backed shared mappings have MEM_MAPPED too, but no file
            // name. They are not VMEM candidates. Other failures stay visible.
            if error.raw_os_error() == Some(ERROR_FILE_INVALID as i32) {
                return Ok(None);
            }
            return Err(error).context("查询映射文件路径失败");
        }
        ensure!(length < path.len(), "映射文件路径被截断");
        // Preserve UTF-16 identity exactly or fail, rather than conflating
        // different filenames through lossy conversion.
        let mapped_file =
            String::from_utf16(&path[..length]).context("映射文件路径含无效 UTF-16")?;
        if !mapped_file.to_ascii_lowercase().ends_with(".vmem") {
            return Ok(None);
        }
        let host_address = info.BaseAddress as u64;
        let length = info.RegionSize as u64;
        Ok(Some(VmwareRegion {
            host_address,
            length,
            mapped_file,
            supported: info.BaseAddress == info.AllocationBase
                && info.Protect == PAGE_READWRITE
                && info.AllocationProtect == PAGE_READWRITE
                && (MIN_VMEM_BYTES..=MAX_VMEM_BYTES).contains(&length)
                && length.is_multiple_of(PAGE_SIZE)
                && host_address.is_multiple_of(PAGE_SIZE),
        }))
    }

    fn target(&self, cancellation: &CancellationToken) -> Result<VmwareTarget> {
        let process = self.identity()?;
        ensure!(
            process.executable.file_name().is_some_and(|name| name
                .to_string_lossy()
                .eq_ignore_ascii_case("vmware-vmx.exe")),
            "PID {} 的可执行文件不是 vmware-vmx.exe",
            self.pid
        );
        let regions = self.regions(cancellation)?;
        self.check_running()?;
        Ok(VmwareTarget { process, regions })
    }

    fn regions(&self, cancellation: &CancellationToken) -> Result<Vec<VmwareRegion>> {
        let mut regions = Vec::new();
        let mut address = 0usize;
        for _ in 0..MAX_REGIONS {
            cancellation.check_cancelled()?;
            let Some(info) = self.query(address)? else {
                return Ok(regions);
            };
            let next = (info.BaseAddress as usize)
                .checked_add(info.RegionSize)
                .context("进程地址空间范围溢出")?;
            ensure!(next > address, "进程地址空间枚举未前进");
            if let Some(region) = self.mapped_region(&info)? {
                regions.push(region);
            }
            address = next;
        }
        bail!("进程地址空间超过 {MAX_REGIONS} 个区域；不能使用截断的映射结果")
    }
}

impl ProcessReader for WindowsProcess {
    fn validate(&self, region: &VmwareRegion) -> Result<()> {
        self.check_running()?;
        // VirtualQueryEx walks forward to the first attribute change. Querying
        // the start of a 2 GiB view for every tiny read repeatedly scans its
        // entire extent. Full geometry is checked at attach; the final page
        // cheaply verifies the allocation base, end, protection and filename.
        // Individual reads still fail on inaccessible interior pages. This is
        // not a proof against unmap/remap ABA between checks.
        let last_page = region
            .host_address
            .checked_add(region.length)
            .and_then(|end| end.checked_sub(PAGE_SIZE))
            .context("实时映射末页地址溢出")?;
        let address: usize = last_page
            .try_into()
            .context("宿主映射地址不适用于当前架构")?;
        let info = self.query(address)?.context("原 .vmem 映射已不存在")?;
        let tail = self
            .mapped_region(&info)?
            .context("原 .vmem 映射末页已不可用")?;
        ensure!(
            tail.host_address == last_page
                && tail.length == PAGE_SIZE
                && tail.mapped_file == region.mapped_file
                && info.AllocationBase as u64 == region.host_address
                && info.Protect == PAGE_READWRITE
                && info.AllocationProtect == PAGE_READWRITE,
            "原 .vmem 映射的地址、长度、属性或路径已改变"
        );
        Ok(())
    }

    fn read(&self, host_address: u64, output: &mut [u8]) -> HostRead {
        let Ok(address) = usize::try_from(host_address) else {
            return HostRead {
                copied: 0,
                error: Some("宿主地址超出当前架构范围".to_owned()),
            };
        };
        let mut copied = 0usize;
        // SAFETY: remote address is never dereferenced locally; output owns its
        // whole writable buffer, and its exact length is passed to the OS.
        let ok = unsafe {
            ReadProcessMemory(
                self.handle.as_raw_handle(),
                address as *const _,
                output.as_mut_ptr().cast(),
                output.len(),
                &mut copied,
            )
        };
        let error =
            (ok == 0).then(|| format!("ReadProcessMemory: {}", std::io::Error::last_os_error()));
        HostRead { copied, error }
    }
}

pub(super) fn attach(
    target: &VmwareTarget,
    cancellation: &CancellationToken,
) -> Result<Box<dyn ProcessReader>> {
    let process = WindowsProcess::open(target.process.pid)?;
    let current = process.target(cancellation)?;
    ensure!(
        &current == target,
        "选择后进程身份或 .vmem 映射已改变，请重新枚举虚拟机"
    );
    cancellation.check_cancelled()?;
    Ok(Box::new(process))
}

pub(super) fn discover(cancellation: &CancellationToken) -> Result<VmwareDiscovery> {
    ensure!(usize::BITS == 64, "VMware 实时读取需要 64 位 Windows 进程");
    // SAFETY: process-only snapshot creates a new independently owned handle.
    let raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    ensure!(
        raw != INVALID_HANDLE_VALUE,
        "枚举进程失败：{}",
        std::io::Error::last_os_error()
    );
    let snapshot = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut entry = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    let mut result = VmwareDiscovery::default();
    // SAFETY: entry has the OS-required dwSize and a live writable structure.
    let mut found = unsafe { Process32FirstW(snapshot.as_raw_handle(), &mut entry) };
    loop {
        if found == 0 {
            let error = std::io::Error::last_os_error();
            ensure!(
                error.raw_os_error() == Some(ERROR_NO_MORE_FILES as i32),
                "进程枚举不完整：{error}"
            );
            break;
        }
        cancellation.check_cancelled()?;
        let length = entry
            .szExeFile
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(entry.szExeFile.len());
        if String::from_utf16_lossy(&entry.szExeFile[..length])
            .eq_ignore_ascii_case("vmware-vmx.exe")
        {
            match WindowsProcess::open(entry.th32ProcessID)
                .and_then(|process| process.target(cancellation))
            {
                Ok(target) => result.targets.push(target),
                Err(error) if is_cancellation_error(&error) => return Err(error),
                Err(error) => result.issues.push(VmwareDiscoveryIssue {
                    pid: entry.th32ProcessID,
                    message: format!("{error:#}"),
                }),
            }
        }
        found = unsafe { Process32NextW(snapshot.as_raw_handle(), &mut entry) };
    }
    cancellation.check_cancelled()?;
    result.targets.sort_by_key(|target| target.process.pid);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;

    struct FixtureFile(PathBuf);
    impl Drop for FixtureFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    #[test]
    fn native_mapping_reads_changes_and_rejects_unmapping() {
        let path = std::env::temp_dir().join(format!(
            "starmem-live-中文-{}-{}.vmem",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        // Declared before the file/mapping so unwinding closes them before deletion.
        let _cleanup = FixtureFile(path.clone());
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.set_len(MIN_VMEM_BYTES).unwrap();
        let mut mapping = unsafe { memmap2::MmapOptions::new().map_mut(&file) }.unwrap();
        let process = WindowsProcess::open(std::process::id()).unwrap();
        let token = CancellationToken::new();
        let regions = process.regions(&token).unwrap();
        let region = regions
            .into_iter()
            .find(|region| region.host_address == mapping.as_ptr() as u64)
            .unwrap();
        assert!(region.supported);
        assert!(region.mapped_file.contains("中文"));
        assert!(process.validate(&region).is_ok());
        let mut shortened = region.clone();
        shortened.length -= PAGE_SIZE;
        assert!(process.validate(&shortened).is_err());
        let mut shifted = region.clone();
        shifted.host_address += PAGE_SIZE;
        shifted.length -= PAGE_SIZE;
        assert!(process.validate(&shifted).is_err());
        let target = VmwareTarget {
            process: process.identity().unwrap(),
            regions: vec![region],
        };
        // Production attachment must reject this fixture's non-VMware EXE.
        assert!(attach(&target, &token).is_err());
        let mut reader = VmwareLiveReader::from_process(
            target,
            VmwareLayout::Workstation3GbHole,
            Box::new(process),
        )
        .unwrap();
        let request = [LiveReadRequest {
            physical_address: 0,
            length: 3,
        }];
        mapping[..3].copy_from_slice(b"old");
        assert_eq!(
            reader.read_batch(&request, &token).unwrap().ranges[0].fragments[0].bytes,
            b"old"
        );
        mapping[..3].copy_from_slice(b"new");
        assert_eq!(
            reader.read_batch(&request, &token).unwrap().ranges[0].fragments[0].bytes,
            b"new"
        );
        drop(mapping);
        assert!(
            reader
                .read_batch(&request, &token)
                .unwrap_err()
                .to_string()
                .contains("STARMEM_LIVE_SOURCE_CHANGED")
        );
        assert!(!reader.is_open());
        drop(reader);
        drop(file);
        std::fs::remove_file(path).unwrap();
    }
}
