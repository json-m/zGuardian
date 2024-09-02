use std::thread;
use std::time::Duration;
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use windows::Win32::Foundation::{CloseHandle, MAX_PATH};
use windows::Win32::System::ProcessStatus::{EnumProcesses, GetProcessMemoryInfo, GetModuleFileNameExW, GetPerformanceInfo, PERFORMANCE_INFORMATION, PROCESS_MEMORY_COUNTERS};
use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE, PROCESS_QUERY_INFORMATION};
use windows::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS};
use std::mem::size_of;

const CHECK_INTERVAL: Duration = Duration::from_millis(50); // Check every 50 milliseconds
const VRCHAT_BASELINE: usize = 17 * 1024 * 1024 * 1024; // 17GB in bytes
const VRCHAT_THRESHOLD: usize = 24 * 1024 * 1024 * 1024; // 24GB in bytes
const RESET_DELAY: Duration = Duration::from_secs(10); // Wait 10 seconds before resetting

fn main() -> windows::core::Result<()> {
    println!("VRChat Memory Guardian started.");

    loop {
        let initial_committed = get_total_committed_memory()?;
        let baseline = initial_committed + VRCHAT_BASELINE;
        let threshold = initial_committed + VRCHAT_THRESHOLD;

        println!("Initial committed memory: {:.2} GB", bytes_to_gb(initial_committed as u64));
        println!("Baseline (with VRChat): {:.2} GB", bytes_to_gb(baseline as u64));
        println!("Threshold: {:.2} GB", bytes_to_gb(threshold as u64));

        let mut last_print_time = std::time::Instant::now();

        loop {
            let current_committed = get_total_committed_memory()?;
            let vrchat_memory = get_vrchat_memory()?;

            let now = std::time::Instant::now();
            if now.duration_since(last_print_time) >= Duration::from_secs(1) {
                println!("Current committed memory: {:.2} GB", bytes_to_gb(current_committed as u64));
                println!("VRChat memory usage: {:.2} GB", bytes_to_gb(vrchat_memory));
                last_print_time = now;
            }

            if vrchat_memory > VRCHAT_THRESHOLD as u64 {
                println!("VRChat memory threshold exceeded! Attempting to terminate VRChat...");
                match terminate_vrchat() {
                    Ok(true) => {
                        println!("VRChat terminated successfully.");
                        break;
                    },
                    Ok(false) => println!("VRChat process not found."),
                    Err(e) => println!("Failed to terminate VRChat: {:?}", e),
                }
            }

            if vrchat_memory == 0 {
                println!("VRChat is not running. Resetting thresholds...");
                break;
            }

            thread::sleep(CHECK_INTERVAL);
        }

        println!("Waiting {} seconds before resetting...", RESET_DELAY.as_secs());
        thread::sleep(RESET_DELAY);
    }
}

fn get_total_committed_memory() -> windows::core::Result<usize> {
    unsafe {
        let mut pi = PERFORMANCE_INFORMATION::default();
        GetPerformanceInfo(&mut pi, size_of::<PERFORMANCE_INFORMATION>() as u32)?;
        Ok(pi.CommitTotal * pi.PageSize)
    }
}

fn get_vrchat_memory() -> windows::core::Result<u64> {
    unsafe {
        let mut processes = [0u32; 1024];
        let mut bytes_returned = 0;
        EnumProcesses(processes.as_mut_ptr(), size_of::<[u32; 1024]>() as u32, &mut bytes_returned)?;

        let count = bytes_returned as usize / size_of::<u32>();
        for &pid in &processes[..count] {
            if pid != 0 {
                if let Ok(handle) = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid) {
                    let mut pmc = PROCESS_MEMORY_COUNTERS::default();
                    if GetProcessMemoryInfo(handle, &mut pmc, size_of::<PROCESS_MEMORY_COUNTERS>() as u32).is_ok() {
                        if let Ok(process_name) = get_process_name(pid) {
                            if process_name.to_lowercase().contains("vrchat") {
                                CloseHandle(handle).expect("TODO: panic message");
                                return Ok(pmc.WorkingSetSize as u64);
                            }
                        }
                    }
                    CloseHandle(handle).expect("TODO: panic message");
                }
            }
        }
    }
    Ok(0)
}

fn terminate_vrchat() -> windows::core::Result<bool> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?;
        let mut entry = PROCESSENTRY32 {
            dwSize: size_of::<PROCESSENTRY32>() as u32,
            ..Default::default()
        };

        if Process32First(snapshot, &mut entry).is_ok() {
            loop {
                let process_name = get_process_name_from_entry(&entry.szExeFile);
                if process_name.to_lowercase().contains("vrchat") {
                    let process_handle = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION, false, entry.th32ProcessID);
                    if let Ok(handle) = process_handle {
                        let result = TerminateProcess(handle, 1);
                        CloseHandle(handle).expect("TODO: panic message");
                        if result.is_ok() {
                            println!("Terminated VRChat process with PID: {}", entry.th32ProcessID);
                            return Ok(true);
                        }
                    }
                }
                if Process32Next(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }

        CloseHandle(snapshot).expect("TODO: panic message");
    }
    Ok(false)
}

fn get_process_name(pid: u32) -> windows::core::Result<String> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid)?;
        let mut buffer = [0u16; MAX_PATH as usize];
        let size = GetModuleFileNameExW(handle, None, &mut buffer);
        CloseHandle(handle).expect("TODO: panic message");
        if size == 0 {
            return Err(windows::core::Error::from_win32());
        }
        Ok(OsString::from_wide(&buffer[..size as usize]).to_string_lossy().into_owned())
    }
}

fn get_process_name_from_entry(raw_name: &[i8; 260]) -> String {
    let mut len = 0;
    for &c in raw_name.iter() {
        if c == 0 {
            break;
        }
        len += 1;
    }
    let name = OsString::from_wide(&raw_name[..len].iter().map(|&c| c as u16).collect::<Vec<u16>>());
    name.to_string_lossy().into_owned()
}

fn bytes_to_gb(bytes: u64) -> f64 {
    (bytes as f64 / 1_073_741_824.0 * 100.0).round() / 100.0
}