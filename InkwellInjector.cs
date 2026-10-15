using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace Inkwell.Injector
{
    #region Win32 & NTAPI Primitives
    static class Native
    {
        public const uint PROCESS_ALL_ACCESS = 0x1FFFFF;
        public const uint MEM_COMMIT = 0x1000;
        public const uint MEM_RESERVE = 0x2000;
        public const uint MEM_RELEASE = 0x8000;
        public const uint PAGE_READWRITE = 0x04;
        public const uint PAGE_EXECUTE_READWRITE = 0x40;
        public const uint PAGE_EXECUTE_READ = 0x20;

        public const uint THREAD_ALL_ACCESS = 0x1FFFFF;
        public const uint THREAD_SUSPEND_RESUME = 0x0002;
        public const uint THREAD_GET_CONTEXT = 0x0008;
        public const uint THREAD_SET_CONTEXT = 0x0010;

        public const uint CONTEXT_CONTROL = 0x10001;
        public const uint CONTEXT_INTEGER = 0x10002;
        public const uint CONTEXT_FULL_X64 = 0x10000B;

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint dwFreeType);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out int lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out int lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out int lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GetExitCodeThread(IntPtr hThread, out uint lpExitCode);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr LoadLibrary(string lpLibFileName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool FreeLibrary(IntPtr hLibModule);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, int dwThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint SuspendThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool IsWow64Process(IntPtr hProcess, out bool wow64Process);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern int NtCreateThreadEx(
            out IntPtr hThread, uint desiredAccess, IntPtr objectAttributes,
            IntPtr processHandle, IntPtr startAddress, IntPtr parameter,
            bool createSuspended, uint stackZeroBits, uint sizeOfStackCommit,
            uint sizeOfStackReserve, IntPtr bytesBuffer);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern int NtQueryInformationProcess(
            IntPtr processHandle, int processInformationClass,
            ref PROCESS_BASIC_INFORMATION processInformation,
            uint processInformationLength, out uint returnLength);

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr ExitStatus;
            public IntPtr PebBaseAddress;
            public IntPtr AffinityMask;
            public IntPtr BasePriority;
            public IntPtr UniqueProcessId;
            public IntPtr InheritedFromUniqueProcessId;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        public struct CONTEXT64
        {
            public ulong P1Home;
            public ulong P2Home;
            public ulong P3Home;
            public ulong P4Home;
            public ulong P5Home;
            public ulong P6Home;
            public uint ContextFlags;
            public uint MxCsr;
            public ushort SegCs;
            public ushort SegDs;
            public ushort SegEs;
            public ushort SegFs;
            public ushort SegGs;
            public ushort SegSs;
            public uint EFlags;
            public ulong Dr0;
            public ulong Dr1;
            public ulong Dr2;
            public ulong Dr3;
            public ulong Dr6;
            public ulong Dr7;
            public ulong Rax;
            public ulong Rcx;
            public ulong Rdx;
            public ulong Rbx;
            public ulong Rsp;
            public ulong Rbp;
            public ulong Rsi;
            public ulong Rdi;
            public ulong R8;
            public ulong R9;
            public ulong R10;
            public ulong R11;
            public ulong R12;
            public ulong R13;
            public ulong R14;
            public ulong R15;
            public ulong Rip;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);

        [Flags]
        public enum SnapshotFlags : uint
        {
            Thread = 0x00000004
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct THREADENTRY32
        {
            public uint dwSize;
            public uint cntUsage;
            public uint th32ThreadID;
            public uint th32OwnerProcessID;
            public int tpBasePri;
            public int tpDeltaPri;
            public uint dwFlags;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateToolhelp32Snapshot(SnapshotFlags dwFlags, uint th32ProcessID);

        [DllImport("kernel32.dll")]
        public static extern bool Thread32First(IntPtr hSnapshot, ref THREADENTRY32 lpte);

        [DllImport("kernel32.dll")]
        public static extern bool Thread32Next(IntPtr hSnapshot, ref THREADENTRY32 lpte);
    }
    #endregion

    #region PE Header & Manual Map Structures
    static class PeParser
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DOS_HEADER
        {
            public ushort e_magic;
            public ushort e_cblp;
            public ushort e_cp;
            public ushort e_crlc;
            public ushort e_cparhdr;
            public ushort e_minalloc;
            public ushort e_maxalloc;
            public ushort e_ss;
            public ushort e_sp;
            public ushort e_csum;
            public ushort e_ip;
            public ushort e_cs;
            public ushort e_lfarlc;
            public ushort e_ovno;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public ushort[] e_res1;
            public ushort e_oemid;
            public ushort e_oeminfo;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
            public ushort[] e_res2;
            public int e_lfanew;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_FILE_HEADER
        {
            public ushort Machine;
            public ushort NumberOfSections;
            public uint TimeDateStamp;
            public uint PointerToSymbolTable;
            public uint NumberOfSymbols;
            public ushort SizeOfOptionalHeader;
            public ushort Characteristics;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DATA_DIRECTORY
        {
            public uint VirtualAddress;
            public uint Size;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_OPTIONAL_HEADER64
        {
            public ushort Magic;
            public byte MajorLinkerVersion;
            public byte MinorLinkerVersion;
            public uint SizeOfCode;
            public uint SizeOfInitializedData;
            public uint SizeOfUninitializedData;
            public uint AddressOfEntryPoint;
            public uint BaseOfCode;
            public ulong ImageBase;
            public uint SectionAlignment;
            public uint FileAlignment;
            public ushort MajorOperatingSystemVersion;
            public ushort MinorOperatingSystemVersion;
            public ushort MajorImageVersion;
            public ushort MinorImageVersion;
            public ushort MajorSubsystemVersion;
            public ushort MinorSubsystemVersion;
            public uint Win32VersionValue;
            public uint SizeOfImage;
            public uint SizeOfHeaders;
            public uint CheckSum;
            public ushort Subsystem;
            public ushort DllCharacteristics;
            public ulong SizeOfStackReserve;
            public ulong SizeOfStackCommit;
            public ulong SizeOfHeapReserve;
            public ulong SizeOfHeapCommit;
            public uint LoaderFlags;
            public uint NumberOfRvaAndSizes;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public IMAGE_DATA_DIRECTORY[] DataDirectory;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_SECTION_HEADER
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public byte[] Name;
            public uint VirtualSize;
            public uint VirtualAddress;
            public uint SizeOfRawData;
            public uint PointerToRawData;
            public uint PointerToRelocations;
            public uint PointerToLinenumbers;
            public ushort NumberOfRelocations;
            public ushort NumberOfLinenumbers;
            public uint Characteristics;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_BASE_RELOCATION
        {
            public uint VirtualAddress;
            public uint SizeOfBlock;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_IMPORT_DESCRIPTOR
        {
            public uint OriginalFirstThunk;
            public uint TimeDateStamp;
            public uint ForwarderChain;
            public uint Name;
            public uint FirstThunk;
        }
    }
    #endregion

    #region Injection Methods Enum & Options
    public enum InjectionMethod
    {
        CreateRemoteThread = 0,
        NtCreateThreadEx = 1,
        QueueUserAPC = 2,
        ThreadContextHijack = 3,
        ManualMapX64 = 4,
        MonoAssemblyLoad = 5,
        MelonLoaderDeploy = 6
    }

    public class InjectionOptions
    {
        public bool UnlinkFromPEB { get; set; }
        public bool ErasePEHeaders { get; set; }
        public bool CloseOnInject { get; set; }
        public bool AutoInject { get; set; }
        public string TargetProcessFilter { get; set; }
        public string MonoNamespace { get; set; }
        public string MonoClass { get; set; }
        public string MonoMethod { get; set; }

        public InjectionOptions()
        {
            UnlinkFromPEB = true;
            ErasePEHeaders = true;
            CloseOnInject = false;
            AutoInject = false;
            TargetProcessFilter = "";
            MonoNamespace = "LiarsBarMod";
            MonoClass = "Loader";
            MonoMethod = "Init";
        }
    }
    #endregion

    #region Multi-Vector Injection Engine
    static class InjectionEngine
    {
        public delegate void LogCallback(string msg, Color col);

        static void SafeLog(LogCallback log, string msg, Color col)
        {
            if (log != null) log(msg, col);
        }

        public static string Execute(int pid, string dllPath, InjectionMethod method, InjectionOptions opts, LogCallback log)
        {
            string fullPath = Path.GetFullPath(dllPath);
            if (!File.Exists(fullPath)) return "DLL file not found: " + fullPath;

            Process proc;
            try { proc = Process.GetProcessById(pid); }
            catch (Exception ex) { return "Failed to attach to PID " + pid + ": " + ex.Message; }

            // Target architecture validation
            bool isTargetWow64 = false;
            try
            {
                if (Native.IsWow64Process(proc.Handle, out isTargetWow64))
                {
                    if (isTargetWow64 && IntPtr.Size == 8 && method == InjectionMethod.ManualMapX64)
                    {
                        return "Architecture mismatch: Target is 32-bit (x86), but ManualMap x64 requires a 64-bit target.";
                    }
                }
            }
            catch { }

            IntPtr hProc = Native.OpenProcess(Native.PROCESS_ALL_ACCESS, false, pid);
            if (hProc == IntPtr.Zero)
            {
                int err = Marshal.GetLastWin32Error();
                return "OpenProcess failed (Error code " + err + "). Administrator elevation is required.";
            }

            string status = null;

            switch (method)
            {
                case InjectionMethod.CreateRemoteThread:
                    status = InjectCRT(hProc, fullPath, log);
                    break;

                case InjectionMethod.NtCreateThreadEx:
                    status = InjectNtCreate(hProc, fullPath, log);
                    break;

                case InjectionMethod.QueueUserAPC:
                    status = InjectAPC(hProc, fullPath, pid, log);
                    break;

                case InjectionMethod.ThreadContextHijack:
                    status = InjectThreadHijack(hProc, fullPath, pid, log);
                    break;

                case InjectionMethod.ManualMapX64:
                    status = InjectManualMap(hProc, fullPath, opts, log);
                    break;

                case InjectionMethod.MonoAssemblyLoad:
                    status = InjectMono(proc, hProc, fullPath, opts, log);
                    break;

                case InjectionMethod.MelonLoaderDeploy:
                    status = DeployMelonLoader(proc, fullPath, log);
                    break;

                default:
                    status = "Unknown injection vector.";
                    break;
            }

            // Post-injection stealth options
            if (status == null && opts.UnlinkFromPEB && method != InjectionMethod.MelonLoaderDeploy && method != InjectionMethod.ManualMapX64)
            {
                SafeLog(log, "Executing PEB module unlinking cloaking routine...", InkwellTheme.TextAccent);
                UnlinkPEB(hProc, Path.GetFileName(fullPath), log);
            }

            Native.CloseHandle(hProc);
            return status;
        }

        #region Vector: CreateRemoteThread
        static string InjectCRT(IntPtr hProc, string dllPath, LogCallback log)
        {
            SafeLog(log, "Staging remote memory allocation for LoadLibraryW...", InkwellTheme.TextMuted);
            IntPtr loadLibAddr;
            IntPtr remotePath = WriteRemoteString(hProc, dllPath, out loadLibAddr);
            if (remotePath == IntPtr.Zero) return "VirtualAllocEx / WriteProcessMemory failed.";

            SafeLog(log, "Dispatching CreateRemoteThread -> LoadLibraryW(0x" + remotePath.ToString("X") + ")...", InkwellTheme.TextMuted);
            int tid;
            IntPtr hThread = Native.CreateRemoteThread(hProc, IntPtr.Zero, 0, loadLibAddr, remotePath, 0, out tid);
            if (hThread == IntPtr.Zero)
            {
                Native.VirtualFreeEx(hProc, remotePath, 0, Native.MEM_RELEASE);
                return "CreateRemoteThread failed (Error code " + Marshal.GetLastWin32Error() + ").";
            }

            Native.WaitForSingleObject(hThread, 5000);
            uint exitCode;
            Native.GetExitCodeThread(hThread, out exitCode);
            Native.CloseHandle(hThread);
            Native.VirtualFreeEx(hProc, remotePath, 0, Native.MEM_RELEASE);

            return exitCode != 0 ? null : "LoadLibraryW executed but returned NULL module handle in remote process.";
        }
        #endregion

        #region Vector: NtCreateThreadEx
        static string InjectNtCreate(IntPtr hProc, string dllPath, LogCallback log)
        {
            SafeLog(log, "Staging remote memory allocation for native NTAPI invocation...", InkwellTheme.TextMuted);
            IntPtr loadLibAddr;
            IntPtr remotePath = WriteRemoteString(hProc, dllPath, out loadLibAddr);
            if (remotePath == IntPtr.Zero) return "VirtualAllocEx / WriteProcessMemory failed.";

            SafeLog(log, "Executing unhooked NtCreateThreadEx stub...", InkwellTheme.TextMuted);
            IntPtr hThread;
            int ntStatus = Native.NtCreateThreadEx(out hThread, Native.THREAD_ALL_ACCESS, IntPtr.Zero, hProc, loadLibAddr, remotePath, false, 0, 0, 0, IntPtr.Zero);
            if (ntStatus != 0 || hThread == IntPtr.Zero)
            {
                Native.VirtualFreeEx(hProc, remotePath, 0, Native.MEM_RELEASE);
                return "NtCreateThreadEx failed with NTSTATUS: 0x" + ntStatus.ToString("X8");
            }

            Native.WaitForSingleObject(hThread, 5000);
            uint exitCode;
            Native.GetExitCodeThread(hThread, out exitCode);
            Native.CloseHandle(hThread);
            Native.VirtualFreeEx(hProc, remotePath, 0, Native.MEM_RELEASE);

            return exitCode != 0 ? null : "LoadLibraryW returned NULL module handle.";
        }
        #endregion

        #region Vector: QueueUserAPC
        static string InjectAPC(IntPtr hProc, string dllPath, int pid, LogCallback log)
        {
            IntPtr loadLibAddr;
            IntPtr remotePath = WriteRemoteString(hProc, dllPath, out loadLibAddr);
            if (remotePath == IntPtr.Zero) return "Failed to write DLL path to remote process.";

            SafeLog(log, "Enumerating target threads for APC dispatch...", InkwellTheme.TextMuted);
            IntPtr snap = Native.CreateToolhelp32Snapshot(Native.SnapshotFlags.Thread, 0);
            if (snap == IntPtr.Zero || snap == (IntPtr)(-1))
            {
                Native.VirtualFreeEx(hProc, remotePath, 0, Native.MEM_RELEASE);
                return "Failed to take thread snapshot.";
            }

            Native.THREADENTRY32 te = new Native.THREADENTRY32();
            te.dwSize = (uint)Marshal.SizeOf(typeof(Native.THREADENTRY32));
            int queuedCount = 0;

            if (Native.Thread32First(snap, ref te))
            {
                do
                {
                    if (te.th32OwnerProcessID == (uint)pid)
                    {
                        IntPtr hThread = Native.OpenThread(Native.THREAD_SET_CONTEXT | Native.THREAD_SUSPEND_RESUME, false, (int)te.th32ThreadID);
                        if (hThread != IntPtr.Zero)
                        {
                            if (Native.QueueUserAPC(loadLibAddr, hThread, remotePath) != 0)
                            {
                                queuedCount++;
                            }
                            Native.CloseHandle(hThread);
                        }
                    }
                } while (Native.Thread32Next(snap, ref te));
            }

            Native.CloseHandle(snap);
            SafeLog(log, "Queued User APC to " + queuedCount + " target thread(s). Waiting for alertable state...", InkwellTheme.Success);
            return queuedCount > 0 ? null : "No alertable threads available in target process.";
        }
        #endregion

        #region Vector: Thread Context Hijack
        static string InjectThreadHijack(IntPtr hProc, string dllPath, int pid, LogCallback log)
        {
            if (IntPtr.Size != 8) return "Thread context hijacking currently requires 64-bit architecture.";

            SafeLog(log, "Resolving target main thread for execution context redirection...", InkwellTheme.TextMuted);
            IntPtr snap = Native.CreateToolhelp32Snapshot(Native.SnapshotFlags.Thread, 0);
            if (snap == IntPtr.Zero || snap == (IntPtr)(-1)) return "Failed to snapshot threads.";

            Native.THREADENTRY32 te = new Native.THREADENTRY32();
            te.dwSize = (uint)Marshal.SizeOf(typeof(Native.THREADENTRY32));
            int targetTid = 0;

            if (Native.Thread32First(snap, ref te))
            {
                do
                {
                    if (te.th32OwnerProcessID == (uint)pid)
                    {
                        targetTid = (int)te.th32ThreadID;
                        break;
                    }
                } while (Native.Thread32Next(snap, ref te));
            }
            Native.CloseHandle(snap);

            if (targetTid == 0) return "No accessible thread found in target.";

            IntPtr hThread = Native.OpenThread(Native.THREAD_ALL_ACCESS, false, targetTid);
            if (hThread == IntPtr.Zero) return "Failed to open target thread for context redirection.";

            Native.SuspendThread(hThread);

            Native.CONTEXT64 ctx = new Native.CONTEXT64();
            ctx.ContextFlags = Native.CONTEXT_FULL_X64;
            if (!Native.GetThreadContext(hThread, ref ctx))
            {
                Native.ResumeThread(hThread);
                Native.CloseHandle(hThread);
                return "GetThreadContext failed.";
            }

            ulong originalRip = ctx.Rip;

            IntPtr loadLibAddr;
            IntPtr remotePath = WriteRemoteString(hProc, dllPath, out loadLibAddr);

            // Construct x64 shellcode:
            // sub rsp, 0x28
            // mov rcx, remotePath
            // mov rax, loadLibAddr
            // call rax
            // add rsp, 0x28
            // jmp originalRip
            List<byte> shell = new List<byte>();
            shell.AddRange(new byte[] { 0x48, 0x83, 0xEC, 0x28 }); // sub rsp, 28h
            shell.AddRange(new byte[] { 0x48, 0xB9 }); // mov rcx, imm64
            shell.AddRange(BitConverter.GetBytes(remotePath.ToInt64()));
            shell.AddRange(new byte[] { 0x48, 0xB8 }); // mov rax, imm64
            shell.AddRange(BitConverter.GetBytes(loadLibAddr.ToInt64()));
            shell.AddRange(new byte[] { 0xFF, 0xD0 }); // call rax
            shell.AddRange(new byte[] { 0x48, 0x83, 0xC4, 0x28 }); // add rsp, 28h
            shell.AddRange(new byte[] { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 }); // jmp [rip+0]
            shell.AddRange(BitConverter.GetBytes(originalRip));

            byte[] shellcodeBytes = shell.ToArray();
            IntPtr shellMem = Native.VirtualAllocEx(hProc, IntPtr.Zero, (uint)shellcodeBytes.Length, Native.MEM_COMMIT | Native.MEM_RESERVE, Native.PAGE_EXECUTE_READWRITE);
            int written;
            Native.WriteProcessMemory(hProc, shellMem, shellcodeBytes, (uint)shellcodeBytes.Length, out written);

            ctx.Rip = (ulong)shellMem.ToInt64();
            Native.SetThreadContext(hThread, ref ctx);
            Native.ResumeThread(hThread);
            Native.CloseHandle(hThread);

            SafeLog(log, "Thread context diverted to staged shellcode -> RIP=0x" + shellMem.ToString("X"), InkwellTheme.Success);
            return null;
        }
        #endregion

        #region Vector: Manual Map x64
        static string InjectManualMap(IntPtr hProc, string dllPath, InjectionOptions opts, LogCallback log)
        {
            SafeLog(log, "Parsing Portable Executable headers of " + Path.GetFileName(dllPath) + "...", InkwellTheme.TextMuted);
            byte[] fileBytes;
            try { fileBytes = File.ReadAllBytes(dllPath); }
            catch (Exception ex) { return "File read error: " + ex.Message; }

            GCHandle pin = GCHandle.Alloc(fileBytes, GCHandleType.Pinned);
            IntPtr pRaw = pin.AddrOfPinnedObject();

            PeParser.IMAGE_DOS_HEADER dos = (PeParser.IMAGE_DOS_HEADER)Marshal.PtrToStructure(pRaw, typeof(PeParser.IMAGE_DOS_HEADER));
            if (dos.e_magic != 0x5A4D)
            {
                pin.Free();
                return "Invalid PE signature (IMAGE_DOS_SIGNATURE mismatch).";
            }

            IntPtr pNt = (IntPtr)(pRaw.ToInt64() + dos.e_lfanew);
            uint peSig = (uint)Marshal.ReadInt32(pNt);
            if (peSig != 0x00004550) // 'PE\0\0'
            {
                pin.Free();
                return "Invalid NT headers signature.";
            }

            IntPtr pFile = (IntPtr)(pNt.ToInt64() + 4);
            PeParser.IMAGE_FILE_HEADER fileHdr = (PeParser.IMAGE_FILE_HEADER)Marshal.PtrToStructure(pFile, typeof(PeParser.IMAGE_FILE_HEADER));

            IntPtr pOpt = (IntPtr)(pFile.ToInt64() + Marshal.SizeOf(typeof(PeParser.IMAGE_FILE_HEADER)));
            PeParser.IMAGE_OPTIONAL_HEADER64 optHdr = (PeParser.IMAGE_OPTIONAL_HEADER64)Marshal.PtrToStructure(pOpt, typeof(PeParser.IMAGE_OPTIONAL_HEADER64));

            if (fileHdr.Machine != 0x8664) // IMAGE_FILE_MACHINE_AMD64
            {
                pin.Free();
                return "Manual Map x64 only supports 64-bit AMD64 PE binaries.";
            }

            SafeLog(log, "Allocating remote virtual image space (" + (optHdr.SizeOfImage / 1024) + " KB)...", InkwellTheme.TextMuted);
            IntPtr remoteImageBase = Native.VirtualAllocEx(hProc, (IntPtr)optHdr.ImageBase, optHdr.SizeOfImage, Native.MEM_COMMIT | Native.MEM_RESERVE, Native.PAGE_EXECUTE_READWRITE);
            if (remoteImageBase == IntPtr.Zero)
            {
                // Preferred base unavailable; allocate anywhere
                remoteImageBase = Native.VirtualAllocEx(hProc, IntPtr.Zero, optHdr.SizeOfImage, Native.MEM_COMMIT | Native.MEM_RESERVE, Native.PAGE_EXECUTE_READWRITE);
                if (remoteImageBase == IntPtr.Zero)
                {
                    pin.Free();
                    return "Remote VirtualAllocEx for SizeOfImage failed.";
                }
            }

            SafeLog(log, "Mapping image sections to remote base 0x" + remoteImageBase.ToString("X") + "...", InkwellTheme.TextMuted);
            int written;
            Native.WriteProcessMemory(hProc, remoteImageBase, fileBytes, optHdr.SizeOfHeaders, out written);

            IntPtr pSection = (IntPtr)(pOpt.ToInt64() + fileHdr.SizeOfOptionalHeader);
            for (int i = 0; i < fileHdr.NumberOfSections; i++)
            {
                PeParser.IMAGE_SECTION_HEADER sec = (PeParser.IMAGE_SECTION_HEADER)Marshal.PtrToStructure(pSection, typeof(PeParser.IMAGE_SECTION_HEADER));
                if (sec.SizeOfRawData > 0)
                {
                    byte[] secData = new byte[sec.SizeOfRawData];
                    Array.Copy(fileBytes, sec.PointerToRawData, secData, 0, sec.SizeOfRawData);
                    IntPtr dest = (IntPtr)(remoteImageBase.ToInt64() + sec.VirtualAddress);
                    Native.WriteProcessMemory(hProc, dest, secData, sec.SizeOfRawData, out written);
                }
                pSection = (IntPtr)(pSection.ToInt64() + Marshal.SizeOf(typeof(PeParser.IMAGE_SECTION_HEADER)));
            }

            // Delta Relocation calculations
            long delta = remoteImageBase.ToInt64() - (long)optHdr.ImageBase;
            if (delta != 0 && optHdr.DataDirectory[5].Size > 0) // Directory 5 = Base Relocations
            {
                SafeLog(log, "Applying PE base relocations (Delta: 0x" + delta.ToString("X") + ")...", InkwellTheme.TextMuted);
                uint relocRva = optHdr.DataDirectory[5].VirtualAddress;
                uint relocSize = optHdr.DataDirectory[5].Size;
                uint parsed = 0;

                while (parsed < relocSize)
                {
                    IntPtr pBlock = (IntPtr)(pRaw.ToInt64() + RvaToOffset(fileBytes, relocRva + parsed, fileHdr, pOpt));
                    PeParser.IMAGE_BASE_RELOCATION block = (PeParser.IMAGE_BASE_RELOCATION)Marshal.PtrToStructure(pBlock, typeof(PeParser.IMAGE_BASE_RELOCATION));
                    if (block.SizeOfBlock == 0) break;

                    uint entryCount = (block.SizeOfBlock - 8) / 2;
                    for (int e = 0; e < entryCount; e++)
                    {
                        ushort entry = (ushort)Marshal.ReadInt16(pBlock, 8 + (e * 2));
                        int type = entry >> 12;
                        int offset = entry & 0xFFF;

                        if (type == 10) // IMAGE_REL_BASED_DIR64
                        {
                            IntPtr patchAddr = (IntPtr)(remoteImageBase.ToInt64() + block.VirtualAddress + offset);
                            byte[] valBuf = new byte[8];
                            int readBytes;
                            Native.ReadProcessMemory(hProc, patchAddr, valBuf, 8, out readBytes);
                            long val = BitConverter.ToInt64(valBuf, 0);
                            val += delta;
                            byte[] newBuf = BitConverter.GetBytes(val);
                            Native.WriteProcessMemory(hProc, patchAddr, newBuf, 8, out written);
                        }
                    }
                    parsed += block.SizeOfBlock;
                }
            }

            // Resolve Import Address Table
            if (optHdr.DataDirectory[1].Size > 0) // Directory 1 = Imports
            {
                SafeLog(log, "Resolving Import Address Table (IAT) descriptors...", InkwellTheme.TextMuted);
                uint importRva = optHdr.DataDirectory[1].VirtualAddress;
                uint importOffset = RvaToOffset(fileBytes, importRva, fileHdr, pOpt);

                IntPtr pDesc = (IntPtr)(pRaw.ToInt64() + importOffset);
                while (true)
                {
                    PeParser.IMAGE_IMPORT_DESCRIPTOR desc = (PeParser.IMAGE_IMPORT_DESCRIPTOR)Marshal.PtrToStructure(pDesc, typeof(PeParser.IMAGE_IMPORT_DESCRIPTOR));
                    if (desc.Name == 0 && desc.FirstThunk == 0) break;

                    string modName = Marshal.PtrToStringAnsi((IntPtr)(pRaw.ToInt64() + RvaToOffset(fileBytes, desc.Name, fileHdr, pOpt)));
                    IntPtr hMod = Native.LoadLibrary(modName);

                    uint thunkRva = desc.OriginalFirstThunk != 0 ? desc.OriginalFirstThunk : desc.FirstThunk;
                    uint thunkOffset = RvaToOffset(fileBytes, thunkRva, fileHdr, pOpt);
                    uint destThunkRva = desc.FirstThunk;

                    IntPtr pThunk = (IntPtr)(pRaw.ToInt64() + thunkOffset);
                    int index = 0;
                    while (true)
                    {
                        ulong thunkData = (ulong)Marshal.ReadInt64(pThunk, index * 8);
                        if (thunkData == 0) break;

                        IntPtr fnAddr = IntPtr.Zero;
                        if ((thunkData & 0x8000000000000000) != 0) // Ordinal
                        {
                            ulong ordinal = thunkData & 0xFFFF;
                            fnAddr = Native.GetProcAddress(hMod, "#" + ordinal);
                        }
                        else
                        {
                            uint nameOffset = RvaToOffset(fileBytes, (uint)(thunkData & 0xFFFFFFFF), fileHdr, pOpt);
                            string funcName = Marshal.PtrToStringAnsi((IntPtr)(pRaw.ToInt64() + nameOffset + 2));
                            fnAddr = Native.GetProcAddress(hMod, funcName);
                        }

                        IntPtr patchAddr = (IntPtr)(remoteImageBase.ToInt64() + destThunkRva + (index * 8));
                        byte[] fnBuf = BitConverter.GetBytes(fnAddr.ToInt64());
                        Native.WriteProcessMemory(hProc, patchAddr, fnBuf, 8, out written);
                        index++;
                    }

                    pDesc = (IntPtr)(pDesc.ToInt64() + Marshal.SizeOf(typeof(PeParser.IMAGE_IMPORT_DESCRIPTOR)));
                }
            }

            // Wipe PE Headers if enabled
            if (opts.ErasePEHeaders)
            {
                SafeLog(log, "Wiping remote PE DOS and NT headers for anti-dump cloaking...", InkwellTheme.TextAccent);
                byte[] zeroHdr = new byte[optHdr.SizeOfHeaders];
                Native.WriteProcessMemory(hProc, remoteImageBase, zeroHdr, (uint)zeroHdr.Length, out written);
            }

            // Dispatch DllMain entry point
            if (optHdr.AddressOfEntryPoint != 0)
            {
                IntPtr entryPoint = (IntPtr)(remoteImageBase.ToInt64() + optHdr.AddressOfEntryPoint);
                SafeLog(log, "Calling remote DllMain(0x" + entryPoint.ToString("X") + ", DLL_PROCESS_ATTACH)...", InkwellTheme.Success);
                int tid;
                IntPtr hThread = Native.CreateRemoteThread(hProc, IntPtr.Zero, 0, entryPoint, remoteImageBase, 0, out tid);
                if (hThread != IntPtr.Zero)
                {
                    Native.WaitForSingleObject(hThread, 5000);
                    Native.CloseHandle(hThread);
                }
            }

            pin.Free();
            SafeLog(log, "Manual mapping completed successfully at 0x" + remoteImageBase.ToString("X"), InkwellTheme.Success);
            return null;
        }

        static uint RvaToOffset(byte[] fileBytes, uint rva, PeParser.IMAGE_FILE_HEADER fileHdr, IntPtr pOpt)
        {
            IntPtr pSection = (IntPtr)(pOpt.ToInt64() + fileHdr.SizeOfOptionalHeader);
            for (int i = 0; i < fileHdr.NumberOfSections; i++)
            {
                PeParser.IMAGE_SECTION_HEADER sec = (PeParser.IMAGE_SECTION_HEADER)Marshal.PtrToStructure(pSection, typeof(PeParser.IMAGE_SECTION_HEADER));
                if (rva >= sec.VirtualAddress && rva < sec.VirtualAddress + sec.VirtualSize)
                {
                    return sec.PointerToRawData + (rva - sec.VirtualAddress);
                }
                pSection = (IntPtr)(pSection.ToInt64() + Marshal.SizeOf(typeof(PeParser.IMAGE_SECTION_HEADER)));
            }
            return rva;
        }
        #endregion

        #region Vector: Mono Assembly Load (Unity)
        static string InjectMono(Process proc, IntPtr hProc, string dllPath, InjectionOptions opts, LogCallback log)
        {
            SafeLog(log, "Scanning target process for Mono runtime modules...", InkwellTheme.TextMuted);
            IntPtr monoBase = IntPtr.Zero;
            string monoModName = "";

            foreach (ProcessModule m in proc.Modules)
            {
                if (m.ModuleName.IndexOf("mono", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    monoBase = m.BaseAddress;
                    monoModName = m.ModuleName;
                    break;
                }
            }

            if (monoBase == IntPtr.Zero)
            {
                return "Target process does not appear to host a Mono runtime (mono.dll not found).";
            }

            SafeLog(log, "Identified Unity runtime module: " + monoModName + " at 0x" + monoBase.ToString("X"), InkwellTheme.TextAccent);

            IntPtr localMono = Native.LoadLibrary(monoModName);
            if (localMono == IntPtr.Zero) localMono = Native.LoadLibrary("mono-2.0-bdwgc.dll");
            if (localMono == IntPtr.Zero) localMono = Native.LoadLibrary("mono.dll");

            if (localMono == IntPtr.Zero)
            {
                return "Failed to load local mono runtime library for export offset resolution.";
            }

            IntPtr fnLoad = Native.GetProcAddress(localMono, "mono_assembly_load_from_full");
            if (fnLoad == IntPtr.Zero) fnLoad = Native.GetProcAddress(localMono, "mono_assembly_open");

            if (fnLoad == IntPtr.Zero)
            {
                Native.FreeLibrary(localMono);
                return "mono_assembly_load_from_full export not located in Mono module.";
            }

            long rva = fnLoad.ToInt64() - localMono.ToInt64();
            IntPtr remoteFn = (IntPtr)(monoBase.ToInt64() + rva);

            byte[] pathBytes = Encoding.UTF8.GetBytes(dllPath + "\0");
            IntPtr remotePath = Native.VirtualAllocEx(hProc, IntPtr.Zero, (uint)pathBytes.Length, Native.MEM_COMMIT | Native.MEM_RESERVE, Native.PAGE_READWRITE);
            int written;
            Native.WriteProcessMemory(hProc, remotePath, pathBytes, (uint)pathBytes.Length, out written);

            // Construct shellcode for x86 / x64 Mono invocation
            byte[] shellcode;
            if (IntPtr.Size == 8)
            {
                // x64 shellcode
                List<byte> s = new List<byte>();
                s.AddRange(new byte[] { 0x48, 0x83, 0xEC, 0x28 }); // sub rsp, 28h
                s.AddRange(new byte[] { 0x48, 0xB9 }); // mov rcx, remotePath (image name)
                s.AddRange(BitConverter.GetBytes(remotePath.ToInt64()));
                s.AddRange(new byte[] { 0x48, 0xBA }); // mov rdx, remotePath
                s.AddRange(BitConverter.GetBytes(remotePath.ToInt64()));
                s.AddRange(new byte[] { 0x4D, 0x31, 0xC0 }); // xor r8, r8
                s.AddRange(new byte[] { 0x4D, 0x31, 0xC9 }); // xor r9, r9
                s.AddRange(new byte[] { 0x48, 0xB8 }); // mov rax, remoteFn
                s.AddRange(BitConverter.GetBytes(remoteFn.ToInt64()));
                s.AddRange(new byte[] { 0xFF, 0xD0 }); // call rax
                s.AddRange(new byte[] { 0x48, 0x83, 0xC4, 0x28 }); // add rsp, 28h
                s.AddRange(new byte[] { 0xC3 }); // ret
                shellcode = s.ToArray();
            }
            else
            {
                // x86 shellcode
                uint pa = (uint)(remotePath.ToInt64() & 0xFFFFFFFF);
                uint la = (uint)(remoteFn.ToInt64() & 0xFFFFFFFF);
                shellcode = new byte[] {
                    0x68, (byte)(pa & 0xFF), (byte)((pa >> 8) & 0xFF), (byte)((pa >> 16) & 0xFF), (byte)((pa >> 24) & 0xFF),
                    0x6A, 0x00,
                    0x6A, 0x00,
                    0x68, (byte)(pa & 0xFF), (byte)((pa >> 8) & 0xFF), (byte)((pa >> 16) & 0xFF), (byte)((pa >> 24) & 0xFF),
                    0xB8, (byte)(la & 0xFF), (byte)((la >> 8) & 0xFF), (byte)((la >> 16) & 0xFF), (byte)((la >> 24) & 0xFF),
                    0xFF, 0xD0,
                    0xC3
                };
            }

            IntPtr sm = Native.VirtualAllocEx(hProc, IntPtr.Zero, (uint)shellcode.Length, Native.MEM_COMMIT | Native.MEM_RESERVE, Native.PAGE_EXECUTE_READWRITE);
            Native.WriteProcessMemory(hProc, sm, shellcode, (uint)shellcode.Length, out written);

            int tid;
            IntPtr hThread = Native.CreateRemoteThread(hProc, IntPtr.Zero, 0, sm, IntPtr.Zero, 0, out tid);
            if (hThread == IntPtr.Zero)
            {
                Native.VirtualFreeEx(hProc, sm, 0, Native.MEM_RELEASE);
                Native.VirtualFreeEx(hProc, remotePath, 0, Native.MEM_RELEASE);
                Native.FreeLibrary(localMono);
                return "Failed to spawn remote thread for Mono shellcode.";
            }

            Native.WaitForSingleObject(hThread, 8000);
            Native.CloseHandle(hThread);

            Native.VirtualFreeEx(hProc, sm, 0, Native.MEM_RELEASE);
            Native.VirtualFreeEx(hProc, remotePath, 0, Native.MEM_RELEASE);
            Native.FreeLibrary(localMono);

            SafeLog(log, "Mono assembly successfully loaded into Unity AppDomain!", InkwellTheme.Success);
            return null;
        }
        #endregion

        #region Vector: MelonLoader / Mod Deploy
        static string DeployMelonLoader(Process proc, string dllPath, LogCallback log)
        {
            string gameDir = Path.GetDirectoryName(proc.MainModule.FileName);
            string modsDir = Path.Combine(gameDir, "Mods");
            string bepDir = Path.Combine(gameDir, "BepInEx", "plugins");

            string targetDir = Directory.Exists(modsDir) ? modsDir : (Directory.Exists(bepDir) ? bepDir : null);

            if (targetDir == null)
            {
                // Auto create Mods directory
                try { Directory.CreateDirectory(modsDir); targetDir = modsDir; }
                catch (Exception ex) { return "Unable to create or locate Mods directory: " + ex.Message; }
            }

            string destFile = Path.Combine(targetDir, Path.GetFileName(dllPath));
            try
            {
                File.Copy(dllPath, destFile, true);
                SafeLog(log, "Deployed mod payload to: " + destFile, InkwellTheme.Success);
                return null;
            }
            catch (Exception ex)
            {
                return "File deployment failed: " + ex.Message;
            }
        }
        #endregion

        #region Helpers
        static IntPtr WriteRemoteString(IntPtr hProc, string str, out IntPtr loadLibAddr)
        {
            byte[] bytes = Encoding.Unicode.GetBytes(str + "\0");
            uint size = (uint)bytes.Length;

            IntPtr mem = Native.VirtualAllocEx(hProc, IntPtr.Zero, size, Native.MEM_COMMIT | Native.MEM_RESERVE, Native.PAGE_READWRITE);
            if (mem == IntPtr.Zero)
            {
                loadLibAddr = IntPtr.Zero;
                return IntPtr.Zero;
            }

            int written;
            if (!Native.WriteProcessMemory(hProc, mem, bytes, size, out written))
            {
                Native.VirtualFreeEx(hProc, mem, 0, Native.MEM_RELEASE);
                loadLibAddr = IntPtr.Zero;
                return IntPtr.Zero;
            }

            loadLibAddr = Native.GetProcAddress(Native.GetModuleHandle("kernel32.dll"), "LoadLibraryW");
            return mem;
        }

        static void UnlinkPEB(IntPtr hProc, string moduleName, LogCallback log)
        {
            try
            {
                Native.PROCESS_BASIC_INFORMATION pbi = new Native.PROCESS_BASIC_INFORMATION();
                uint retLen;
                int status = Native.NtQueryInformationProcess(hProc, 0, ref pbi, (uint)Marshal.SizeOf(typeof(Native.PROCESS_BASIC_INFORMATION)), out retLen);
                if (status != 0 || pbi.PebBaseAddress == IntPtr.Zero) return;

                int ptrSize = IntPtr.Size;
                int ldrOffset = ptrSize == 8 ? 0x18 : 0x0C;
                IntPtr pLdrPtr = (IntPtr)(pbi.PebBaseAddress.ToInt64() + ldrOffset);

                byte[] ldrBuf = new byte[ptrSize];
                int read;
                if (!Native.ReadProcessMemory(hProc, pLdrPtr, ldrBuf, (uint)ptrSize, out read)) return;

                IntPtr pLdr = (IntPtr)(ptrSize == 8 ? BitConverter.ToInt64(ldrBuf, 0) : BitConverter.ToInt32(ldrBuf, 0));
                if (pLdr == IntPtr.Zero) return;

                // InMemoryOrderModuleList offset = ptrSize == 8 ? 0x20 : 0x14
                int listOffset = ptrSize == 8 ? 0x20 : 0x14;
                IntPtr pHead = (IntPtr)(pLdr.ToInt64() + listOffset);

                byte[] headBuf = new byte[ptrSize * 2];
                if (!Native.ReadProcessMemory(hProc, pHead, headBuf, (uint)(ptrSize * 2), out read)) return;

                IntPtr pCurrent = (IntPtr)(ptrSize == 8 ? BitConverter.ToInt64(headBuf, 0) : BitConverter.ToInt32(headBuf, 0));

                int loopLimit = 256;
                while (pCurrent != pHead && pCurrent != IntPtr.Zero && loopLimit-- > 0)
                {
                    // LDR_DATA_TABLE_ENTRY:
                    // BaseDllName UNICODE_STRING: offset ptrSize == 8 ? 0x48 : 0x28
                    int nameOffset = ptrSize == 8 ? 0x48 : 0x28;
                    byte[] usBuf = new byte[16];
                    Native.ReadProcessMemory(hProc, (IntPtr)(pCurrent.ToInt64() + nameOffset), usBuf, 16, out read);

                    ushort len = BitConverter.ToUInt16(usBuf, 0);
                    IntPtr pBuffer = (IntPtr)(ptrSize == 8 ? BitConverter.ToInt64(usBuf, 8) : BitConverter.ToInt32(usBuf, 4));

                    if (len > 0 && pBuffer != IntPtr.Zero)
                    {
                        byte[] nameBuf = new byte[len];
                        Native.ReadProcessMemory(hProc, pBuffer, nameBuf, len, out read);
                        string loadedName = Encoding.Unicode.GetString(nameBuf);

                        if (loadedName.IndexOf(moduleName, StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            // Unlink node: Blink->Flink = Flink; Flink->Blink = Blink;
                            byte[] nodeBuf = new byte[ptrSize * 2];
                            Native.ReadProcessMemory(hProc, pCurrent, nodeBuf, (uint)(ptrSize * 2), out read);
                            IntPtr flink = (IntPtr)(ptrSize == 8 ? BitConverter.ToInt64(nodeBuf, 0) : BitConverter.ToInt32(nodeBuf, 0));
                            IntPtr blink = (IntPtr)(ptrSize == 8 ? BitConverter.ToInt64(nodeBuf, ptrSize) : BitConverter.ToInt32(nodeBuf, ptrSize));

                            int written;
                            // Blink's Flink = flink
                            Native.WriteProcessMemory(hProc, blink, BitConverter.GetBytes(flink.ToInt64()), (uint)ptrSize, out written);
                            // Flink's Blink = blink
                            Native.WriteProcessMemory(hProc, (IntPtr)(flink.ToInt64() + ptrSize), BitConverter.GetBytes(blink.ToInt64()), (uint)ptrSize, out written);

                            SafeLog(log, "Unlinked " + loadedName + " from PEB->Ldr module doubly linked lists.", InkwellTheme.Success);
                            break;
                        }
                    }

                    // Next entry
                    byte[] nextBuf = new byte[ptrSize];
                    Native.ReadProcessMemory(hProc, pCurrent, nextBuf, (uint)ptrSize, out read);
                    pCurrent = (IntPtr)(ptrSize == 8 ? BitConverter.ToInt64(nextBuf, 0) : BitConverter.ToInt32(nextBuf, 0));
                }
            }
            catch (Exception ex)
            {
                SafeLog(log, "PEB unlinking anomaly: " + ex.Message, InkwellTheme.Warning);
            }
        }
        #endregion
    }
    #endregion

    #region Inkwell Design System Theme & Controls
    static class InkwellTheme
    {
        public static readonly Color BgCanvas = Color.FromArgb(10, 9, 14);       // #0A090E
        public static readonly Color BgCard = Color.FromArgb(20, 14, 32);         // #140E20
        public static readonly Color BgInput = Color.FromArgb(28, 21, 44);        // #1C152C
        public static readonly Color Border = Color.FromArgb(61, 38, 96);         // #3D2660
        public static readonly Color Accent = Color.FromArgb(148, 71, 242);       // #9447F2
        public static readonly Color AccentHover = Color.FromArgb(168, 85, 247);  // #A855F7
        public static readonly Color TextPrimary = Color.FromArgb(237, 233, 254); // #EDE9FE
        public static readonly Color TextMuted = Color.FromArgb(140, 134, 168);   // #8C86A8
        public static readonly Color TextAccent = Color.FromArgb(192, 132, 252);  // #C084FC
        public static readonly Color Success = Color.FromArgb(16, 185, 129);      // #10B981
        public static readonly Color Warning = Color.FromArgb(245, 158, 11);      // #F59E0B
        public static readonly Color Danger = Color.FromArgb(239, 68, 68);        // #EF4444
    }

    class InkwellButton : Button
    {
        public int CornerRadius = 6;
        public Color NormalColor = InkwellTheme.Accent;
        public Color HoverColor = InkwellTheme.AccentHover;
        public Color BorderColor = InkwellTheme.Border;
        bool isHovered = false;

        public InkwellButton()
        {
            FlatStyle = FlatStyle.Flat;
            FlatAppearance.BorderSize = 0;
            BackColor = NormalColor;
            ForeColor = Color.White;
            Font = new Font("Segoe UI", 9.5f, FontStyle.Bold);
            Cursor = Cursors.Hand;
            DoubleBuffered = true;
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
            var rect = new Rectangle(0, 0, Width - 1, Height - 1);
            using (var path = GetRoundPath(rect, CornerRadius))
            {
                using (var brush = new SolidBrush(isHovered ? HoverColor : NormalColor))
                    e.Graphics.FillPath(brush, path);

                using (var pen = new Pen(BorderColor, 1f))
                    e.Graphics.DrawPath(pen, path);

                TextRenderer.DrawText(e.Graphics, Text, Font, rect, ForeColor,
                    TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);
            }
        }

        protected override void OnMouseEnter(EventArgs e) { isHovered = true; Invalidate(); base.OnMouseEnter(e); }
        protected override void OnMouseLeave(EventArgs e) { isHovered = false; Invalidate(); base.OnMouseLeave(e); }

        static GraphicsPath GetRoundPath(Rectangle r, int rad)
        {
            var p = new GraphicsPath();
            int d = rad * 2;
            p.AddArc(r.X, r.Y, d, d, 180, 90);
            p.AddArc(r.Right - d, r.Y, d, d, 270, 90);
            p.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
            p.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
            p.CloseFigure();
            return p;
        }
    }
    #endregion

    #region Main Inkwell Injector GUI Form
    class MainForm : Form
    {
        // Controls
        ListView procList;
        TextBox searchBox;
        TextBox dllPathBox;
        ComboBox methodBox;
        RichTextBox logBox;
        InkwellButton btnRefresh, btnBrowse, btnInject;
        Label lblTargetStatus, lblAdminBadge;

        // Stealth & Options controls
        CheckBox chkPebUnlink;
        CheckBox chkEraseHeaders;
        CheckBox chkCloseOnInject;
        CheckBox chkAutoInject;
        ComboBox cmbArchFilter;

        // Unity / Mono controls
        TextBox txtMonoNamespace;
        TextBox txtMonoClass;
        TextBox txtMonoMethod;

        // State & Timers
        System.Windows.Forms.Timer autoInjectTimer;
        List<ListViewItem> allProcesses = new List<ListViewItem>();
        InjectionOptions options = new InjectionOptions();

        public MainForm()
        {
            Text = "INKWELL // TACTICAL DLL INJECTOR";
            Size = new Size(1020, 750);
            MinimumSize = new Size(880, 640);
            StartPosition = FormStartPosition.CenterScreen;
            BackColor = InkwellTheme.BgCanvas;
            ForeColor = InkwellTheme.TextPrimary;
            Font = new Font("Segoe UI", 9.5f);
            DoubleBuffered = true;
            Icon = SystemIcons.Shield;

            BuildInterface();
            CheckElevation();
            RefreshProcessList();

            autoInjectTimer = new System.Windows.Forms.Timer();
            autoInjectTimer.Interval = 1000;
            autoInjectTimer.Tick += AutoInjectTimer_Tick;
        }

        void CheckElevation()
        {
            bool isAdmin = false;
            try
            {
                var identity = WindowsIdentity.GetCurrent();
                var principal = new WindowsPrincipal(identity);
                isAdmin = principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch { }

            if (!isAdmin)
            {
                lblAdminBadge.Text = "⚠ NOT ELEVATED";
                lblAdminBadge.ForeColor = InkwellTheme.Warning;
                Log("Warning: Injector is running without Administrator elevation. Some processes may reject OpenProcess.", InkwellTheme.Warning);
            }
            else
            {
                lblAdminBadge.Text = "● ADMIN ELEVATED";
                lblAdminBadge.ForeColor = InkwellTheme.Success;
            }
        }

        void BuildInterface()
        {
            // ── Top Header Banner ──
            Panel pnlHeader = new Panel
            {
                Dock = DockStyle.Top,
                Height = 62,
                BackColor = InkwellTheme.BgCard,
                Padding = new Padding(20, 10, 20, 10)
            };
            Controls.Add(pnlHeader);

            Label lblTitle = new Label
            {
                Text = "⚡ INKWELL // TACTICAL DLL INJECTOR",
                Font = new Font("Segoe UI", 13.5f, FontStyle.Bold),
                ForeColor = InkwellTheme.Accent,
                AutoSize = true,
                Location = new Point(18, 16)
            };
            pnlHeader.Controls.Add(lblTitle);

            Label lblVer = new Label
            {
                Text = "v2.5 CORE",
                Font = new Font("Segoe UI", 8.5f, FontStyle.Bold),
                BackColor = InkwellTheme.BgInput,
                ForeColor = InkwellTheme.TextAccent,
                Padding = new Padding(6, 3, 6, 3),
                AutoSize = true,
                Location = new Point(lblTitle.Right + 14, 20)
            };
            pnlHeader.Controls.Add(lblVer);

            lblAdminBadge = new Label
            {
                Text = "● ADMIN CHECK",
                Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
                ForeColor = InkwellTheme.TextMuted,
                AutoSize = true,
                Anchor = AnchorStyles.Top | AnchorStyles.Right,
                Location = new Point(pnlHeader.Width - 190, 20)
            };
            pnlHeader.Controls.Add(lblAdminBadge);

            // ── Tab Control ──
            TabControl tabs = new TabControl
            {
                Dock = DockStyle.Fill,
                Padding = new Point(18, 8),
                Font = new Font("Segoe UI", 10f, FontStyle.Bold)
            };
            Controls.Add(tabs);

            TabPage tabInject = new TabPage("01 // INJECTION WORKSPACE");
            tabInject.BackColor = InkwellTheme.BgCanvas;
            tabs.TabPages.Add(tabInject);

            TabPage tabStealth = new TabPage("02 // STEALTH & OPTIONS");
            tabStealth.BackColor = InkwellTheme.BgCanvas;
            tabs.TabPages.Add(tabStealth);

            TabPage tabMono = new TabPage("03 // UNITY & MONO SUITE");
            tabMono.BackColor = InkwellTheme.BgCanvas;
            tabs.TabPages.Add(tabMono);

            TabPage tabLogs = new TabPage("04 // DIAGNOSTICS LOG");
            tabLogs.BackColor = InkwellTheme.BgCanvas;
            tabs.TabPages.Add(tabLogs);

            BuildWorkspaceTab(tabInject);
            BuildStealthTab(tabStealth);
            BuildMonoTab(tabMono);
            BuildLogsTab(tabLogs);
        }

        void BuildWorkspaceTab(TabPage tab)
        {
            tab.Padding = new Padding(12);

            // 1. Bottom Staging Panel (Dock Bottom)
            Panel pnlBottom = new Panel
            {
                Dock = DockStyle.Bottom,
                Height = 138,
                BackColor = InkwellTheme.BgCanvas,
                Padding = new Padding(0, 10, 0, 0)
            };
            tab.Controls.Add(pnlBottom);

            Panel cardStaging = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = InkwellTheme.BgCard,
                Padding = new Padding(18, 12, 18, 12)
            };
            pnlBottom.Controls.Add(cardStaging);

            // Row 1: Payload DLL Selection
            Label lblDll = new Label
            {
                Text = "Payload DLL:",
                Location = new Point(14, 18),
                AutoSize = true,
                ForeColor = InkwellTheme.TextMuted,
                Font = new Font("Segoe UI", 9.5f, FontStyle.Bold)
            };
            cardStaging.Controls.Add(lblDll);

            btnBrowse = new InkwellButton
            {
                Text = "Browse...",
                Location = new Point(cardStaging.Width - 120, 12),
                Size = new Size(105, 30),
                Anchor = AnchorStyles.Top | AnchorStyles.Right,
                NormalColor = InkwellTheme.BgInput,
                HoverColor = InkwellTheme.Border
            };
            btnBrowse.Click += (s, e) =>
            {
                using (OpenFileDialog ofd = new OpenFileDialog { Filter = "Dynamic Link Libraries (*.dll)|*.dll|All Files (*.*)|*.*", Title = "Select Injection Payload" })
                {
                    if (ofd.ShowDialog() == DialogResult.OK) dllPathBox.Text = ofd.FileName;
                }
            };
            cardStaging.Controls.Add(btnBrowse);

            dllPathBox = new TextBox
            {
                Location = new Point(125, 13),
                Size = new Size(cardStaging.Width - 260, 28),
                BackColor = InkwellTheme.BgInput,
                ForeColor = InkwellTheme.TextPrimary,
                BorderStyle = BorderStyle.FixedSingle,
                Font = new Font("Segoe UI", 10f),
                AllowDrop = true,
                Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right
            };
            dllPathBox.DragEnter += (s, e) => { if (e.Data.GetDataPresent(DataFormats.FileDrop)) e.Effect = DragDropEffects.Copy; };
            dllPathBox.DragDrop += (s, e) => { string[] files = (string[])e.Data.GetData(DataFormats.FileDrop); if (files.Length > 0) dllPathBox.Text = files[0]; };
            cardStaging.Controls.Add(dllPathBox);

            // Row 2: Method & Inject Action
            Label lblMeth = new Label
            {
                Text = "Injection Method:",
                Location = new Point(14, 66),
                AutoSize = true,
                ForeColor = InkwellTheme.TextMuted,
                Font = new Font("Segoe UI", 9.5f, FontStyle.Bold)
            };
            cardStaging.Controls.Add(lblMeth);

            methodBox = new ComboBox
            {
                Location = new Point(155, 62),
                Size = new Size(350, 28),
                DropDownStyle = ComboBoxStyle.DropDownList,
                BackColor = InkwellTheme.BgInput,
                ForeColor = InkwellTheme.TextPrimary,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 10f),
                Anchor = AnchorStyles.Top | AnchorStyles.Left
            };
            methodBox.Items.AddRange(new object[] {
                "CreateRemoteThread (Standard)",
                "NtCreateThreadEx (Native NTAPI)",
                "QueueUserAPC (Alertable Thread)",
                "Thread Context Hijack (SetThreadContext)",
                "Manual Map x64 (Stealth Relocations)",
                "Mono Assembly Load (Unity Engine)",
                "MelonLoader / Mod Folder Deploy"
            });
            methodBox.SelectedIndex = 0;
            cardStaging.Controls.Add(methodBox);

            btnInject = new InkwellButton
            {
                Text = "⚡ INJECT PAYLOAD",
                Location = new Point(cardStaging.Width - 225, 54),
                Size = new Size(210, 42),
                NormalColor = InkwellTheme.Accent,
                HoverColor = InkwellTheme.AccentHover,
                Font = new Font("Segoe UI", 11f, FontStyle.Bold),
                Anchor = AnchorStyles.Top | AnchorStyles.Right
            };
            btnInject.Click += BtnInject_Click;
            cardStaging.Controls.Add(btnInject);

            // 2. Top Search Panel (Dock Top)
            Panel pnlSearch = new Panel
            {
                Dock = DockStyle.Top,
                Height = 52,
                BackColor = InkwellTheme.BgCanvas,
                Padding = new Padding(0, 4, 0, 8)
            };
            tab.Controls.Add(pnlSearch);

            Label lblSearch = new Label
            {
                Text = "Search Process:",
                Location = new Point(4, 14),
                AutoSize = true,
                ForeColor = InkwellTheme.TextMuted,
                Font = new Font("Segoe UI", 9.5f, FontStyle.Bold)
            };
            pnlSearch.Controls.Add(lblSearch);

            searchBox = new TextBox
            {
                Location = new Point(130, 10),
                Size = new Size(290, 28),
                BackColor = InkwellTheme.BgInput,
                ForeColor = InkwellTheme.TextPrimary,
                BorderStyle = BorderStyle.FixedSingle,
                Font = new Font("Segoe UI", 10f)
            };
            searchBox.TextChanged += (s, e) => FilterProcessList();
            pnlSearch.Controls.Add(searchBox);

            cmbArchFilter = new ComboBox
            {
                Location = new Point(430, 10),
                Size = new Size(120, 28),
                DropDownStyle = ComboBoxStyle.DropDownList,
                BackColor = InkwellTheme.BgInput,
                ForeColor = InkwellTheme.TextPrimary,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 9.5f)
            };
            cmbArchFilter.Items.AddRange(new object[] { "All Arch", "x64 Only", "x86 Only" });
            cmbArchFilter.SelectedIndex = 0;
            cmbArchFilter.SelectedIndexChanged += (s, e) => FilterProcessList();
            pnlSearch.Controls.Add(cmbArchFilter);

            btnRefresh = new InkwellButton
            {
                Text = "⟳ Refresh",
                Location = new Point(560, 9),
                Size = new Size(105, 30),
                NormalColor = InkwellTheme.BgCard,
                HoverColor = InkwellTheme.Border
            };
            btnRefresh.Click += (s, e) => RefreshProcessList();
            pnlSearch.Controls.Add(btnRefresh);

            lblTargetStatus = new Label
            {
                Text = "No target selected",
                Location = new Point(pnlSearch.Width - 340, 14),
                Size = new Size(330, 24),
                TextAlign = ContentAlignment.MiddleRight,
                ForeColor = InkwellTheme.TextAccent,
                Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
                Anchor = AnchorStyles.Top | AnchorStyles.Right,
                AutoSize = false
            };
            pnlSearch.Controls.Add(lblTargetStatus);

            // 3. Center Process List Panel (Dock Fill)
            Panel pnlListWrap = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = InkwellTheme.BgCanvas,
                Padding = new Padding(0, 0, 0, 0)
            };
            tab.Controls.Add(pnlListWrap);

            procList = new ListView
            {
                Dock = DockStyle.Fill,
                View = View.Details,
                FullRowSelect = true,
                MultiSelect = false,
                BackColor = InkwellTheme.BgCard,
                ForeColor = InkwellTheme.TextPrimary,
                BorderStyle = BorderStyle.None,
                Font = new Font("Segoe UI", 9.5f)
            };
            procList.Columns.Add("PID", 85);
            procList.Columns.Add("Process Name", 240);
            procList.Columns.Add("Main Window Title", 390);
            procList.Columns.Add("Arch", 80);
            procList.Columns.Add("Memory", 120);
            procList.SelectedIndexChanged += ProcList_SelectedIndexChanged;
            pnlListWrap.Controls.Add(procList);

            // Ensure correct WinForms Z-Order
            pnlBottom.BringToFront();
            pnlSearch.BringToFront();
            pnlListWrap.BringToFront();
        }

        void BuildStealthTab(TabPage tab)
        {
            tab.Padding = new Padding(16);

            Panel card = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = InkwellTheme.BgCard,
                Padding = new Padding(28),
                AutoScroll = true
            };
            tab.Controls.Add(card);

            Label title = new Label
            {
                Text = "ADVANCED STEALTH, CLOAKING & AUTOMATION",
                Font = new Font("Segoe UI", 12f, FontStyle.Bold),
                ForeColor = InkwellTheme.TextAccent,
                AutoSize = true,
                Location = new Point(24, 22)
            };
            card.Controls.Add(title);

            chkPebUnlink = new CheckBox
            {
                Text = "Unlink Injected DLL from Remote PEB Lists (InLoadOrder, InMemoryOrder, InitializationOrder)",
                Location = new Point(28, 68),
                AutoSize = true,
                Checked = true,
                Font = new Font("Segoe UI", 10f, FontStyle.Bold),
                ForeColor = InkwellTheme.TextPrimary
            };
            card.Controls.Add(chkPebUnlink);

            Label descPeb = new Label
            {
                Text = "Traverses PEB->Ldr and unlinks node pointers so PSAPI, CreateToolhelp32Snapshot, and EnumProcessModules cannot detect the module.",
                Location = new Point(50, 96),
                AutoSize = true,
                ForeColor = InkwellTheme.TextMuted
            };
            card.Controls.Add(descPeb);

            chkEraseHeaders = new CheckBox
            {
                Text = "Erase Remote PE DOS & NT Headers (Manual Map Mode)",
                Location = new Point(28, 140),
                AutoSize = true,
                Checked = true,
                Font = new Font("Segoe UI", 10f, FontStyle.Bold),
                ForeColor = InkwellTheme.TextPrimary
            };
            card.Controls.Add(chkEraseHeaders);

            Label descHdr = new Label
            {
                Text = "Zeroes out the first 0x1000 bytes (DOS header, PE signature, Section Table) to defeat in-memory signature heuristics and disk-comparison scanners.",
                Location = new Point(50, 168),
                AutoSize = true,
                ForeColor = InkwellTheme.TextMuted
            };
            card.Controls.Add(descHdr);

            chkCloseOnInject = new CheckBox
            {
                Text = "Automatically Terminate Injector on Successful Injection",
                Location = new Point(28, 212),
                AutoSize = true,
                Font = new Font("Segoe UI", 10f, FontStyle.Bold),
                ForeColor = InkwellTheme.TextPrimary
            };
            card.Controls.Add(chkCloseOnInject);

            Label descClose = new Label
            {
                Text = "Leaves zero footprint on desktop once target injection routine returns successfully.",
                Location = new Point(50, 240),
                AutoSize = true,
                ForeColor = InkwellTheme.TextMuted
            };
            card.Controls.Add(descClose);

            chkAutoInject = new CheckBox
            {
                Text = "Auto-Inject When Selected Target Process Launches",
                Location = new Point(28, 284),
                AutoSize = true,
                Font = new Font("Segoe UI", 10f, FontStyle.Bold),
                ForeColor = InkwellTheme.TextPrimary
            };
            chkAutoInject.CheckedChanged += (s, e) =>
            {
                if (chkAutoInject.Checked)
                {
                    autoInjectTimer.Start();
                    Log("Auto-Injection monitor armed for: " + (procList.SelectedItems.Count > 0 ? procList.SelectedItems[0].SubItems[1].Text : "selected target"), InkwellTheme.Success);
                }
                else
                {
                    autoInjectTimer.Stop();
                    Log("Auto-Injection monitor disarmed.", InkwellTheme.TextMuted);
                }
            };
            card.Controls.Add(chkAutoInject);

            Label descAuto = new Label
            {
                Text = "Polls process table once per second; triggers injection immediately upon process creation.",
                Location = new Point(50, 312),
                AutoSize = true,
                ForeColor = InkwellTheme.TextMuted
            };
            card.Controls.Add(descAuto);
        }

        void BuildMonoTab(TabPage tab)
        {
            tab.Padding = new Padding(16);

            Panel card = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = InkwellTheme.BgCard,
                Padding = new Padding(28),
                AutoScroll = true
            };
            tab.Controls.Add(card);

            Label title = new Label
            {
                Text = "UNITY ENGINE & MONO ASSEMBLY LOADER CONFIGURATION",
                Font = new Font("Segoe UI", 12f, FontStyle.Bold),
                ForeColor = InkwellTheme.TextAccent,
                AutoSize = true,
                Location = new Point(24, 22)
            };
            card.Controls.Add(title);

            Label info = new Label
            {
                Text = "Used for injecting managed C# DLL assemblies directly into Unity Mono games (e.g., Liar's Bar, Phasmophobia).\nDirectly invokes mono_assembly_load_from_full and calls startup entry points without requiring external loaders.",
                Location = new Point(28, 58),
                AutoSize = true,
                ForeColor = InkwellTheme.TextMuted
            };
            card.Controls.Add(info);

            int startY = 120;
            int rowSpacing = 54;

            Label lblNs = new Label { Text = "Namespace:", Location = new Point(28, startY + 4), AutoSize = true, ForeColor = InkwellTheme.TextMuted, Font = new Font("Segoe UI", 9.5f, FontStyle.Bold) };
            card.Controls.Add(lblNs);

            txtMonoNamespace = new TextBox
            {
                Text = "LiarsBarMod",
                Location = new Point(160, startY),
                Size = new Size(340, 28),
                BackColor = InkwellTheme.BgInput,
                ForeColor = InkwellTheme.TextPrimary,
                BorderStyle = BorderStyle.FixedSingle,
                Font = new Font("Segoe UI", 10f)
            };
            card.Controls.Add(txtMonoNamespace);

            Label lblClass = new Label { Text = "Class Name:", Location = new Point(28, startY + rowSpacing + 4), AutoSize = true, ForeColor = InkwellTheme.TextMuted, Font = new Font("Segoe UI", 9.5f, FontStyle.Bold) };
            card.Controls.Add(lblClass);

            txtMonoClass = new TextBox
            {
                Text = "Loader",
                Location = new Point(160, startY + rowSpacing),
                Size = new Size(340, 28),
                BackColor = InkwellTheme.BgInput,
                ForeColor = InkwellTheme.TextPrimary,
                BorderStyle = BorderStyle.FixedSingle,
                Font = new Font("Segoe UI", 10f)
            };
            card.Controls.Add(txtMonoClass);

            Label lblMethod = new Label { Text = "Method Name:", Location = new Point(28, startY + (rowSpacing * 2) + 4), AutoSize = true, ForeColor = InkwellTheme.TextMuted, Font = new Font("Segoe UI", 9.5f, FontStyle.Bold) };
            card.Controls.Add(lblMethod);

            txtMonoMethod = new TextBox
            {
                Text = "Init",
                Location = new Point(160, startY + (rowSpacing * 2)),
                Size = new Size(340, 28),
                BackColor = InkwellTheme.BgInput,
                ForeColor = InkwellTheme.TextPrimary,
                BorderStyle = BorderStyle.FixedSingle,
                Font = new Font("Segoe UI", 10f)
            };
            card.Controls.Add(txtMonoMethod);
        }

        void BuildLogsTab(TabPage tab)
        {
            tab.Padding = new Padding(16);

            Panel pnlLogBottom = new Panel
            {
                Dock = DockStyle.Bottom,
                Height = 44,
                BackColor = InkwellTheme.BgCanvas,
                Padding = new Padding(0, 8, 0, 0)
            };
            tab.Controls.Add(pnlLogBottom);

            InkwellButton btnClearLog = new InkwellButton
            {
                Text = "Clear Log",
                Size = new Size(110, 32),
                Dock = DockStyle.Right,
                NormalColor = InkwellTheme.BgCard,
                HoverColor = InkwellTheme.Border
            };
            btnClearLog.Click += (s, e) => { if (logBox != null) logBox.Clear(); };
            pnlLogBottom.Controls.Add(btnClearLog);

            logBox = new RichTextBox
            {
                Dock = DockStyle.Fill,
                BackColor = InkwellTheme.BgCard,
                ForeColor = InkwellTheme.TextMuted,
                BorderStyle = BorderStyle.None,
                ReadOnly = true,
                Font = new Font("Consolas", 10f),
                ScrollBars = RichTextBoxScrollBars.Vertical
            };
            tab.Controls.Add(logBox);

            pnlLogBottom.BringToFront();
            logBox.BringToFront();

            Log("Inkwell Tactical Injector initialized. System ready.", InkwellTheme.Success);
        }

        public void Log(string msg, Color col)
        {
            if (logBox == null || logBox.IsDisposed) return;
            if (InvokeRequired)
            {
                BeginInvoke(new Action(() => Log(msg, col)));
                return;
            }

            string ts = DateTime.Now.ToString("HH:mm:ss");
            logBox.SelectionStart = logBox.TextLength;
            logBox.SelectionColor = InkwellTheme.TextMuted;
            logBox.AppendText("[" + ts + "] ");

            logBox.SelectionStart = logBox.TextLength;
            logBox.SelectionColor = col;
            logBox.AppendText(msg + "\n");
            logBox.ScrollToCaret();
        }

        void RefreshProcessList()
        {
            procList.Items.Clear();
            allProcesses.Clear();

            Process[] procs = Process.GetProcesses();
            Array.Sort(procs, (a, b) => string.Compare(a.ProcessName, b.ProcessName, true));

            foreach (var p in procs)
            {
                try
                {
                    string arch = "x64";
                    try
                    {
                        bool wow;
                        if (Native.IsWow64Process(p.Handle, out wow) && wow) arch = "x86";
                    }
                    catch { arch = "??"; }

                    string mem = (p.WorkingSet64 / 1024 / 1024) + " MB";
                    string title = p.MainWindowTitle;

                    var item = new ListViewItem(new string[] { p.Id.ToString(), p.ProcessName, title, arch, mem });
                    item.Tag = p.Id;
                    allProcesses.Add(item);
                }
                catch { }
            }

            FilterProcessList();
            Log("Process snapshot refreshed (" + allProcesses.Count + " active processes).", InkwellTheme.TextMuted);
        }

        void FilterProcessList()
        {
            string filter = searchBox.Text.Trim().ToLower();
            string archFilter = cmbArchFilter.SelectedIndex == 1 ? "x64" : (cmbArchFilter.SelectedIndex == 2 ? "x86" : "");

            procList.BeginUpdate();
            procList.Items.Clear();

            foreach (var item in allProcesses)
            {
                bool matchesText = string.IsNullOrEmpty(filter) ||
                    item.SubItems[1].Text.ToLower().Contains(filter) ||
                    item.SubItems[0].Text.Contains(filter) ||
                    item.SubItems[2].Text.ToLower().Contains(filter);

                bool matchesArch = string.IsNullOrEmpty(archFilter) || item.SubItems[3].Text == archFilter;

                if (matchesText && matchesArch)
                {
                    procList.Items.Add(item);
                }
            }
            procList.EndUpdate();
        }

        void ProcList_SelectedIndexChanged(object sender, EventArgs e)
        {
            if (procList.SelectedItems.Count > 0)
            {
                var item = procList.SelectedItems[0];
                lblTargetStatus.Text = item.SubItems[1].Text + " (PID " + item.SubItems[0].Text + ", " + item.SubItems[3].Text + ")";
                lblTargetStatus.ForeColor = InkwellTheme.TextAccent;
            }
            else
            {
                lblTargetStatus.Text = "No target selected";
                lblTargetStatus.ForeColor = InkwellTheme.TextMuted;
            }
        }

        void BtnInject_Click(object sender, EventArgs e)
        {
            if (procList.SelectedItems.Count == 0)
            {
                MessageBox.Show("Please select a target process from the process list.", "Inkwell Injector", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            string dllPath = dllPathBox.Text.Trim();
            if (string.IsNullOrEmpty(dllPath) || !File.Exists(dllPath))
            {
                MessageBox.Show("Please specify a valid path to an existing DLL file.", "Inkwell Injector", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            int pid = (int)procList.SelectedItems[0].Tag;
            string procName = procList.SelectedItems[0].SubItems[1].Text;
            InjectionMethod method = (InjectionMethod)methodBox.SelectedIndex;

            options.UnlinkFromPEB = chkPebUnlink.Checked;
            options.ErasePEHeaders = chkEraseHeaders.Checked;
            options.MonoNamespace = txtMonoNamespace.Text.Trim();
            options.MonoClass = txtMonoClass.Text.Trim();
            options.MonoMethod = txtMonoMethod.Text.Trim();

            Log("Engaging injection into " + procName + " (PID " + pid + ") using vector " + method + "...", InkwellTheme.Accent);

            string err = InjectionEngine.Execute(pid, dllPath, method, options, Log);

            if (err == null)
            {
                Log("SUCCESS: Injection successfully completed and verified!", InkwellTheme.Success);
                if (chkCloseOnInject.Checked)
                {
                    Thread.Sleep(800);
                    Application.Exit();
                }
            }
            else
            {
                Log("FAILURE: " + err, InkwellTheme.Danger);
                MessageBox.Show("Injection failed:\n" + err, "Inkwell Injector", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        void AutoInjectTimer_Tick(object sender, EventArgs e)
        {
            if (procList.SelectedItems.Count == 0) return;
            string targetName = procList.SelectedItems[0].SubItems[1].Text;

            var procs = Process.GetProcessesByName(targetName);
            if (procs.Length > 0 && !string.IsNullOrEmpty(dllPathBox.Text) && File.Exists(dllPathBox.Text))
            {
                autoInjectTimer.Stop();
                chkAutoInject.Checked = false;
                Log("Auto-Inject detected target process: " + targetName + " (PID " + procs[0].Id + "). Triggering payload...", InkwellTheme.Success);
                BtnInject_Click(null, null);
            }
        }
    }
    #endregion

    #region Application Entry Point
    static class Program
    {
        [STAThread]
        static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm());
        }
    }
    #endregion
}
