# INKWELL // TACTICAL DLL INJECTOR CORE v2.5

Unified multi-vector user-mode process injector, PE manual mapper, and Unity Mono assembly loader styled under the **Inkwell Tactical Design System**.

---

## 1. Directory Structure

```text
injector/
├── InkwellInjector.cs       # Complete standalone C# Windows Forms source code
├── InkwellInjector.exe      # Precompiled 64-bit standalone executable (Zero external dependencies)
├── build.bat                # Automated one-click compiler script via csc.exe
├── inkwell_injector.ini     # Configuration & persistence state file
└── README.md                # Technical systems documentation
```

---

## 2. Supported Injection Vectors

The injector combines the best mechanisms from `others/`, `mine/`, and `Liars-Bar-Mod-main/mono injector/`:

| Index | Vector | Target Subsystem | Description & Low-Level Mechanics |
| :---: | :--- | :--- | :--- |
| **0** | **CreateRemoteThread (Standard)** | `kernel32.dll` | Allocates virtual memory in target process via `VirtualAllocEx`, writes the Unicode DLL path, and dispatches remote execution to `LoadLibraryW`. |
| **1** | **NtCreateThreadEx (Native NTAPI)** | `ntdll.dll` | Direct invocation of native `NtCreateThreadEx` with `THREAD_ALL_ACCESS`, bypassing user-mode API detours placed on `CreateRemoteThread`. |
| **2** | **QueueUserAPC (Alertable Thread)** | Thread Pool | Iterates all active threads in target process via `CreateToolhelp32Snapshot`, queuing execution of `LoadLibraryW` to alertable worker threads. |
| **3** | **Thread Context Hijack** | CPU Registers | Suspends target thread (`SuspendThread`), queries 64-bit registers (`GetThreadContext`), writes an x64 trampoline stub calling `LoadLibraryW`, diverts `RIP`, and resumes execution. |
| **4** | **Manual Map x64 (Stealth)** | Raw Virtual Memory | In-memory PE loader. Parses DOS/NT headers, maps sections, processes base relocations (Delta math), resolves Import Address Table (IAT) descriptors, and executes remote `DllMain`. |
| **5** | **Mono Assembly Load (Unity Engine)** | `mono.dll` / `mono-2.0-bdwgc.dll` | Locates target Mono runtime module, resolves `mono_assembly_load_from_full`, constructs x64/x86 shellcode, and executes managed assembly loading into the Unity AppDomain (e.g. *Liar's Bar*). |
| **6** | **MelonLoader / Mod Folder Deploy** | Filesystem Hook | Directly detects game directory and deploys the DLL to the `Mods/` or `BepInEx/plugins/` directory for automated mod initialization. |

---

## 3. Stealth, Cloaking & Security Capabilities

- **PEB Module Unlinking (`UnlinkFromPEB`)**:
  Traverses `PEB->Ldr` lists (`InLoadOrderModuleList`, `InMemoryOrderModuleList`, `InInitializationOrderModuleList`). Atomically unlinks doubly linked list nodes (`Blink->Flink = Flink; Flink->Blink = Blink;`), rendering the injected DLL completely invisible to `Toolhelp32`, `EnumProcessModules`, and PSAPI scans.
- **Remote PE Header Erasure (`ErasePEHeaders`)**:
  Overwrites the first `0x1000` bytes (DOS Header, DOS Stub, PE Signature, Section Headers) with zeros in remote memory after mapping to defeat signature scanners and memory dumpers.
- **Target Architecture Defense**:
  Performs real-time `IsWow64Process` evaluation. Prevents crashing by blocking 64-bit manual mapping into 32-bit targets.
- **Administrator Elevation Validation**:
  Checks Windows token elevation (`WindowsPrincipal.IsInRole(Administrator)`) and renders an active status badge.

---

## 4. Inkwell Design System Specifications

Adheres strictly to the visual theme tokens established across the Inkwell suite (`Inkwell loader`, `Inkwell_Bodycam`, `Inkwell Marvel`):

- **Background Canvas**: Pitch Black (`#0A090E`)
- **Card Panels**: Dark Violet Glass (`#140E20`)
- **Input Fields & Search**: Deep Slate Violet (`#1C152C`)
- **Primary Accent**: Inkwell Purple (`#9447F2`) / Hover (`#A855F7`)
- **Highlight Accent**: Light Violet (`#C084FC`)
- **Status Indicators**:
  - Success: Cyber Emerald (`#10B981`)
  - Warning: Amber (`#F59E0B`)
  - Error: Crimson (`#EF4444`)
- **Borders**: Muted Violet (`#3D2660`)

---

## 5. Build & Compilation Instructions

To recompile the executable from source at any time without Visual Studio:

```cmd
build.bat
```

Or manually via the 64-bit .NET Framework compiler:
```cmd
"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /target:winexe /platform:x64 /optimize+ /out:"InkwellInjector.exe" "InkwellInjector.cs"
```
