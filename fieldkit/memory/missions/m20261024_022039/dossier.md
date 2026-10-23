# Mission m20261024_022039 — Map the license check of bench/toy_protector/belt1: find the check function, name its site, state what input would pass it. Do not modify the binary.
target: /tmp/swarmre_audit/fieldkit/bench/toy_protector/belt1

## identity
```
{"status": "ok", "path": "/tmp/swarmre_audit/fieldkit/bench/toy_protector/belt1", "size_bytes": 16000, "sha256": "75678056eafbb58e8ae3264f0a2778a6bfa08835488257a6142f9e655b98fba4", "file_verdict": "ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=6ab5d2889899a0522a745015199e6486afa22399, for GNU/Linux 3.2.0, not stripped", "readelf_h": "ELF Header:\n  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 \n  Class:                             ELF64\n  Data:                              2's complement, little endian\n  Version:                           1 (current)\n  OS/ABI:                            UNIX - System V\n  ABI Version:                       0\n  Type:                              DYN (Position-Independent Executable file)\n  Machine:                           Advanced Micro Devices X86-64\n  Version:                           0x1\n  Entry point address:               0x1080\n  Start of program headers:          64 (bytes into file)\n  Start of section headers:          14016 (bytes into file)\n  Flags:                             0x0\n  Size of this header:               64 (bytes)\n  Size of program headers:           56 (bytes)\n  Number of program headers:         13\n  Size of section headers:           64 (bytes)\n  Number of section headers:         31\n  Section header string table index: 30\n", "comment": "\nString dump of section '.comment':\n  [     0]  GCC: (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0\n\n", "n_strings": 64, "strings_census": ["/lib64/ld-linux-x86-64.so.2", "__libc_start_main", "__cxa_finalize", "strcmp", "libc.so.6", "GLIBC_2.2.5", "GLIBC_2.34", "_ITM_deregisterTMCloneTable", "__gmon_start__", "_ITM_registerTMCloneTable", "SWARM-OK-1337", "Not valid licence. Exit.", "Licensed. Welcome.", "GCC: (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0", "Scrt1.o", "__abi_tag", "crtstuff.c", "deregister_tm_clones", "__do_global_dtors_aux", "completed.0", "__do_global_dtors_aux_fini_array_entry", "frame_dummy", "__frame_dummy_init_array_entry", "belt1.c", "__FRAME_END__", "_DYNAMIC", "__GNU_EH_FRAME_HDR", "_GLOBAL_OFFSET_TABLE_", "__libc_start_main@GLIBC_2.34", "_ITM_deregisterTMCloneTable", "puts@GLIBC_2.2.5", "_edata", "__data_start", "strcmp@GLIBC_2.2.5", "__gmon_start__", "__dso_handle", "_IO_stdin_used", "__bss_start", "__TMC_END__", "_ITM_registerTMCloneTable", "__cxa_finalize@GLIBC_2.2.5", ".symtab", ".strtab", ".shstrtab", ".interp", ".note.gnu.property", ".note.gnu.build-id", ".note.ABI-tag", ".gnu.hash", ".dynsym", ".dynstr", ".gnu.version", ".gnu.version_r", ".rela.dyn", ".rela.plt", ".plt.got", ".plt.sec", ".rodata", ".eh_frame_hdr", ".eh_frame", ".init_array", ".fini_array", ".dynamic", ".comment"], "dyn_imports": "\n/tmp/swarmre_audit/fieldkit/bench/toy_protector/belt1:     file format elf64-x86-64\n\nDYNAMIC SYMBOL TABLE:\n0000000000000000      DF *UND*\t0000000000000000 (GLIBC_2.34) __libc_start_main\n0000000000000000  w   D  *UND*\t0000000000000000  Base        _ITM_deregisterTMCloneTable\n0000000000000000      DF *UND*\t0000000000000000 (GLIBC_2.2.5) puts\n0000000000000000      DF *UND*\t0000000000000000 (GLIBC_2.2.5) strcmp\n0000000000000000  w   D  *UND*\t0000000000000000  Base        __gmon_start__\n0000000000000000  w   D  *UND*\t0000000000000000  Base        _ITM_registerTMCloneTable\n0000000000000000  w   DF *UND*\t0000000000000000 (GLIBC_2.2.5) __cxa_finalize\n\n\n", "symbols": "000000000000038c r __abi_tag\n0000000000004010 B __bss_start\n0000000000004010 b completed.0\n0000000000004000 D __data_start\n0000000000004000 W data_start\n00000000000010b0 t deregister_tm_clones\n0000000000001120 t __do_global_dtors_aux\n0000000000003db8 d __do_global_dtors_aux_fini_array_entry\n0000000000004008 D __dso_handle\n0000000000003dc0 d _DYNAMIC\n0000000000004010 D _edata\n0000000000004018 B _end\n00000000000011b0 T _fini\n0000000000001160 t frame_dummy\n0000000000003db0 d __frame_dummy_init_array_entry\n0000000000
```

## plan
```
[fallback-brain] role=planner received 310 chars. (Ollama unreachable — running on rails)
```

## mapper_result
```
{"status": "ok", "suspect_symbols": [], "check_sites": ["           \tret\n    1159:\t0f 1f 80 00 00 00 00 \tnopl   0x0(%rax)\n\n0000000000001160 <frame_dummy>:\n    1160:\tf3 0f 1e fa          \tendbr64\n    1164:\te9 77 ff ff ff       \tjmp    10e0 <register_tm_clones>\n\n0000000000001169 <main>:\n    1169:\tf3 0f 1e fa          \tendbr64\n    116d:\t48 83 ec 08          \tsub    $0x8,%rsp\n    1171:\t83 ff 01             \tcmp    $0x1,%edi\n    1174:\t7e 2a                \tjle    11a0 <main+0x37>\n    1176:\t48 8b 7e 08          \tmov    0x8(%rsi),%rdi\n    117a:\t48 8d 35 83 0e 00 00 \tlea    0xe83(%rip),%rsi        # 2004 <_IO_stdin_used+0x4>\n    1181:\te8 ea fe ff ff       \tcall   1070 <strcmp@plt>\n    1186:\t85 c0                \ttest   %eax,%eax\n    1188:\t75 16                \tjne    11a0 <main+0x37>\n    118a:\t48 8d 3d 9a 0e 00 00 \tlea    0xe9a(%rip),%rdi        # 202b <_IO_stdin_used+0x2b>\n  "], "n_strcmp_refs": 3}
```

## mapper
```
[fallback-brain] role=mapper received 451 chars. (Ollama unreachable — running on rails)
```

## tracer_result
```
{"status": "refused", "reason": "mission is static-only; execution firewall blocked run", "target": "/tmp/swarmre_audit/fieldkit/bench/toy_protector/belt1"}
```

## tracer
```
[fallback-brain] role=tracer received 6515 chars. (Ollama unreachable — running on rails)
```
