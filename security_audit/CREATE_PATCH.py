"""FINAL PATCH: Bypass license check in Раскраска.exe (v3 — TYPE-SAFE)
=================================================================
FIXES vs v2:
- Parses #Blob signatures to determine ACTUAL return type per method
- Methods returning object/string/class references -> ldnull; ret (0x14 0x2A)
  (was ldc.i4.x which pushed int32 -> InvalidProgramException from CLR verifier)
- Methods returning bool/int32 -> ldc.i4.1; ret (0x17 0x2A) or ldc.i4.0; ret
- Dead code filled with NOP (0x00)

USAGE:
    python CREATE_PATCH.py [--input EXE] [--output PATCHED.exe]

    Default input  : Раскраска.exe in the directory ABOVE this script
                     (i.e. <repo-root>/Раскраска.exe)
    Default output : Раскраска_PATCHED.exe next to this script
                     (i.e. <repo-root>/security_audit/Раскраска_PATCHED.exe)

EDUCATIONAL USE ONLY. See SECURITY_AUDIT_REPORT.md for details.
"""
import argparse
import struct
import shutil
import sys

try:
    import pefile
    import dnfile
except ImportError:
    sys.stderr.write("[!] Missing dependencies. Please install:\n")
    sys.stderr.write("    pip install pefile dnfile\n")
    sys.exit(1)

from pathlib import Path
from collections import OrderedDict

# Resolve paths relative to this script, so the tool works regardless of cwd.
_THIS_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _THIS_DIR.parent

_DEFAULT_INPUT = _REPO_ROOT / "Раскраска.exe"
_DEFAULT_OUTPUT = _THIS_DIR / "Раскраска_PATCHED.exe"


def _parse_args():
    p = argparse.ArgumentParser(
        description="IL patcher for Раскраска.exe (educational PoC — bypass license checks via type-safe IL rewrites).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument(
        "-i", "--input",
        type=Path,
        default=_DEFAULT_INPUT,
        help=f"Path to the original Раскраска.exe (default: {_DEFAULT_INPUT})",
    )
    p.add_argument(
        "-o", "--output",
        type=Path,
        default=_DEFAULT_OUTPUT,
        help=f"Path to write the patched binary (default: {_DEFAULT_OUTPUT})",
    )
    return p.parse_args()


_args = _parse_args()
exe_path = str(_args.input)
patched_path = str(_args.output)

if not _args.input.is_file():
    sys.stderr.write(f"[!] Input file not found: {_args.input}\n")
    sys.exit(1)

print("=" * 70)
print("IL BINARY PATCHING — License Bypass (v3 TYPE-SAFE)")
print("=" * 70)

# ── Load metadata ──────────────────────────────────────────────────────────
dn = dnfile.dnPE(exe_path)
pe = pefile.PE(exe_path)

with open(exe_path, "rb") as f:
    binary = bytearray(f.read())
file_size = len(binary)

# ── Critical methods with desired semantics ───────────────────────────────
# TRUE  = push int32 1 (ldc.i4.1) for bool/int32-returning
# FALSE = push int32 0 (ldc.i4.0) for bool-returning "check" methods
# NULL  = push null ref (ldnull) for object/string/class-returning methods
METHODS_RETURN_TRUE = [
    "OnlyCheckVersion",
    "CheckVersionAndAddInfoCreateItIfNoExist",
    "IsUnexpired",
    "CheckShowLicense",
    "CheckDateTimeEnd",                    # returns object → needs ldnull
    "IsIDComputerMemorized_AndGenerateAndWriteItIfNo",
    "CheckIsItOldVersionOfProgramWithGoodOldAbilities",
    "IsEnableEnglishVersion",
    "HasTheUserAbilityOfSelectingAreas",
    "HasTheUserAbilityOfRemovingSmallDetails",
    "get_UpgradeRequired",
]

# Возвращают ПУСТУЮ СТРОКУ (ldstr "" из #US heap token=0x70000065, offset 101)
# вместо ldnull, потому что вызывающий код делает .Equals() на результате
# и NullReferenceException при null. Пустая строка безопасна: "".Equals(x) → false.
METHODS_RETURN_EMPTY_STRING = [
    "CheckIsItSpecialVersionAndGetKeyIfItIs",  # returns string, caller does .Equals()
]

# Возвращают ldnull (reference types — object, string, class)
# Даже если скрипт не определил ref=True, явно указываем
METHODS_RETURN_NULL = [
    "CheckDateTimeEnd",  # returns object (0x15), need ldnull
]

# Методы, которые просто пропускаем — обнуляем на ранний ret (чтобы не падали)
# Это void/bool методы с сложной логикой, которые вызывают проблемные функции
METHODS_RETURN_VOID = [
    "DefineSpecialVersions",  # вызывает CheckIsItSpecialVersionAndGetKeyIfItIs и падает
]

CRITICAL_METHODS = set(METHODS_RETURN_TRUE + METHODS_RETURN_EMPTY_STRING + METHODS_RETURN_NULL + METHODS_RETURN_VOID)

# ── Locate critical methods in #~ heap (manual parsing, robust) ────────────
with open(exe_path, "rb") as f:
    raw = f.read()

def parse_pe_metadata(raw):
    """Parse PE32 to find metadata root, blob heap, strings heap, MethodDef table."""
    e_lfanew = struct.unpack_from("<I", raw, 0x3C)[0]
    opt_hdr_size = struct.unpack_from("<H", raw, e_lfanew + 20)[0]
    magic = struct.unpack_from("<H", raw, e_lfanew + 24)[0]
    dd_start = e_lfanew + 24 + (112 if magic == 0x20B else 96)
    cli_rva   = struct.unpack_from("<I", raw, dd_start + 14*8)[0]
    num_sec   = struct.unpack_from("<H", raw, e_lfanew + 6)[0]
    sec_start = e_lfanew + 24 + opt_hdr_size

    def rva2off(rva):
        for i in range(num_sec):
            s = sec_start + i * 40
            va  = struct.unpack_from("<I", raw, s+12)[0]
            vs  = struct.unpack_from("<I", raw, s+8)[0]
            rp  = struct.unpack_from("<I", raw, s+20)[0]
            if va <= rva < va + vs:
                return rp + (rva - va)
        return None

    cli_off = rva2off(cli_rva)
    meta_rva = struct.unpack_from("<I", raw, cli_off + 8)[0]
    meta_off = rva2off(meta_rva)

    # Metadata root
    ver_len = struct.unpack_from("<I", raw, meta_off + 12)[0]
    p = meta_off + 16 + ver_len
    p = (p + 3) & ~3
    n_streams = struct.unpack_from("<H", raw, p + 2)[0]
    p += 4
    streams = {}
    for _ in range(n_streams):
        s_off  = struct.unpack_from("<I", raw, p)[0]
        s_size = struct.unpack_from("<I", raw, p + 4)[0]
        name_end = raw.index(b'\x00', p + 8)
        name = raw[p+8:name_end].decode()
        streams[name] = (s_off, s_size)
        p = (name_end + 4) & ~3

    blob_abs    = meta_off + streams['#Blob'][0]
    str_abs     = meta_off + streams['#Strings'][0]
    tilde_abs   = meta_off + streams['#~'][0]

    heap_sizes = raw[tilde_abs + 6]
    str_idx_sz  = 4 if (heap_sizes & 0x01) else 2
    guid_idx_sz = 4 if (heap_sizes & 0x02) else 2
    blob_idx_sz = 4 if (heap_sizes & 0x04) else 2

    valid = struct.unpack_from("<Q", raw, tilde_abs + 8)[0]
    rc_pos = tilde_abs + 24
    rc = {}
    pt = []
    for i in range(64):
        if valid & (1 << i):
            c = struct.unpack_from("<I", raw, rc_pos)[0]
            rc[i] = c; pt.append(i); rc_pos += 4

    def coded_sz(bits, tids):
        mx = max(rc.get(t, 0) for t in tids)
        return 2 if mx < (1 << (16 - bits)) else 4

    rss   = coded_sz(2, [0,26,32,1])  # AssemblyRef = 32, not 35
    tdr   = coded_sz(2, [2,1,27])
    fld_i = 4 if rc.get(4,0) > 0xFFFF else 2
    mtd_i = 4 if rc.get(6,0) > 0xFFFF else 2
    prm_i = 4 if rc.get(8,0) > 0xFFFF else 2

    RS = {
        0: 2 + str_idx_sz + guid_idx_sz*3,
        1: rss + str_idx_sz*2,
        2: 4 + str_idx_sz*2 + tdr + fld_i + mtd_i,
        4: 2 + str_idx_sz + blob_idx_sz,
        6: 4 + 2 + 2 + str_idx_sz + blob_idx_sz + prm_i,
    }

    off = 0
    for tid in pt:
        if tid == 6: break
        off += RS[tid] * rc[tid]

    mtd_table = rc_pos + off
    return mtd_table, RS[6], blob_abs, str_abs, blob_idx_sz, str_idx_sz

mtd_tableoff, MTD_ROWSZ, blob_abs, str_abs, blob_idx_sz, str_idx_sz = parse_pe_metadata(raw)

# ── Helpers ────────────────────────────────────────────────────────────────
def read_blob(idx):
    p = blob_abs + idx
    b = raw[p]
    if   b & 0x80 == 0:        length, hs = b, 1
    elif b & 0xC0 == 0x80:     length, hs = ((b & 0x3F) << 8) | raw[p+1], 2
    elif b & 0xE0 == 0xC0:     length, hs = ((b & 0x1F) << 24) | (raw[p+1]<<16) | (raw[p+2]<<8) | raw[p+3], 4
    else: return None
    return raw[p + hs : p + hs + length]

def read_cu(sig, p):
    b = sig[p]
    if   b & 0x80 == 0:        return b, p+1
    elif b & 0xC0 == 0x80:     return ((b & 0x3F) << 8) | sig[p+1], p+2
    elif b & 0xE0 == 0xC0:     v = ((b & 0x1F)<<24)|(sig[p+1]<<16)|(sig[p+2]<<8)|sig[p+3]; return v, p+4
    return 0, p+1

def read_string_raw(idx):
    p = str_abs + idx
    e = raw.index(b'\x00', p)
    return raw[p:e].decode('utf-8', errors='replace')

# Return the first element type name from a method signature at `pos`.
ELEM = {1:"void",2:"bool",3:"char",
        4:"sbyte",5:"byte",6:"int16",7:"uint16",
        8:"int32",9:"uint32",10:"int64",11:"uint64",
        12:"float32",13:"float64",14:"string",
        28:"object"}   # 0x1C = 28 decimal

def skip_type(sig, p):
    """Advance past one type token; return (is_ref_type, new_pos)"""
    if p >= len(sig): return False, p
    b = sig[p]; p += 1
    if b in ELEM:
        is_ref = (ELEM[b] in ("void","string","object"))
        return is_ref, p
    elif b in (0x11, 0x12):           # valuetype / class → CLASS token is a ref
        _, p = read_cu(sig, p)
        return b == 0x12, p           # class* = ref; valuetype* is value (boxed)
    elif b == 0x10:                   # byref
        return skip_type(sig, p)      # inner type determines
    elif b in (0x0F, 0x1D, 0x15):    # ptr / szarray / array
        return skip_type(sig, p)
    elif b in (0x1C, 0x1E):           # var / mvar
        _, p = read_cu(sig, p); return False, p
    elif b == 0x1F:                   # pinned
        return skip_type(sig, p)
    elif b in (0x45, 0x46):           # modreq / modopt
        _, p = read_cu(sig, p)
        return skip_type(sig, p)
    elif b == 0x41:                   # sentinel
        return False, p
    else:
        return False, p               # unknown — treat as value

def get_return_type_name_and_kind(rid):
    """Return (type_name_str, is_ref_type) for a MethodDef RID."""
    off = mtd_tableoff + (rid - 1) * MTD_ROWSZ
    name_idx = struct.unpack_from("<I" if str_idx_sz == 4 else "<H", raw, off + 8)[0]
    sig_idx  = struct.unpack_from("<I" if blob_idx_sz == 4 else "<H", raw, off + 12)[0]
    blob = read_blob(sig_idx)
    if not blob: return "?blob?", False
    p = 1                                # skip calling convention
    if blob[0] & 0x10:                   # generic?
        _, p = read_cu(blob, p)
    _, p = read_cu(blob, p)              # param count
    is_ref, p = skip_type(blob, p)
    # Build human-readable name
    rb = blob[p-1] if p > 0 else 0
    # Re-read for name
    p = 1
    if blob[0] & 0x10: _, p = read_cu(blob, p)
    _, p = read_cu(blob, p)
    return type_name_at(blob, p), is_ref

def type_name_at(sig, p):
    if p >= len(sig): return "?"
    b = sig[p]
    if b in ELEM: return ELEM[b]
    if b == 0x11: return "valuetype"
    if b == 0x12: return "class"
    if b == 0x10: inner = type_name_at(sig, p+1); return f"byref({inner})"
    if b in (0x0F, 0x1D): return type_name_at(sig, p+1) + "*"
    return f"0x{b:02x}"

# ── Find methods ───────────────────────────────────────────────────────────
print(f"\n[*] Searching for {len(CRITICAL_METHODS)} critical methods...")

found = OrderedDict()
if dn.net and dn.net.mdtables and dn.net.mdtables.MethodDef:
    for i, row in enumerate(dn.net.mdtables.MethodDef):
        name = str(row.Name) if row.Name else ""
        if name in CRITICAL_METHODS and name not in found:
            rva = int(row.Rva) if hasattr(row, 'Rva') and row.Rva else 0
            rid = i + 1
            ret_name, is_ref = get_return_type_name_and_kind(rid)
            found[name] = (rid, rva, row, ret_name, is_ref)
            print(f"  [+] {name:55s} RID={rid:4d} RVA=0x{rva:x} ret={ret_name:12s} ref={is_ref}")

print(f"\n[*] Total found: {len(found)} / {len(CRITICAL_METHODS)}")

# ── RVA→file offset ────────────────────────────────────────────────────────
def rva_to_offset(rva):
    for sec in pe.sections:
        if sec.VirtualAddress <= rva < sec.VirtualAddress + sec.Misc_VirtualSize:
            return sec.PointerToRawData + (rva - sec.VirtualAddress)
    return None

# ── Patch each method ──────────────────────────────────────────────────────
patched = []
print("\n[*] Patching methods:")

for name, (rid, rva, row, ret_name, is_ref) in found.items():
    if rva == 0:
        print(f"  [SKIP] {name}: RVA=0"); continue
    file_off = rva_to_offset(rva)
    if file_off is None:
        print(f"  [SKIP] {name}: cannot resolve RVA=0x{rva:x}"); continue
    if file_off + 14 >= file_size:
        print(f"  [SKIP] {name}: out of bounds"); continue

    # Determine what to write based on return type and method category
    if name in METHODS_RETURN_EMPTY_STRING:
        # ldstr "" (0x70 + token 0x70000065) + ret
        # Token 0x70000065 = empty string in #US heap at offset 101
        code_bytes = bytes([0x70, 0x65, 0x00, 0x00, 0x70, 0x2A])  # ldstr ""; ret
        label = "STR"
        min_code_size = len(code_bytes)
    elif name in METHODS_RETURN_VOID:
        # Just ret (void method, skip all logic)
        code_bytes = bytes([0x2A])  # ret
        label = "VOID"
        min_code_size = 1
    elif name in METHODS_RETURN_NULL or is_ref:
        # object/string/class reference → ldnull; ret
        code_bytes = bytes([0x14, 0x2A])  # ldnull; ret
        label = "NULL"
        min_code_size = 2
    else:
        # bool/int32: push 1 for TRUE
        code_bytes = bytes([0x17, 0x2A])  # ldc.i4.1; ret
        label = "TRUE"
        min_code_size = 2

    hb = binary[file_off]
    fmt = hb & 0x03

    if fmt == 0x02:                                  # Tiny
        cs = hb >> 2
        code_s = file_off + 1
        if cs < min_code_size or code_s + cs > file_size:
            print(f"  [SKIP] {name}: Tiny cs={cs} < min={min_code_size}"); continue
        # Write code bytes + NOP pad
        for j in range(cs):
            binary[code_s + j] = code_bytes[j] if j < len(code_bytes) else 0x00
        # Update Tiny header to reflect actual code size (prevents verifier issues)
        binary[file_off] = (len(code_bytes) << 2) | 0x02
        patched.append( (name, label, "Tiny", cs) )
        print(f"  [→{label:5s}] {name:50s} Tiny cs={cs}→{len(code_bytes)} ret={ret_name}")

    elif fmt == 0x03:                                # Fat
        word = struct.unpack_from("<H", binary, file_off)[0]
        hdr_size = (word >> 12) * 4
        orig_code_size = struct.unpack_from("<I", binary, file_off + 4)[0]
        code_s = file_off + hdr_size
        if orig_code_size < min_code_size or code_s + orig_code_size > file_size:
            print(f"  [SKIP] {name}: Fat cs={orig_code_size} < min={min_code_size}"); continue
        # Clear more_sects bit → skip exception handler sections (cleaner)
        binary[file_off] = binary[file_off] & ~0x08
        # Write code bytes + NOP pad
        for j in range(orig_code_size):
            binary[code_s + j] = code_bytes[j] if j < len(code_bytes) else 0x00
        # IMPORTANT: Update code_size in Fat header to match actual code
        # This prevents CLR verifier from analyzing unreachable NOP bytes
        struct.pack_into("<I", binary, file_off + 4, len(code_bytes))
        patched.append( (name, label, "Fat", orig_code_size) )
        print(f"  [→{label:5s}] {name:50s} Fat  cs={orig_code_size}→{len(code_bytes)} ret={ret_name}")

    else:
        print(f"  [SKIP] {name}: unknown fmt=0x{fmt:02x}")

print(f"\n[*] Total patched: {len(patched)}")

# ── Save ──────────────────────────────────────────────────────────────────
with open(patched_path, "wb") as f:
    f.write(binary)

# ── Mirror <original>.exe.config → <patched>.exe.config ─────────────────
# Without this, .NET's WCF client can't find the endpoint configuration
# (BasicHttpBinding_IServices / ServiceReference.IServices) because it looks
# for a config named after the running executable, not the original.
src_cfg = Path(exe_path).with_suffix(".exe.config")
dst_cfg = Path(patched_path).with_suffix(".exe.config")
if src_cfg.is_file():
    shutil.copyfile(src_cfg, dst_cfg)
    print(f"[✓] CONFIG COPIED: {src_cfg.name} -> {dst_cfg.name}")
else:
    print(f"[!] WARNING: source config not found at {src_cfg}")
    print("    WCF client will fail with: 'Не удалось найти элемент конечной точки...'")

print("=" * 70)
print(f"[✓] PATCHED BINARY SAVED: {patched_path}")
print(f"    Size: {len(binary)} bytes (same as original)")
print(f"    Methods patched: {len(patched)}")
print("=" * 70)
for (n, l, f, s) in patched:
    print(f"    {l:5s} {n}  ({f}, cs={s})")
