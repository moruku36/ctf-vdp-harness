"""P2 stdlib-only static artifact inspector adapter and standalone worker subprocess."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import stat
import struct
import sys
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any

# Pinned capability identity and strictly bounded operation surface.
STATIC_INSPECTOR_ADAPTER_ID = "ctf-static-inspector"
STATIC_INSPECTOR_CAPABILITY_NAME = "analysis.query"
STATIC_INSPECTOR_ADAPTER_COMMIT = "ctf-static-inspector-v1.0.0-692af25"

STATIC_INSPECTOR_OPERATIONS: tuple[str, ...] = (
    "inspect_header",
    "extract_strings",
    "hex_slice",
    "hash_and_entropy",
)

# Explicitly excluded operations (never exposed in CapabilityDescriptor.operations).
FORBIDDEN_OR_UNACCEPTED_OPERATIONS: tuple[str, ...] = (
    "raw_disasm",
    "carve_execute",
    "dynamic_trace",
    "remote_fetch",
)

STATIC_INSPECTOR_ARG_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "additionalProperties": False,
    "required": ["artifact_id"],
    "properties": {
        "artifact_id": {
            "type": "string",
            "minLength": 1,
            "maxLength": 128,
            "pattern": "^[A-Za-z0-9._-]+$",
        },
        "encoding": {
            "type": "string",
            "enum": ["ascii", "utf-16le", "both"],
        },
        "min_length": {
            "type": "integer",
            "minimum": 3,
            "maximum": 64,
        },
        "offset": {
            "type": "integer",
            "minimum": 0,
            "maximum": 1073741824,
        },
        "length": {
            "type": "integer",
            "minimum": 1,
            "maximum": 65536,
        },
        "max_matches": {
            "type": "integer",
            "minimum": 1,
            "maximum": 10000,
        },
        "block_size": {
            "type": "integer",
            "minimum": 16,
            "maximum": 65536,
        },
    },
}

_OP_ALLOWED_ARGS: dict[str, frozenset[str]] = {
    "inspect_header": frozenset({"artifact_id"}),
    "extract_strings": frozenset(
        {"artifact_id", "encoding", "min_length", "offset", "max_matches"}
    ),
    "hex_slice": frozenset({"artifact_id", "offset", "length"}),
    "hash_and_entropy": frozenset({"artifact_id", "block_size"}),
}

_FILE_ATTRIBUTE_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_MAX_CHUNK_BYTES = 65_536
_MAX_STRING_TOKEN_LEN = 2_048
_ASCII_RE = re.compile(rb"[\x20-\x7e]+")
_PEM_RE = re.compile(rb"-----BEGIN [A-Z0-9 ]+-----")
_BASE64_BLOCK_RE = re.compile(rb"(?:[A-Za-z0-9+/]{32,}={0,2})")

_ELF_TYPES = {
    0: "ET_NONE",
    1: "ET_REL",
    2: "ET_EXEC",
    3: "ET_DYN",
    4: "ET_CORE",
}

_ELF_MACHINES = {
    3: "EM_386",
    40: "EM_ARM",
    62: "EM_X86_64",
    183: "EM_AARCH64",
    243: "EM_RISCV",
}

_PE_MACHINES = {
    0x014C: "IMAGE_FILE_MACHINE_I386",
    0x01C0: "IMAGE_FILE_MACHINE_ARM",
    0x8664: "IMAGE_FILE_MACHINE_AMD64",
    0xAA64: "IMAGE_FILE_MACHINE_ARM64",
}


class _WorkerError(Exception):
    """Structured non-fatal error inside the static worker subprocess."""


def _sanitize_label(text: str, *, max_len: int = 160) -> str:
    """Replace control chars/newlines so metadata strings stay single-line printable."""
    cleaned = "".join(ch if 0x20 <= ord(ch) <= 0x7E else "?" for ch in text)
    return cleaned[:max_len]


def _open_verified_regular_file(path_str: str) -> tuple[Any, int]:
    """Open artifact read-only, enforcing non-symlink regular file before & after open."""
    if not path_str or "\x00" in path_str:
        raise _WorkerError("Artifact path is invalid.")
    candidate = Path(path_str)
    try:
        lstat_res = os.lstat(candidate)
    except OSError as exc:
        raise _WorkerError(f"Artifact path is unreadable: {exc}") from exc

    if stat.S_ISLNK(lstat_res.st_mode) or (
        getattr(lstat_res, "st_file_attributes", 0) & _FILE_ATTRIBUTE_REPARSE_POINT
    ):
        raise _WorkerError("Symlink or reparse point artifact paths are forbidden.")
    if not stat.S_ISREG(lstat_res.st_mode):
        raise _WorkerError("Artifact path is not a regular file.")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(candidate, flags)
    except OSError as exc:
        raise _WorkerError(f"Failed to open artifact read-only: {exc}") from exc

    try:
        fstat_res = os.fstat(fd)
        if not stat.S_ISREG(fstat_res.st_mode) or (
            fstat_res.st_dev,
            fstat_res.st_ino,
        ) != (lstat_res.st_dev, lstat_res.st_ino):
            raise _WorkerError("Artifact changed or resolved to non-regular file after open.")
        stream = os.fdopen(fd, "rb", closefd=True)
        fd = -1
        return stream, int(fstat_res.st_size)
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass


def _parse_elf_header(stream: Any, size_bytes: int) -> dict[str, Any]:
    """Inspect ELF32/ELF64 headers and bounded section names."""
    if size_bytes < 16:
        raise _WorkerError("Corrupt ELF: file smaller than 16-byte e_ident.")
    stream.seek(0)
    ident = stream.read(16)
    ei_class = ident[4]
    ei_data = ident[5]
    if ei_class not in (1, 2):
        raise _WorkerError(f"Corrupt ELF: unsupported EI_CLASS={ei_class}.")
    if ei_data not in (1, 2):
        raise _WorkerError(f"Corrupt ELF: unsupported EI_DATA={ei_data}.")

    endian = "<" if ei_data == 1 else ">"
    header_size = 52 if ei_class == 1 else 64
    if size_bytes < header_size:
        raise _WorkerError(
            f"Corrupt ELF{32 if ei_class == 1 else 64}: file smaller than {header_size} bytes."
        )

    stream.seek(16)
    rest = stream.read(header_size - 16)
    if len(rest) != header_size - 16:
        raise _WorkerError("Corrupt ELF: truncated header.")

    if ei_class == 1:
        (
            e_type,
            e_machine,
            e_version,
            e_entry,
            e_phoff,
            e_shoff,
            e_flags,
            e_ehsize,
            e_phentsize,
            e_phnum,
            e_shentsize,
            e_shnum,
            e_shstrndx,
        ) = struct.unpack(f"{endian}HHIIIIIHHHHHH", rest)
    else:
        (
            e_type,
            e_machine,
            e_version,
            e_entry,
            e_phoff,
            e_shoff,
            e_flags,
            e_ehsize,
            e_phentsize,
            e_phnum,
            e_shentsize,
            e_shnum,
            e_shstrndx,
        ) = struct.unpack(f"{endian}HHIQQQIHHHHHH", rest)

    if e_ehsize not in (0, header_size):
        raise _WorkerError(f"Corrupt ELF: unexpected e_ehsize={e_ehsize}.")
    if e_phoff > size_bytes or e_shoff > size_bytes:
        raise _WorkerError("Corrupt ELF: program or section table offset exceeds file size.")

    section_names: list[str] = []
    min_sh_size = 40 if ei_class == 1 else 64
    if (
        e_shoff > 0
        and e_shnum > 0
        and e_shnum <= 128
        and e_shentsize >= min_sh_size
        and e_shoff + e_shnum * e_shentsize <= size_bytes
    ):
        strtab_bytes = b""
        if e_shstrndx < e_shnum:
            str_sh_off = e_shoff + e_shstrndx * e_shentsize
            stream.seek(str_sh_off)
            str_sh = stream.read(min_sh_size)
            if len(str_sh) == min_sh_size:
                if ei_class == 1:
                    sh_offset, sh_size = struct.unpack_from(f"{endian}II", str_sh, 16)
                else:
                    sh_offset, sh_size = struct.unpack_from(f"{endian}QQ", str_sh, 24)
                if sh_offset + sh_size <= size_bytes and sh_size <= 65_536:
                    stream.seek(sh_offset)
                    strtab_bytes = stream.read(sh_size)

        for idx in range(min(e_shnum, 64)):
            stream.seek(e_shoff + idx * e_shentsize)
            sh = stream.read(min_sh_size)
            if len(sh) < 4:
                break
            sh_name = struct.unpack_from(f"{endian}I", sh, 0)[0]
            if strtab_bytes and sh_name < len(strtab_bytes):
                end = strtab_bytes.find(b"\x00", sh_name, min(len(strtab_bytes), sh_name + 64))
                raw_name = strtab_bytes[sh_name : end if end >= 0 else sh_name + 64]
                section_names.append(_sanitize_label(raw_name.decode("ascii", errors="replace"), max_len=64))
            else:
                section_names.append(f"section_{idx}")

    return {
        "format": f"elf{32 if ei_class == 1 else 64}",
        "bits": 32 if ei_class == 1 else 64,
        "endianness": "little" if ei_data == 1 else "big",
        "e_type": _ELF_TYPES.get(e_type, f"0x{e_type:x}"),
        "e_machine": _ELF_MACHINES.get(e_machine, f"0x{e_machine:x}"),
        "e_version": e_version,
        "entry_point": f"0x{e_entry:x}",
        "e_flags": f"0x{e_flags:x}",
        "program_header_count": e_phnum,
        "section_header_count": e_shnum,
        "section_names_preview": section_names,
    }


def _parse_pe_header(stream: Any, size_bytes: int) -> dict[str, Any]:
    """Inspect PE/COFF headers and bounded section metadata."""
    if size_bytes < 64:
        raise _WorkerError("Corrupt PE: file smaller than 64-byte DOS header.")
    stream.seek(0x3C)
    e_lfanew = struct.unpack("<I", stream.read(4))[0]
    if e_lfanew + 24 > size_bytes:
        raise _WorkerError("Corrupt PE: e_lfanew points past EOF.")

    stream.seek(e_lfanew)
    pe_sig = stream.read(4)
    if pe_sig != b"PE\x00\x00":
        raise _WorkerError("Corrupt PE: missing PE signature at e_lfanew.")

    coff = stream.read(20)
    if len(coff) != 20:
        raise _WorkerError("Corrupt PE: truncated COFF header.")
    machine, num_sections, timestamp, _, _, opt_size, characteristics = struct.unpack(
        "<HHIIIHH", coff
    )

    opt_magic_hex = None
    entry_rva = None
    if opt_size >= 20 and e_lfanew + 24 + opt_size <= size_bytes:
        opt = stream.read(min(opt_size, 256))
        opt_magic = struct.unpack_from("<H", opt, 0)[0]
        opt_magic_hex = f"0x{opt_magic:x}"
        if opt_magic in (0x10B, 0x20B) and len(opt) >= 20:
            entry_rva = f"0x{struct.unpack_from('<I', opt, 16)[0]:x}"

    sections: list[dict[str, Any]] = []
    sec_table_off = e_lfanew + 24 + opt_size
    if num_sections <= 96 and sec_table_off + num_sections * 40 <= size_bytes:
        stream.seek(sec_table_off)
        for _ in range(min(num_sections, 32)):
            sec = stream.read(40)
            if len(sec) != 40:
                break
            raw_name = sec[:8].split(b"\x00", 1)[0]
            vsize, vaddr, raw_size, raw_ptr = struct.unpack_from("<IIII", sec, 8)
            sections.append(
                {
                    "name": _sanitize_label(raw_name.decode("ascii", errors="replace"), max_len=16),
                    "virtual_size": vsize,
                    "virtual_address": f"0x{vaddr:x}",
                    "raw_size": raw_size,
                    "raw_offset": f"0x{raw_ptr:x}",
                }
            )

    return {
        "format": "pe_coff",
        "machine": _PE_MACHINES.get(machine, f"0x{machine:x}"),
        "section_count": num_sections,
        "timestamp": timestamp,
        "characteristics": f"0x{characteristics:04x}",
        "optional_header_magic": opt_magic_hex,
        "entry_point_rva": entry_rva,
        "sections_preview": sections,
    }


def _parse_zip_header(
    stream: Any,
    size_bytes: int,
    *,
    max_archive_entries: int,
    max_expansion_ratio: float,
    max_decode_bytes: int,
) -> dict[str, Any]:
    """Inspect ZIP central directory metadata with pre-decompression safety caps."""
    try:
        zf = zipfile.ZipFile(stream, "r")
    except (zipfile.BadZipFile, OSError, ValueError) as exc:
        raise _WorkerError(f"Corrupt ZIP archive: {exc}") from exc

    with zf:
        infos = zf.infolist()
        if len(infos) > max_archive_entries:
            raise _WorkerError(
                f"ZIP entry count {len(infos)} exceeds max_archive_entries={max_archive_entries}."
            )

        total_compressed = 0
        total_uncompressed = 0
        encrypted_count = 0
        entries_preview: list[dict[str, Any]] = []

        for idx, info in enumerate(infos):
            if info.file_size < 0 or info.compress_size < 0:
                raise _WorkerError("Corrupt ZIP entry: negative size metadata.")
            total_compressed += int(info.compress_size)
            total_uncompressed += int(info.file_size)

            # Enforce single-entry expansion ratio cap before allowing metadata acceptance.
            if info.file_size > 1024:
                entry_ratio = info.file_size / max(int(info.compress_size), 1)
                if entry_ratio > max_expansion_ratio:
                    raise _WorkerError(
                        f"ZIP entry ratio {entry_ratio:.2f} exceeds max_expansion_ratio={max_expansion_ratio}."
                    )

            encrypted = bool(info.flag_bits & 0x1)
            if encrypted:
                encrypted_count += 1
            if idx < 64:
                entries_preview.append(
                    {
                        "name": _sanitize_label(info.filename, max_len=120),
                        "file_size": int(info.file_size),
                        "compress_size": int(info.compress_size),
                        "compress_type": int(info.compress_type),
                        "encrypted": encrypted,
                        "is_dir": info.is_dir(),
                    }
                )

        if total_uncompressed > max_decode_bytes:
            raise _WorkerError(
                f"ZIP total declared uncompressed size {total_uncompressed} exceeds "
                f"max_decode_bytes={max_decode_bytes}."
            )

        agg_basis = max(total_compressed, 1)
        agg_ratio = (total_uncompressed / agg_basis) if total_uncompressed > 0 else 0.0
        if total_uncompressed > 1024 and agg_ratio > max_expansion_ratio:
            raise _WorkerError(
                f"ZIP expansion ratio {agg_ratio:.2f} exceeds max_expansion_ratio={max_expansion_ratio}."
            )

        return {
            "format": "zip",
            "archive_bytes": size_bytes,
            "entry_count": len(infos),
            "encrypted_entries": encrypted_count,
            "has_encrypted_entries": encrypted_count > 0,
            "total_compressed_bytes": total_compressed,
            "total_uncompressed_bytes": total_uncompressed,
            "expansion_ratio": round(agg_ratio, 4),
            "entries_preview": entries_preview,
        }


def _classify_non_container_header(
    stream: Any,
    size_bytes: int,
    head: bytes,
    *,
    max_decode_bytes: int,
) -> dict[str, Any]:
    """Classify non-ELF/PE/ZIP files as empty, UTF-8 text, or opaque binary."""
    if size_bytes == 0:
        return {"format": "empty"}

    sample_cap = min(size_bytes, max_decode_bytes)
    stream.seek(0)
    sample = stream.read(sample_cap)

    bom_utf8 = sample.startswith(b"\xef\xbb\xbf")
    if b"\x00" not in sample:
        # Trim at most 3 trailing incomplete UTF-8 continuation bytes if sample was capped at EOF boundary.
        decode_buf = sample
        if size_bytes > sample_cap:
            for trim in range(4):
                try:
                    text = decode_buf[: len(decode_buf) - trim].decode("utf-8")
                    break
                except UnicodeDecodeError:
                    continue
            else:
                text = None
        else:
            try:
                text = decode_buf.decode("utf-8")
            except UnicodeDecodeError:
                text = None

        if text is not None:
            printable = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
            ratio = (printable / len(text)) if text else 1.0
            if ratio >= 0.90:
                return {
                    "format": "utf8_text",
                    "utf8_valid": True,
                    "utf8_bom": bom_utf8,
                    "sampled_bytes": len(sample),
                    "sampled_chars": len(text),
                    "sampled_lines": text.count("\n") + (1 if text and not text.endswith("\n") else 0),
                    "printable_ratio": round(ratio, 4),
                }

    return {
        "format": "opaque_binary",
        "magic_ascii": _sanitize_label(head[:8].decode("ascii", errors="replace"), max_len=16),
    }


def _op_inspect_header(
    stream: Any,
    size_bytes: int,
    *,
    max_archive_entries: int,
    max_expansion_ratio: float,
    max_decode_bytes: int,
) -> dict[str, Any]:
    """Dispatch magic-byte inspection for ELF32/64, PE/COFF, ZIP, or UTF-8 text."""
    stream.seek(0)
    head = stream.read(64)
    if head.startswith(b"\x7fELF"):
        details = _parse_elf_header(stream, size_bytes)
    elif head.startswith(b"MZ"):
        details = _parse_pe_header(stream, size_bytes)
    elif head[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        details = _parse_zip_header(
            stream,
            size_bytes,
            max_archive_entries=max_archive_entries,
            max_expansion_ratio=max_expansion_ratio,
            max_decode_bytes=max_decode_bytes,
        )
    else:
        details = _classify_non_container_header(
            stream,
            size_bytes,
            head,
            max_decode_bytes=max_decode_bytes,
        )

    return {
        "operation": "inspect_header",
        "file_size_bytes": size_bytes,
        "magic_hex": head[:16].hex(),
        **details,
    }


def _is_printable_utf16le_unit(code_unit: int) -> bool:
    """Allow printable ASCII plus common whitespace cleanly representable in UTF-8."""
    return 0x20 <= code_unit <= 0x7E


def _extract_utf16le_from_buffer(
    buf: bytes,
    *,
    base_offset: int,
    min_length: int,
    max_matches: int,
    already_emitted: int,
) -> tuple[int, list[str]]:
    """Extract UTF-16LE printable ASCII strings at both even and odd alignments."""
    emitted = already_emitted
    lines: list[str] = []
    # Scan byte-by-byte at 2-byte aligned positions within current chunk (no overlap duplication).
    i = 0
    limit = len(buf) - 1
    while i < limit and emitted < max_matches:
        unit = buf[i] | (buf[i + 1] << 8)
        if _is_printable_utf16le_unit(unit):
            start = i
            chars: list[str] = [chr(unit)]
            j = i + 2
            while j < limit and len(chars) < _MAX_STRING_TOKEN_LEN:
                nxt = buf[j] | (buf[j + 1] << 8)
                if not _is_printable_utf16le_unit(nxt):
                    break
                chars.append(chr(nxt))
                j += 2
            if len(chars) >= min_length:
                lines.append(
                    f"0x{base_offset + start:08x} [utf-16le] {''.join(chars)}\n"
                )
                emitted += 1
            i = j
        else:
            i += 1
    return emitted, lines


def _op_extract_strings(
    stream: Any,
    size_bytes: int,
    *,
    offset: int,
    encoding: str,
    min_length: int,
    max_matches: int,
) -> int:
    """Stream ASCII and/or UTF-16LE printable strings directly to stdout."""
    if size_bytes == 0:
        sys.stdout.write(
            f"# strings offset=0x{offset:08x} encoding={encoding} min_length={min_length} "
            f"max_matches={max_matches}\n# total_matches=0\n"
        )
        sys.stdout.flush()
        return 0
    if offset >= size_bytes:
        raise _WorkerError(
            f"Requested offset={offset} is >= file_size={size_bytes}."
        )

    sys.stdout.write(
        f"# strings offset=0x{offset:08x} encoding={encoding} min_length={min_length} "
        f"max_matches={max_matches}\n"
    )
    sys.stdout.flush()

    emitted = 0
    stream.seek(offset)
    pos = offset
    ascii_carry = b""
    ascii_carry_offset = pos

    utf16_carry = b""
    utf16_carry_offset = pos

    def _emit_line(line: str) -> None:
        sys.stdout.write(line)

    while emitted < max_matches:
        chunk = stream.read(_MAX_CHUNK_BYTES)
        if not chunk:
            break

        if encoding in ("ascii", "both") and emitted < max_matches:
            work = ascii_carry + chunk
            work_base = ascii_carry_offset if ascii_carry else pos
            # Determine if work ends inside a printable ASCII run so we carry it across chunk boundary.
            trailing_printable = 0
            if len(chunk) == _MAX_CHUNK_BYTES:
                idx = len(work) - 1
                while idx >= 0 and 0x20 <= work[idx] <= 0x7E and trailing_printable < _MAX_STRING_TOKEN_LEN:
                    trailing_printable += 1
                    idx -= 1
            split_at = len(work) - trailing_printable
            process_part = work[:split_at]
            ascii_carry = work[split_at:]
            ascii_carry_offset = work_base + split_at

            for match in _ASCII_RE.finditer(process_part):
                raw_tok = match.group(0)
                if len(raw_tok) >= min_length:
                    for sub_off in range(0, len(raw_tok), _MAX_STRING_TOKEN_LEN):
                        if emitted >= max_matches:
                            break
                        piece = raw_tok[sub_off : sub_off + _MAX_STRING_TOKEN_LEN]
                        if len(piece) >= min_length:
                            abs_off = work_base + match.start() + sub_off
                            _emit_line(
                                f"0x{abs_off:08x} [ascii] {piece.decode('ascii')}\n"
                            )
                            emitted += 1

        if encoding in ("utf-16le", "both") and emitted < max_matches:
            work16 = utf16_carry + chunk
            work16_base = utf16_carry_offset if utf16_carry else pos
            # Keep trailing printable UTF-16LE tail (including lone half-pair) across chunks.
            if len(chunk) == _MAX_CHUNK_BYTES and len(work16) >= 2:
                back = len(work16)
                if 0x20 <= work16[back - 1] <= 0x7E:
                    back -= 1
                kept = 0
                while (
                    back >= 2
                    and kept < _MAX_STRING_TOKEN_LEN * 2
                    and 0x20 <= work16[back - 2] <= 0x7E
                    and work16[back - 1] == 0
                ):
                    back -= 2
                    kept += 2
                process16 = work16[:back]
                carry16 = work16[back:]
                utf16_carry_offset = work16_base + back
            else:
                process16 = work16
                carry16 = b""
                utf16_carry_offset = work16_base + len(work16)

            utf16_carry = carry16
            emitted, lines16 = _extract_utf16le_from_buffer(
                process16,
                base_offset=work16_base,
                min_length=min_length,
                max_matches=max_matches,
                already_emitted=emitted,
            )
            for line in lines16:
                _emit_line(line)

        sys.stdout.flush()
        pos += len(chunk)

    # Flush trailing buffers at EOF.
    if encoding in ("ascii", "both") and ascii_carry and emitted < max_matches:
        for match in _ASCII_RE.finditer(ascii_carry):
            raw_tok = match.group(0)
            if len(raw_tok) >= min_length:
                for sub_off in range(0, len(raw_tok), _MAX_STRING_TOKEN_LEN):
                    if emitted >= max_matches:
                        break
                    piece = raw_tok[sub_off : sub_off + _MAX_STRING_TOKEN_LEN]
                    if len(piece) >= min_length:
                        abs_off = ascii_carry_offset + match.start() + sub_off
                        _emit_line(f"0x{abs_off:08x} [ascii] {piece.decode('ascii')}\n")
                        emitted += 1

    if encoding in ("utf-16le", "both") and len(utf16_carry) >= 2 and emitted < max_matches:
        emitted, lines16 = _extract_utf16le_from_buffer(
            utf16_carry[: len(utf16_carry) - (len(utf16_carry) % 2)],
            base_offset=utf16_carry_offset,
            min_length=min_length,
            max_matches=max_matches,
            already_emitted=emitted,
        )
        for line in lines16:
            _emit_line(line)

    sys.stdout.write(f"# total_matches={emitted}\n")
    sys.stdout.flush()
    return emitted


def _op_hex_slice(
    stream: Any,
    size_bytes: int,
    *,
    offset: int,
    length: int,
) -> int:
    """Emit canonical 16-byte hexdump + printable ASCII gutter slice."""
    if size_bytes == 0 and offset == 0:
        sys.stdout.write(
            "# hex_slice offset=0x00000000 requested_length="
            f"{length} actual_bytes=0 file_size=0\n"
        )
        sys.stdout.flush()
        return 0
    if offset >= size_bytes:
        raise _WorkerError(
            f"Requested offset={offset} is >= file_size={size_bytes}."
        )

    stream.seek(offset)
    data = stream.read(min(length, size_bytes - offset))
    sys.stdout.write(
        f"# hex_slice offset=0x{offset:08x} requested_length={length} "
        f"actual_bytes={len(data)} file_size={size_bytes}\n"
    )

    for row_off in range(0, len(data), 16):
        row = data[row_off : row_off + 16]
        left = " ".join(f"{b:02x}" for b in row[:8])
        right = " ".join(f"{b:02x}" for b in row[8:])
        hex_part = f"{left:<23}  {right:<23}"
        ascii_part = "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in row)
        sys.stdout.write(f"0x{offset + row_off:08x}: {hex_part}  |{ascii_part}|\n")

    sys.stdout.flush()
    return len(data)


def _shannon_entropy(data: bytes) -> float:
    """Compute Shannon entropy in bits/byte over [0.0, 8.0]."""
    total = len(data)
    if total == 0:
        return 0.0
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return round(entropy, 6)


def _op_hash_and_entropy(
    stream: Any,
    size_bytes: int,
    *,
    block_size: int,
) -> dict[str, Any]:
    """Compute SHA-256, identification SHA-1, overall & per-block Shannon entropy."""
    h256 = hashlib.sha256()
    h1 = hashlib.sha1()
    overall_counts: Counter[int] = Counter()
    blocks_preview: list[dict[str, Any]] = []
    pem_marker_count = 0
    base64_blob_count = 0

    stream.seek(0)
    offset = 0
    block_buf = bytearray()
    total_blocks = 0
    min_ent: float | None = None
    max_ent: float | None = None
    sum_ent = 0.0
    prev_tail = b""

    while chunk := stream.read(_MAX_CHUNK_BYTES):
        h256.update(chunk)
        h1.update(chunk)
        overall_counts.update(chunk)

        scan_window = prev_tail + chunk
        pem_marker_count += len(_PEM_RE.findall(scan_window))
        base64_blob_count += len(_BASE64_BLOCK_RE.findall(scan_window))
        prev_tail = chunk[-64:]

        block_buf.extend(chunk)
        while len(block_buf) >= block_size:
            block = bytes(block_buf[:block_size])
            del block_buf[:block_size]
            ent = _shannon_entropy(block)
            sum_ent += ent
            min_ent = ent if min_ent is None else min(min_ent, ent)
            max_ent = ent if max_ent is None else max(max_ent, ent)
            if len(blocks_preview) < 256:
                blocks_preview.append(
                    {"offset": f"0x{offset:08x}", "size": len(block), "entropy": ent}
                )
            total_blocks += 1
            offset += len(block)

    if block_buf:
        block = bytes(block_buf)
        ent = _shannon_entropy(block)
        sum_ent += ent
        min_ent = ent if min_ent is None else min(min_ent, ent)
        max_ent = ent if max_ent is None else max(max_ent, ent)
        if len(blocks_preview) < 256:
            blocks_preview.append(
                {"offset": f"0x{offset:08x}", "size": len(block), "entropy": ent}
            )
        total_blocks += 1

    overall_entropy = 0.0
    if size_bytes > 0:
        for count in overall_counts.values():
            p = count / size_bytes
            overall_entropy -= p * math.log2(p)
        overall_entropy = round(overall_entropy, 6)

    return {
        "operation": "hash_and_entropy",
        "file_size_bytes": size_bytes,
        "sha256": h256.hexdigest(),
        "sha1_identification_only": h1.hexdigest(),
        "overall_shannon_entropy": overall_entropy,
        "high_entropy_suspected": overall_entropy >= 7.2,
        "block_size": block_size,
        "total_blocks": total_blocks,
        "blocks_truncated": total_blocks > len(blocks_preview),
        "min_block_entropy": min_ent if min_ent is not None else 0.0,
        "max_block_entropy": max_ent if max_ent is not None else 0.0,
        "mean_block_entropy": round(sum_ent / total_blocks, 6) if total_blocks else 0.0,
        "static_encoding_indicators": {
            "pem_header_count": pem_marker_count,
            "base64_segment_count": base64_blob_count,
        },
        "blocks_preview": blocks_preview,
    }


def _configure_stdio_utf8() -> None:
    """Keep stdout/stderr strictly UTF-8 with deterministic LF newlines."""
    for handle in (sys.stdout, sys.stderr):
        reconfigure = getattr(handle, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(encoding="utf-8", errors="replace", newline="\n")
            except OSError:
                pass


def _worker_main(argv: list[str] | None = None) -> int:
    """Standalone stdlib-only worker executed under SubprocessRunner isolation."""
    _configure_stdio_utf8()
    parser = argparse.ArgumentParser(description="Bounded offline static artifact inspector")
    parser.add_argument("--operation", required=True)
    parser.add_argument("--artifact", required=True)
    parser.add_argument("--offset", type=int, default=0)
    parser.add_argument("--length", type=int, default=256)
    parser.add_argument("--encoding", default="both")
    parser.add_argument("--min-length", type=int, default=4)
    parser.add_argument("--max-matches", type=int, default=2000)
    parser.add_argument("--block-size", type=int, default=256)
    parser.add_argument("--max-decode-bytes", type=int, default=65_536)
    parser.add_argument("--max-archive-entries", type=int, default=256)
    parser.add_argument("--max-expansion-ratio", type=float, default=20.0)
    args = parser.parse_args(argv)

    op = str(args.operation).strip()
    if op in FORBIDDEN_OR_UNACCEPTED_OPERATIONS or op not in STATIC_INSPECTOR_OPERATIONS:
        sys.stderr.write(f"Denied unaccepted or forbidden static operation: {op!r}.\n")
        return 2

    if args.offset < 0:
        sys.stderr.write("Invalid negative offset.\n")
        return 2
    if args.max_decode_bytes < 1:
        sys.stderr.write("Invalid max-decode-bytes bound.\n")
        return 2
    if args.max_archive_entries < 1:
        sys.stderr.write("Invalid max-archive-entries bound.\n")
        return 2
    if args.max_expansion_ratio <= 0:
        sys.stderr.write("Invalid max-expansion-ratio bound.\n")
        return 2

    try:
        stream, size_bytes = _open_verified_regular_file(args.artifact)
        with stream:
            if op == "inspect_header":
                payload = _op_inspect_header(
                    stream,
                    size_bytes,
                    max_archive_entries=args.max_archive_entries,
                    max_expansion_ratio=args.max_expansion_ratio,
                    max_decode_bytes=args.max_decode_bytes,
                )
                sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False))
                sys.stdout.write("\n")
                sys.stdout.flush()
            elif op == "extract_strings":
                if args.encoding not in ("ascii", "utf-16le", "both"):
                    raise _WorkerError(f"Unsupported string encoding: {args.encoding!r}.")
                if not (3 <= args.min_length <= 64):
                    raise _WorkerError("min_length must be between 3 and 64.")
                if not (1 <= args.max_matches <= 10_000):
                    raise _WorkerError("max_matches must be between 1 and 10000.")
                _op_extract_strings(
                    stream,
                    size_bytes,
                    offset=args.offset,
                    encoding=args.encoding,
                    min_length=args.min_length,
                    max_matches=args.max_matches,
                )
            elif op == "hex_slice":
                max_slice = min(65_536, args.max_decode_bytes)
                if not (1 <= args.length <= max_slice):
                    raise _WorkerError(
                        f"hex_slice length={args.length} must be in [1, {max_slice}]."
                    )
                _op_hex_slice(
                    stream,
                    size_bytes,
                    offset=args.offset,
                    length=args.length,
                )
            elif op == "hash_and_entropy":
                if not (16 <= args.block_size <= 65_536):
                    raise _WorkerError("block_size must be between 16 and 65536.")
                payload = _op_hash_and_entropy(
                    stream,
                    size_bytes,
                    block_size=args.block_size,
                )
                sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False))
                sys.stdout.write("\n")
                sys.stdout.flush()
    except _WorkerError as exc:
        sys.stderr.write(f"static_inspector_error: {_sanitize_label(str(exc), max_len=240)}\n")
        return 3
    except OSError as exc:
        sys.stderr.write(f"static_inspector_io_error: {_sanitize_label(str(exc), max_len=240)}\n")
        return 4

    return 0


if __name__ != "__main__":
    from collections.abc import Mapping

    from ctf_mcp.adapters.base import BaseAdapter, build_signed_descriptor
    from ctf_mcp.adapters.runner import SubprocessResult, SubprocessRunner
    from ctf_mcp.contracts import (
        ActionRecord,
        CapabilityDeniedError,
        CapabilityDescriptor,
        CapabilityLimits,
        ContractViolationError,
        EvidenceVaultPort,
        ExecutionClass,
        RunMode,
    )

    _SCRIPT_PATH = Path(__file__).resolve()

    def get_dependency_lock_sha256() -> str:
        """Compute SHA-256 of pinned pyproject.toml lock manifest (stdlib manifest fallback)."""
        pyproject = Path(__file__).resolve().parents[3] / "pyproject.toml"
        if pyproject.is_file():
            return hashlib.sha256(pyproject.read_bytes()).hexdigest()
        fallback = json.dumps(
            {
                "adapter": STATIC_INSPECTOR_ADAPTER_ID,
                "python_deps": [],
                "stdlib_only": True,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(fallback).hexdigest()

    STATIC_INSPECTOR_DEPENDENCY_LOCK_SHA256 = get_dependency_lock_sha256()

    def create_static_inspector_descriptor(
        *,
        name: str = STATIC_INSPECTOR_CAPABILITY_NAME,
        enabled: bool = True,
        timeout_seconds: int = 60,
        max_output_bytes: int = 65_536,
        max_decode_bytes: int = 65_536,
        max_archive_depth: int = 3,
        max_archive_entries: int = 256,
        max_expansion_ratio: float = 20.0,
        required_scope: Mapping[str, Any] | None = None,
        profile_modes: tuple[RunMode, ...] = (RunMode.OFFLINE_CTF,),
    ) -> CapabilityDescriptor:
        """Create and self-sign the P2 StaticArtifactInspectorAdapter descriptor."""
        scope_req = (
            dict(required_scope)
            if required_scope is not None
            else {"modes": [mode.value for mode in profile_modes]}
        )
        return build_signed_descriptor(
            name=name,
            adapter_id=STATIC_INSPECTOR_ADAPTER_ID,
            adapter_commit=STATIC_INSPECTOR_ADAPTER_COMMIT,
            dependency_lock_sha256=STATIC_INSPECTOR_DEPENDENCY_LOCK_SHA256,
            operations=STATIC_INSPECTOR_OPERATIONS,
            arg_schema=dict(STATIC_INSPECTOR_ARG_SCHEMA),
            execution_classes=(ExecutionClass.STATIC,),
            required_scope=scope_req,
            limits=CapabilityLimits(
                timeout_seconds=timeout_seconds,
                max_output_bytes=max_output_bytes,
                max_decode_bytes=max_decode_bytes,
                max_archive_depth=max_archive_depth,
                max_archive_entries=max_archive_entries,
                max_expansion_ratio=max_expansion_ratio,
            ),
            enabled=enabled,
            profile_modes=profile_modes,
        )

    class StaticArtifactInspectorAdapter(BaseAdapter):
        """MVP P2 stdlib-only static artifact inspector (analysis.query, STATIC only)."""

        def __init__(
            self,
            *,
            name: str = STATIC_INSPECTOR_CAPABILITY_NAME,
            enabled: bool = True,
            timeout_seconds: int = 60,
            max_output_bytes: int = 65_536,
            max_decode_bytes: int = 65_536,
            max_archive_depth: int = 3,
            max_archive_entries: int = 256,
            max_expansion_ratio: float = 20.0,
            required_scope: Mapping[str, Any] | None = None,
            profile_modes: tuple[RunMode, ...] = (RunMode.OFFLINE_CTF,),
            runner: SubprocessRunner | None = None,
            evidence_vault: EvidenceVaultPort | None = None,
            descriptor_override: CapabilityDescriptor | None = None,
            require_running_state: bool = False,
        ) -> None:
            desc = descriptor_override or create_static_inspector_descriptor(
                name=name,
                enabled=enabled,
                timeout_seconds=timeout_seconds,
                max_output_bytes=max_output_bytes,
                max_decode_bytes=max_decode_bytes,
                max_archive_depth=max_archive_depth,
                max_archive_entries=max_archive_entries,
                max_expansion_ratio=max_expansion_ratio,
                required_scope=required_scope,
                profile_modes=profile_modes,
            )
            if set(desc.execution_classes) != {ExecutionClass.STATIC}:
                raise ContractViolationError(
                    "StaticArtifactInspectorAdapter only permits ExecutionClass.STATIC."
                )
            for forbidden in FORBIDDEN_OR_UNACCEPTED_OPERATIONS:
                if forbidden in desc.operations:
                    raise ContractViolationError(
                        f"Forbidden static operation {forbidden!r} cannot be exposed in descriptor."
                    )
            super().__init__(
                desc,
                runner=runner,
                evidence_vault=evidence_vault,
                require_running_state=require_running_state,
            )

        def _build_invocation(
            self,
            action: ActionRecord,
            *,
            artifact_paths: dict[str, Path],
        ) -> tuple[list[str], dict[str, str] | None, Path | None]:
            op = action.operation
            if op in FORBIDDEN_OR_UNACCEPTED_OPERATIONS or op not in STATIC_INSPECTOR_OPERATIONS:
                raise CapabilityDeniedError(
                    f"Operation {op!r} is forbidden or unaccepted for {self._descriptor.adapter_id!r}.",
                    details={"operation": op},
                )

            args = dict(action.sanitized_args)
            allowed_keys = _OP_ALLOWED_ARGS[op]
            extra_keys = sorted(set(args.keys()) - allowed_keys)
            if extra_keys:
                raise ContractViolationError(
                    f"Operation {op!r} received unsupported arguments: {', '.join(extra_keys)}.",
                    details={"operation": op, "unexpected_keys": extra_keys},
                )

            artifact_id = args.get("artifact_id")
            if not isinstance(artifact_id, str) or artifact_id not in artifact_paths:
                raise ContractViolationError(
                    f"Operation {op!r} requires a resolved regular artifact_id.",
                    details={"operation": op, "artifact_id": artifact_id},
                )

            limits = self._descriptor.limits
            argv: list[str] = [
                sys.executable,
                str(_SCRIPT_PATH),
                "--operation",
                op,
                "--artifact",
                str(artifact_paths[artifact_id]),
                "--max-decode-bytes",
                str(limits.max_decode_bytes),
                "--max-archive-entries",
                str(limits.max_archive_entries),
                "--max-expansion-ratio",
                str(limits.max_expansion_ratio),
            ]

            if op == "extract_strings":
                if "offset" in args:
                    argv.extend(["--offset", str(int(args["offset"]))])
                if "encoding" in args:
                    argv.extend(["--encoding", str(args["encoding"])])
                if "min_length" in args:
                    argv.extend(["--min-length", str(int(args["min_length"]))])
                if "max_matches" in args:
                    argv.extend(["--max-matches", str(int(args["max_matches"]))])
            elif op == "hex_slice":
                if "offset" in args:
                    argv.extend(["--offset", str(int(args["offset"]))])
                if "length" in args:
                    req_len = int(args["length"])
                    if req_len > limits.max_decode_bytes:
                        raise ContractViolationError(
                            f"hex_slice length={req_len} exceeds max_decode_bytes={limits.max_decode_bytes}."
                        )
                    argv.extend(["--length", str(req_len)])
            elif op == "hash_and_entropy":
                if "block_size" in args:
                    argv.extend(["--block-size", str(int(args["block_size"]))])

            return argv, None, None

        def _summarize_result(
            self,
            action: ActionRecord,
            sub_res: SubprocessResult,
        ) -> str:
            """Return strictly metadata-only summary (never raw strings/markers, CTF-12)."""
            return (
                f"{self._descriptor.adapter_id} operation={action.operation!r} finished "
                f"(outcome={sub_res.outcome.value}, output_bytes={sub_res.output_bytes}, "
                f"capture_complete={sub_res.capture_complete}, cleanup_confirmed={sub_res.cleanup_confirmed})."
            )


if __name__ == "__main__":
    raise SystemExit(_worker_main())


__all__ = [
    "FORBIDDEN_OR_UNACCEPTED_OPERATIONS",
    "STATIC_INSPECTOR_ADAPTER_COMMIT",
    "STATIC_INSPECTOR_ADAPTER_ID",
    "STATIC_INSPECTOR_ARG_SCHEMA",
    "STATIC_INSPECTOR_CAPABILITY_NAME",
    "STATIC_INSPECTOR_DEPENDENCY_LOCK_SHA256",
    "STATIC_INSPECTOR_OPERATIONS",
    "StaticArtifactInspectorAdapter",
    "create_static_inspector_descriptor",
    "get_dependency_lock_sha256",
]
