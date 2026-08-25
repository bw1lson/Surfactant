# Copyright 2026 AMPTools
# SPDX-License-Identifier: MIT
"""Surfactant plugin that unpacks non-native firmware/container formats with OFRAK.

Surfactant natively decompresses common archives (ZIP/TAR/GZIP/BZIP2/XZ/RAR) via
``file_decompression.py``. This plugin extends that idea to firmware and embedded
container formats that OFRAK knows how to unpack (SquashFS, CramFS, JFFS2, UBI/UBIFS,
romfs, ext filesystems, U-Boot uImage, Android boot images, CPIO, device tree blobs,
etc.).

It works exactly like the built-in decompressor: it unpacks the container to a
temporary directory and pushes ``ContextEntry`` objects onto Surfactant's
``context_queue`` so the extracted artifacts are re-processed by the *entire* plugin
pipeline (ELF/PE extractors, checksec, angr-expanded, relationship builders, ...).
This plugin therefore does not analyze the contents itself; it only unpacks.

OFRAK is an optional dependency. If it is not installed, ``identify_file_type`` still
works (so the firmware type is still recorded), and ``extract_file_info`` logs a
warning and skips unpacking.
"""

from __future__ import annotations

import pathlib
import tempfile
from typing import TYPE_CHECKING, Any

from loguru import logger

import surfactant.plugin
from surfactant import ContextEntry
from surfactant.configmanager import ConfigManager
from surfactant.sbomtypes import SBOM, Software

if TYPE_CHECKING:
    from queue import Queue

# ---------------------------------------------------------------------------
# File-type identification (magic bytes)
# ---------------------------------------------------------------------------

# Each entry maps a Surfactant file-type label to a (offset, signatures) pair.
# ``signatures`` is a tuple of byte strings; a match at ``offset`` for any of them
# identifies the type. These are the non-native container formats that OFRAK can
# unpack but Surfactant does not handle on its own.
_MAGIC_SIGNATURES: dict[str, tuple[int, tuple[bytes, ...]]] = {
    # SquashFS: "hsqs" (little-endian) or "sqsh" (big-endian) at offset 0
    "SQUASHFS": (0, (b"hsqs", b"sqsh")),
    # CramFS: 0x28cd3d45 stored little-endian at offset 0
    "CRAMFS": (0, (b"\x45\x3d\xcd\x28",)),
    # JFFS2: 0x1985 as either endianness at offset 0
    "JFFS2": (0, (b"\x85\x19", b"\x19\x85")),
    # UBI volume ("UBI#") and UBIFS ("UBI!") at offset 0
    "UBI": (0, (b"UBI#",)),
    "UBIFS": (0, (b"\x31\x18\x10\x06",)),
    # romfs
    "ROMFS": (0, (b"-rom1fs-",)),
    # U-Boot legacy uImage: magic 0x27051956 at offset 0
    "UIMAGE": (0, (b"\x27\x05\x19\x56",)),
    # Android boot image
    "ANDROID_BOOT": (0, (b"ANDROID!",)),
    # Device tree blob (FDT): 0xd00dfeed at offset 0
    "DTB": (0, (b"\xd0\x0d\xfe\xed",)),
    # CPIO archives (newc/crc ASCII and old binary)
    "CPIO": (0, (b"070701", b"070702", b"070707", b"\xc7\x71")),
    # YAFFS2 object header (first record is typically a directory named for the root)
    "YAFFS": (0, (b"\x03\x00\x00\x00\x01\x00\x00\x00\xff\xff",)),
    # GPT-partitioned disk image: "EFI PART" at LBA 1 (offset 0x200)
    "GPT": (0x200, (b"EFI PART",)),
}

# ext2/3/4 superblock magic 0xEF53 lives at offset 0x438, handled specially.
_EXT_MAGIC_OFFSET = 0x438
_EXT_MAGIC = b"\x53\xef"

# MBR-partitioned disk image: 0x55AA boot signature at offset 0x1FE with at least
# one non-empty partition table entry (checked specially to reduce false positives).
_MBR_SIG_OFFSET = 0x1FE
_MBR_SIG = b"\x55\xaa"
_MBR_PART_TABLE_OFFSET = 0x1BE

# The set of labels this plugin knows how to unpack.
_SUPPORTED_TYPES = frozenset(_MAGIC_SIGNATURES) | {"EXT", "DISK_IMAGE"}

_METADATA_KEY = "ofrakUnpacker"
_SETTINGS_SECTION = "ofrak_unpacker"

# ---------------------------------------------------------------------------
# Extraction bookkeeping
# ---------------------------------------------------------------------------

# sha256 -> extracted directory path, so repeated files are only unpacked once.
# sha256 -> extracted directory path, so repeated files are only unpacked once.
# Extraction directories are intentionally kept (not auto-deleted) so their
# contents can be inspected and reused, mirroring Surfactant's built-in
# file_decompression extractor.
_EXTRACT_DIRS: dict[str, str] = {}

_SECTOR_SIZE = 512
# Extended-partition container types hold logical partitions rather than a
# filesystem, so they are skipped (their logical partitions would be carved
# separately in a fuller implementation).
_EXTENDED_PART_TYPES = {0x05, 0x0F, 0x85}


def _make_extract_dir() -> str:
    base = ConfigManager().get(_SETTINGS_SECTION, "extract_dir", tempfile.gettempdir())
    pathlib.Path(base).mkdir(parents=True, exist_ok=True)
    return tempfile.mkdtemp(prefix="surfactant-ofrak-", dir=base)


def _carve_range(src_path: str, offset: int, length: int, dest_path: str) -> int:
    """Copy ``length`` bytes starting at ``offset`` from ``src_path`` to ``dest_path``."""
    written = 0
    with open(src_path, "rb") as src, open(dest_path, "wb") as out:
        src.seek(offset)
        remaining = length
        while remaining > 0:
            chunk = src.read(min(1 << 20, remaining))
            if not chunk:
                break
            out.write(chunk)
            written += len(chunk)
            remaining -= len(chunk)
    return written


def _mbr_partitions(header: bytes, file_size: int) -> list[dict[str, int]]:
    """Parse the four primary MBR partition-table entries."""
    parts: list[dict[str, int]] = []
    table = header[_MBR_PART_TABLE_OFFSET : _MBR_PART_TABLE_OFFSET + 64]
    for i in range(4):
        entry = table[i * 16 : (i + 1) * 16]
        if len(entry) < 16:
            break
        ptype = entry[4]
        lba_start = int.from_bytes(entry[8:12], "little")
        num_sectors = int.from_bytes(entry[12:16], "little")
        if ptype == 0 or num_sectors == 0 or ptype in _EXTENDED_PART_TYPES:
            continue
        offset = lba_start * _SECTOR_SIZE
        if offset <= 0 or offset >= file_size:
            continue
        length = min(num_sectors * _SECTOR_SIZE, file_size - offset)
        parts.append({"index": i, "type": ptype, "offset": offset, "length": length})
    return parts


def _gpt_partitions(src_path: str, file_size: int) -> list[dict[str, int]]:
    """Parse the GPT partition entry array (header at LBA 1)."""
    parts: list[dict[str, int]] = []
    with open(src_path, "rb") as f:
        f.seek(_SECTOR_SIZE)
        hdr = f.read(_SECTOR_SIZE)
        if hdr[:8] != b"EFI PART":
            return parts
        part_entry_lba = int.from_bytes(hdr[72:80], "little")
        num_entries = int.from_bytes(hdr[80:84], "little")
        entry_size = int.from_bytes(hdr[84:88], "little")
        if entry_size < 128 or num_entries == 0 or num_entries > 512:
            return parts
        f.seek(part_entry_lba * _SECTOR_SIZE)
        table = f.read(num_entries * entry_size)
    for i in range(num_entries):
        entry = table[i * entry_size : (i + 1) * entry_size]
        if len(entry) < 56:
            break
        if entry[0:16] == b"\x00" * 16:  # unused entry (zero type GUID)
            continue
        first_lba = int.from_bytes(entry[32:40], "little")
        last_lba = int.from_bytes(entry[40:48], "little")
        if last_lba < first_lba:
            continue
        offset = first_lba * _SECTOR_SIZE
        if offset >= file_size:
            continue
        length = min((last_lba - first_lba + 1) * _SECTOR_SIZE, file_size - offset)
        parts.append({"index": i, "type": 0xEE, "offset": offset, "length": length})
    return parts


def _carve_partitions(filename: str, out_dir: str) -> list[dict[str, Any]]:
    """Carve each partition of an MBR/GPT disk image into ``out_dir``."""
    file_size = pathlib.Path(filename).stat().st_size
    with open(filename, "rb") as f:
        header = f.read(1088)

    partitions: list[dict[str, int]] = []
    if header[0x200:0x208] == b"EFI PART":
        partitions = _gpt_partitions(filename, file_size)
    if not partitions:
        partitions = _mbr_partitions(header, file_size)

    results: list[dict[str, Any]] = []
    for p in partitions:
        dest = str(pathlib.Path(out_dir) / f"partition_{p['index']}_type_0x{p['type']:02x}.img")
        written = _carve_range(filename, p["offset"], p["length"], dest)
        results.append(
            {
                "index": p["index"],
                "partitionType": f"0x{p['type']:02x}",
                "offset": p["offset"],
                "length": written,
                "path": dest,
            }
        )
    return results


def _existing_partition_files(out_dir: str) -> list[dict[str, Any]]:
    return [
        {"path": str(p), "length": p.stat().st_size}
        for p in sorted(pathlib.Path(out_dir).glob("partition_*.img"))
    ]


def supports_file(filetype: list[str] | None) -> list[str] | None:
    """Return the subset of ``filetype`` labels this plugin can unpack."""
    if not filetype:
        return None
    supported = [ft for ft in filetype if ft in _SUPPORTED_TYPES]
    return supported or None


@surfactant.plugin.hookimpl
def identify_file_type(filepath: str, context: ContextEntry | None = None) -> list[str] | None:
    """Identify non-native firmware/container formats by magic bytes."""
    try:
        with pathlib.Path(filepath).open("rb") as f:
            header = f.read(1088)  # covers all offset-0 sigs plus the ext superblock
    except OSError:
        return None

    matches: list[str] = []
    for label, (offset, signatures) in _MAGIC_SIGNATURES.items():
        window = header[offset : offset + max(len(s) for s in signatures)]
        if any(window.startswith(sig) for sig in signatures):
            matches.append(label)

    if header[_EXT_MAGIC_OFFSET : _EXT_MAGIC_OFFSET + 2] == _EXT_MAGIC:
        matches.append("EXT")

    # MBR disk image: boot signature plus a partition table entry with a non-zero
    # partition type byte (offset +4 within a 16-byte entry). GPT protective MBRs
    # also match, which is fine since GPT is detected separately above.
    if header[_MBR_SIG_OFFSET : _MBR_SIG_OFFSET + 2] == _MBR_SIG:
        part_types = [
            header[_MBR_PART_TABLE_OFFSET + i * 16 + 4] for i in range(4)
        ]
        if any(pt != 0 for pt in part_types):
            matches.append("DISK_IMAGE")

    return matches or None


# ---------------------------------------------------------------------------
# OFRAK unpacking
# ---------------------------------------------------------------------------


def _ofrak_available() -> bool:
    try:
        import ofrak  # noqa: F401
    except ImportError:
        return False
    return True


def _unpack_fs_with_ofrak(filename: str, out_dir: str) -> dict[str, Any]:
    """Unpack a single filesystem/container ``filename`` into ``out_dir`` with OFRAK.

    OFRAK is asyncio-based, so the async work is wrapped and run to completion.
    A recursive unpack gives the best coverage but can crash on a spurious match
    (e.g. a false-positive device-tree blob inside an extracted file). Such
    errors are tolerated: whatever filesystem trees were recovered are still
    flushed to disk, and a single-level unpack is used as a fallback.
    """
    import ofrak  # local import so the plugin loads without OFRAK installed
    from ofrak.core.filesystem import FilesystemRoot

    summary: dict[str, Any] = {"extractedFileCount": 0, "filesystemCount": 0}

    async def _run(ofrak_context: "ofrak.OFRAKContext") -> None:
        root = await ofrak_context.create_root_resource_from_file(filename)

        async def _collect_fs_roots() -> list[Any]:
            found: list[Any] = []
            if root.has_tag(FilesystemRoot):
                found.append(root)
            for descendant in await root.get_descendants():
                if descendant.has_tag(FilesystemRoot):
                    found.append(descendant)
            return found

        try:
            await root.unpack_recursively()
        except Exception as exc:  # noqa: BLE001 - tolerate crashing sub-unpackers
            logger.warning(f"OFRAK recursive unpack of {filename} hit an error: {exc}")

        fs_resources = await _collect_fs_roots()
        if not fs_resources:
            try:
                await root.unpack()
            except Exception as exc:  # noqa: BLE001
                logger.warning(f"OFRAK shallow unpack of {filename} failed: {exc}")
            fs_resources = await _collect_fs_roots()

        for idx, fsr in enumerate(fs_resources):
            dest = pathlib.Path(out_dir) / f"filesystem_{idx}"
            dest.mkdir(parents=True, exist_ok=True)
            try:
                view = await fsr.view_as(FilesystemRoot)
                await view.flush_to_disk(str(dest))
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    f"OFRAK failed to flush filesystem_{idx} of {filename}: {exc}"
                )

        summary["filesystemCount"] = len(fs_resources)
        summary["extractedFileCount"] = sum(
            1 for p in pathlib.Path(out_dir).rglob("*") if p.is_file()
        )

    ofrak.OFRAK().run(_run)
    return summary


# pylint: disable=too-many-positional-arguments
@surfactant.plugin.hookimpl
def extract_file_info(
    sbom: SBOM,
    software: Software,
    filename: str,
    filetype: list[str],
    context_queue: "Queue[ContextEntry]",
    current_context: ContextEntry | None,
    omit_unrecognized_types: bool = False,
) -> dict[str, Any] | None:
    supported = supports_file(filetype)
    if not supported:
        return None

    # Avoid re-extracting an archive we're already inside of.
    if current_context and current_context.archive == filename and current_context.extractPaths:
        return None

    # Inherit the install prefix from the parent context, if any.
    install_prefix = current_context.installPrefix if current_context else ""
    is_disk_image = any(t in ("DISK_IMAGE", "GPT") for t in supported)

    # Reuse a previous extraction of identical bytes.
    out_dir = _EXTRACT_DIRS.get(software.sha256)
    reused = bool(out_dir and pathlib.Path(out_dir).exists())
    if not reused:
        out_dir = _make_extract_dir()
        _EXTRACT_DIRS[software.sha256] = out_dir

    if is_disk_image:
        # Partition carving is pure-Python; OFRAK has no MBR/GPT unpacker.
        try:
            partitions = (
                _existing_partition_files(out_dir)
                if reused
                else _carve_partitions(filename, out_dir)
            )
        except Exception as exc:  # noqa: BLE001
            logger.opt(exception=True).error(
                f"Failed to carve partitions from {filename}: {exc}"
            )
            return {
                _METADATA_KEY: {
                    "detectedFormats": supported,
                    "unpacked": False,
                    "error": str(exc),
                }
            }

        if not partitions:
            logger.warning(f"No partitions carved from disk image {filename}")
            return {_METADATA_KEY: {"detectedFormats": supported, "unpacked": False}}

        for part in partitions:
            context_queue.put(
                ContextEntry(
                    archive=filename,
                    installPrefix=install_prefix,
                    extractPaths=[part["path"]],
                    skipProcessingArchive=True,
                    omitUnrecognizedTypes=True,
                )
            )
        logger.info(
            f"Carved {len(partitions)} partition(s) from {supported} '{filename}' -> {out_dir}"
        )
        return {
            _METADATA_KEY: {
                "detectedFormats": supported,
                "unpacked": True,
                "extractPath": out_dir,
                "partitions": partitions,
            }
        }

    # Filesystem/container formats require OFRAK.
    if not _ofrak_available():
        logger.warning(
            f"OFRAK is not installed; cannot unpack {supported} file {filename}. "
            "Install with 'pip install ofrak' to enable extraction."
        )
        return {_METADATA_KEY: {"detectedFormats": supported, "unpacked": False}}

    if reused:
        summary: dict[str, Any] = {"cached": True}
    else:
        try:
            summary = _unpack_fs_with_ofrak(filename, out_dir)
        except Exception as exc:  # noqa: BLE001 - surface OFRAK errors without crashing
            logger.opt(exception=True).error(f"OFRAK failed to unpack {filename}: {exc}")
            return {
                _METADATA_KEY: {
                    "detectedFormats": supported,
                    "unpacked": False,
                    "error": str(exc),
                }
            }

    context_queue.put(
        ContextEntry(
            archive=filename,
            installPrefix=install_prefix,
            extractPaths=[out_dir],
            skipProcessingArchive=True,
            omitUnrecognizedTypes=True,
        )
    )
    logger.info(f"OFRAK unpacked {supported} '{filename}' -> {out_dir}")

    return {
        _METADATA_KEY: {
            "detectedFormats": supported,
            "unpacked": True,
            "extractPath": out_dir,
            **summary,
        }
    }


@surfactant.plugin.hookimpl
def short_name() -> str:
    return "ofrak_unpacker"
