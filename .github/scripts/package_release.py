#!/usr/bin/env python3
"""Create a deterministic mtls-pki release archive."""

from __future__ import annotations

import argparse
import gzip
import os
from pathlib import Path
import stat
import tarfile
import time
import zipfile


ROOT_FILES = ("README.md", "LICENSE")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--format", choices=("tar.gz", "zip"), required=True)
    parser.add_argument("--output-dir", type=Path, default=Path("dist"))
    return parser.parse_args()


def source_date_epoch() -> int:
    value = os.environ.get("SOURCE_DATE_EPOCH")
    if value is None:
        return int(time.time())

    try:
        return int(value)
    except ValueError as error:
        raise SystemExit("SOURCE_DATE_EPOCH must be an integer") from error


def archive_entries(binary: Path, root_name: str) -> list[tuple[Path, str, int]]:
    if not binary.is_file():
        raise SystemExit(f"binary does not exist: {binary}")

    binary_name = "mtls-pki.exe" if binary.suffix == ".exe" else "mtls-pki"
    entries = [(binary, f"{root_name}/{binary_name}", 0o755)]
    for name in ROOT_FILES:
        path = Path(name)
        if not path.is_file():
            raise SystemExit(f"required release file does not exist: {path}")
        entries.append((path, f"{root_name}/{name}", 0o644))
    return entries


def write_tar_gz(
    output: Path,
    entries: list[tuple[Path, str, int]],
    epoch: int,
) -> None:
    with output.open("wb") as raw_output:
        with gzip.GzipFile(
            filename="",
            mode="wb",
            fileobj=raw_output,
            mtime=epoch,
            compresslevel=9,
        ) as gzip_output:
            with tarfile.open(
                fileobj=gzip_output,
                mode="w",
                format=tarfile.PAX_FORMAT,
            ) as archive:
                for source, archive_name, mode in sorted(entries, key=lambda item: item[1]):
                    info = archive.gettarinfo(str(source), archive_name)
                    info.uid = 0
                    info.gid = 0
                    info.uname = ""
                    info.gname = ""
                    info.mode = mode
                    info.mtime = epoch
                    with source.open("rb") as source_file:
                        archive.addfile(info, source_file)


def zip_datetime(epoch: int) -> tuple[int, int, int, int, int, int]:
    timestamp = time.gmtime(max(epoch, 315532800))
    return (
        timestamp.tm_year,
        timestamp.tm_mon,
        timestamp.tm_mday,
        timestamp.tm_hour,
        timestamp.tm_min,
        timestamp.tm_sec - (timestamp.tm_sec % 2),
    )


def write_zip(
    output: Path,
    entries: list[tuple[Path, str, int]],
    epoch: int,
) -> None:
    timestamp = zip_datetime(epoch)
    with zipfile.ZipFile(
        output,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as archive:
        for source, archive_name, mode in sorted(entries, key=lambda item: item[1]):
            info = zipfile.ZipInfo(archive_name, timestamp)
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, source.read_bytes())


def main() -> None:
    args = parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)

    root_name = f"mtls-pki_{args.version}_{args.target}"
    suffix = ".zip" if args.format == "zip" else ".tar.gz"
    output = args.output_dir / f"{root_name}{suffix}"
    entries = archive_entries(args.binary, root_name)
    epoch = source_date_epoch()

    if args.format == "zip":
        write_zip(output, entries, epoch)
    else:
        write_tar_gz(output, entries, epoch)

    print(f"created {output}")


if __name__ == "__main__":
    main()
