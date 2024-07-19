from typing import TextIO, BinaryIO, Any, Self, Optional, Literal

import click
import dataclasses
import pathlib
import sys

from ..common.utils import simple_checksum


def relative_to_root(path: pathlib.PureWindowsPath) -> pathlib.PureWindowsPath:
    return path.relative_to(path.anchor)


def search_file(root: pathlib.Path, rel_path: str | pathlib.Path):
    if isinstance(rel_path, pathlib.Path) or isinstance(rel_path, pathlib.PurePath):
        rel_path = str(rel_path.as_posix())
    files = tuple(root.glob(rel_path, case_sensitive=False))
    if len(files) == 0:
        return root / rel_path
    return files[0]


class ParserError(RuntimeError):
    pass


@dataclasses.dataclass
class TitleChecksumEntry:
    path: pathlib.PureWindowsPath
    checksum: int


@dataclasses.dataclass
class TitleIndex:
    version: str
    overall_checksum: int
    entries: list[TitleChecksumEntry]

    @classmethod
    def from_scratch(cls) -> Self:
        return cls('V0.00', 0, [])

    @classmethod
    def from_file(cls, file: TextIO) -> Self:
        version = file.readline()
        overall_checksum = int(file.readline(), 16)
        num_files = int(file.readline())
        entries: list[TitleChecksumEntry] = []
        for i in range(num_files):
            path = file.readline()
            checksum = file.readline()
            entries.append(TitleChecksumEntry(pathlib.PureWindowsPath(path.rstrip()), int(checksum, 16)))
        return cls(version, overall_checksum, entries)

    def dump(self) -> str:
        result: list[str] = [
            self.version,
            f'{self.overall_checksum:#06x}',
            f'{len(self.entries):>6}'
        ]

        for entry in self.entries:
            result.append(entry.path)
            result.append(f'{entry.checksum:#06x}')
        return '\n'.join(result)

    def to_file(self, file: TextIO) -> None:
        file.write(self.dump())

    def validate(self) -> bool:
        overall_checksum = sum(entry.checksum for entry in self.entries) & 0xffff
        return overall_checksum == self.overall_checksum

    def fix_checksum(self) -> None:
        self.overall_checksum = sum(entry.checksum for entry in self.entries) & 0xffff


@click.group()
def app():
    pass


@app.command('init', help='Initialize an title index file.')
@click.argument('path', type=click.Path(exists=True))
@click.option('-f', '--force', is_flag=True, help='Overwrite any existing title index file.')
def do_init(path: str, force: bool):
    root = pathlib.Path(path)
    index_file = search_file(root, 'SYSCHECK.$$$')

    if index_file.is_file():
        if not force:
            click.echo('Refusing to create a new index file as it already exists.')
            sys.exit(1)
    elif index_file.exists():
        click.echo('Index file does not seem to be a file. Aborting.')
        sys.exit(1)

    with index_file.open('w', newline='\r\n', encoding='ascii') as f:
        TitleIndex.from_scratch().to_file(f)


@app.command('validate', help='Validate a user data root.')
@click.argument('path', type=click.Path(exists=True))
@click.option('-m', '--metadata-only', is_flag=True, help='Only check index consistency.')
@click.option('-e', '--encoding', default='cp936', help='Encoding type to use (default is cp936).')
def do_validate(path: str, metadata_only: bool, encoding: str):
    root = pathlib.Path(path)
    index_file = search_file(root, 'SYSCHECK.$$$')
    with index_file.open('r', encoding=encoding) as f:
        title_index = TitleIndex.from_file(f)

    if not title_index.validate():
        click.echo('Overall checksum inconsistent with the actual sum of checksum of entries.')
        sys.exit(1)

    if metadata_only:
        return
    
    failed_io = 0
    failed_checksum = 0

    for entry in title_index.entries:
        actual_path = search_file(root, relative_to_root(entry.path))
        try:
            with actual_path.open('rb') as f:
                checksum = simple_checksum(f)
                if checksum != entry.checksum:
                    click.echo(f'{str(actual_path)}: FAILED')
                    failed_checksum += 1
                else:
                    click.echo(f'{str(actual_path)}: OK')
        except OSError as err:
            click.echo(f'Validation error: {repr(str(actual_path))}: {err.strerror}')
            click.echo(f'{str(actual_path)}: FAILED open or read')
            failed_io += 1

    if failed_io > 0:
        click.echo(f'WARNING: {failed_io} file(s) could not be read.')
    if failed_checksum > 0:
        click.echo(f'WARNING: {failed_checksum} computed checksum did NOT match.')


def main():
    app()
