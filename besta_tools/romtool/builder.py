from typing import Final, TypedDict, NotRequired, Sequence, cast, Mapping

import io

from .formats import RomExtMetadataHeader, CsRomSpecType, CsRomExtMetadataHeader, CsRomLocalizedTitle, \
    CsRomLocalizedTitleEntry, CsRomFallbackTitle, RomLocalizedTitle, RomLocale, RomFallbackTitle, RomSpecType, \
    MagicType, RomType, RomSpecTimestamp, RomLocalizedTitleEntry
from ..common.formats import ChecksumValue
from ..common.utils import simple_checksum, Fragment, BinaryBuilder

LOCALE_MAPPING: Final[dict[str, RomLocale]] = {
    'zh_CN': RomLocale.ZH_CN,
    'zh_TW': RomLocale.ZH_TW,
    'ja': RomLocale.JA_JP,
    'ko': RomLocale.KO_KR,
    'th': RomLocale.TH_TH,
    'en': RomLocale.EN_US,
}

SpecTomlRomSection = TypedDict('SpecTomlRomSection', {
    'title': str,
    'short-title': NotRequired[str],
    'title-alt': NotRequired[str],
    'short-title-alt': NotRequired[str],
    'category': str | int,
    'subtype': NotRequired[int],
    'version': str,
    'copyright': str,
    'sdk-id': NotRequired[str],
    'default-locale': NotRequired[str | int],
    'icon': NotRequired[str],
})

SpecTomlMetadataElement = TypedDict('SpecTomlMetadataElement', {
    'title': str,
    'short-title': NotRequired[str],
})


class SpecToml(TypedDict):
    rom: SpecTomlRomSection
    metadata: NotRequired[Mapping[str, SpecTomlMetadataElement]]


def build_embeddable_from_spec_file(spec_dict_in: dict):
    str_table: dict[str, Fragment] = {}

    def add_to_strtab(str_: str) -> Fragment:
        nonlocal str_table
        if str_ not in str_table:
            encoded = str_.encode('utf-16le')
            str_table_entry = builder.append(len(encoded) + 2)
            str_table_entry.set_data(encoded + b'\x00\x00')
            str_table[str_] = str_table_entry
            return str_table_entry
        else:
            return str_table[str_]

    spec_dict = cast(SpecToml, spec_dict_in)
    spec_dict_rom = spec_dict['rom']
    spec_dict_metadata = spec_dict.get('metadata', [])

    build_date = RomSpecTimestamp.now()

    builder = BinaryBuilder()

    # Forward declaration
    header_alloc = builder.append(CsRomSpecType.sizeof())
    ext_metadata_header_alloc = builder.append(CsRomExtMetadataHeader.sizeof())
    localized_title_alloc = builder.append(CsRomLocalizedTitle.sizeof())
    localized_title_elements_alloc = [
        builder.append(CsRomLocalizedTitleEntry.sizeof()) for _ in spec_dict_metadata
    ]
    fallback_title_alloc = builder.append(CsRomFallbackTitle.sizeof())

    ext_metadata_header = RomExtMetadataHeader(
        num_localized_title_entries=len(spec_dict_metadata),
    )
    ext_metadata_header_alloc.set_data(CsRomExtMetadataHeader.build(ext_metadata_header))

    localized_title = RomLocalizedTitle(
        num_entries=len(spec_dict_metadata),
        locale=RomLocale.UNSET,
    )
    localized_title_alloc.set_data(CsRomLocalizedTitle.build(localized_title))

    for element, (locale_str, metadata) in zip(localized_title_elements_alloc, spec_dict_metadata.items()):
        title_fragment = add_to_strtab(metadata['title'])
        short_title_fragment = add_to_strtab(metadata['short-title'])

        encoded_element_index = RomLocalizedTitleEntry(
            locale=LOCALE_MAPPING[locale_str],
            title_offset=title_fragment.offset,
            short_title_offset=short_title_fragment.offset,
        )
        element.set_data(CsRomLocalizedTitleEntry.build(encoded_element_index))

    fallback_title_fragment = add_to_strtab(spec_dict_rom['title'])

    if 'title-alt' in spec_dict_rom:
        fallback_title_alt_fragment = add_to_strtab(spec_dict_rom['title-alt'])
    else:
        fallback_title_alt_fragment = fallback_title_fragment

    if 'short-title' in spec_dict_rom:
        fallback_short_title_fragment = add_to_strtab(spec_dict_rom['short-title'])
    else:
        fallback_short_title_fragment = None

    if 'short-title-alt' in spec_dict_rom:
        fallback_short_title_alt_fragment = add_to_strtab(spec_dict_rom['short-title-alt'])
    else:
        fallback_short_title_alt_fragment = None

    fallback_title_index = RomFallbackTitle(
        locale=RomLocale.UNSET,
        title_offset=fallback_title_fragment.offset,
        short_title_offset=(
            fallback_short_title_fragment.offset if fallback_short_title_fragment is not None else 0xffffffff
        ),
        chinese_title_offset=fallback_title_alt_fragment.offset,
        chinese_short_title_offset=(
            fallback_short_title_alt_fragment.offset if fallback_short_title_alt_fragment is not None else 0xffffffff
        ),
    )

    fallback_title_alloc.set_data(CsRomFallbackTitle.build(fallback_title_index))

    copyright_offset = add_to_strtab(spec_dict_rom['copyright']).offset
    version_offset = add_to_strtab(spec_dict_rom['version']).offset
    sdk_id_offset = add_to_strtab(spec_dict_rom.get('sdk-id', 'besta_tools.romtool')).offset

    checksum_value = ChecksumValue(0)

    header = RomSpecType(
        magic=MagicType.APPLET,
        type_=(
            RomType[spec_dict_rom['category']].value
            if isinstance(spec_dict_rom['category'], str)
            else int(spec_dict_rom['category'])
        ),
        checksum=checksum_value,
        default_locale=RomLocale.FORCE_UTF16 | LOCALE_MAPPING[spec_dict_rom['default-locale']],
        sections_offset=0,
        build_timestamp=build_date,
        rom_size=builder.sizeof(),
        entry_point=0,
        fallback_title_offset=fallback_title_alloc.offset,
        copyright_offset=copyright_offset,
        icon_offset=0xffffffff,
        version_offset=version_offset,
        data_offset=builder.sizeof(),
        sdk_id_offset=sdk_id_offset,
        ext_metadata_offset=ext_metadata_header_alloc.offset,
        localized_title_offset=localized_title_alloc.offset,
        subtype=spec_dict_rom.get('subtype', 0),
    )

    header_alloc.set_data(CsRomSpecType.build(header))

    # Fix checksum
    checksum = simple_checksum(io.BytesIO(builder.concat()))
    checksum_value.checksum = checksum

    return builder.concat()
