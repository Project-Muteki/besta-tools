import logging

import pefile

from elftools.elf.enums import ENUM_E_TYPE

from besta_tools.elf2bestape.formats import ImageBuildContext


logger = logging.getLogger('elf2bestape.steps.initialize')


def initialize_directory_dicts(context: ImageBuildContext):
    result = []
    for _ in range(pefile.IMAGE_NUMBEROF_DIRECTORY_ENTRIES):
        result.append({'VirtualAddress': 0, 'Size': 0})
    context['directory_dicts'] = result


def detect_type(context: ImageBuildContext):
    elf = context['elf']

    if elf.header['e_type'] == 'ET_DYN':
        logger.debug('ELF is a shared library.')
        context['is_dll'] = True
    elif elf.header['e_type'] == 'ET_EXEC':
        logger.debug('ELF is an executable.')
        context['is_dll'] = False
    elif elf.header['e_type'] == 'ET_CORE':
        logger.error('Refusing to build from a core dump file.')
        raise RuntimeError('Refusing to build from a core dump file.')
    else:
        logger.warning('Unhandled ELF e_type %s. Assuming executable.', elf.header['e_type'])
        context['is_dll'] = False
