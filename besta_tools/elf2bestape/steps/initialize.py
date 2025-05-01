import pefile

from besta_tools.elf2bestape.formats import ImageBuildContext


def initialize_directory_dicts(context: ImageBuildContext):
    result = []
    for _ in range(pefile.IMAGE_NUMBEROF_DIRECTORY_ENTRIES):
        result.append({'VirtualAddress': 0, 'Size': 0})
    context['directory_dicts'] = result
