from click_extra import Style


ListLabel = Style(bold=True)


def label_field(label: str, field: str) -> str:
    return f'{ListLabel(label)}: {field}'
