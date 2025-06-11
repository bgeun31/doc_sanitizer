import os
import config


def sanitize_hwp(file_path: str, output_dir: str = None) -> tuple[str, list[str]]:
    if output_dir is None:
        output_dir = config.DIRECTORIES['sanitized_output']

    ext = os.path.splitext(file_path)[1].lower()
    filename = os.path.splitext(os.path.basename(file_path))[0]
    clean_file = os.path.join(output_dir, f"{filename}_clean{ext}")
    removed_strings = []

    with open(file_path, "rb") as f:
        data = f.read()

    for pattern in [b'Shell', b'cmd', b'urlmon', b'http', b'javascript']:
        if pattern in data:
            data = data.replace(pattern, b'[REMOVED]')
            removed_strings.append(pattern.decode())

    os.makedirs(output_dir, exist_ok=True)
    with open(clean_file, "wb") as f:
        f.write(data)

    return clean_file, removed_strings