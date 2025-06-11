import os
from PyPDF2 import PdfReader, PdfWriter
from PyPDF2.generic import IndirectObject
import config


def safe_get(obj):
    return obj.get_object() if isinstance(obj, IndirectObject) else obj


def find_javascript_keys(obj, found=None, path=""):
    if found is None:
        found = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            key_str = str(k)
            full_path = f"{path}/{key_str}" if path else key_str
            full_path = full_path.replace("//", "/")
            if key_str in ["/JavaScript", "/JS", "/OpenAction", "/AA"]:
                found.append(full_path)
            find_javascript_keys(v, found, full_path)
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            find_javascript_keys(item, found, f"{path}[{i}]")
    return found


def sanitize_pdf(file_path: str, output_dir: str = None) -> tuple[str, list[str]]:
    if output_dir is None:
        output_dir = config.DIRECTORIES['sanitized_output']

    reader = PdfReader(file_path)
    writer = PdfWriter()

    for page in reader.pages:
        writer.add_page(page)

    removed_keys = []
    root = safe_get(reader.trailer.get("/Root", {}))
    found_keys = find_javascript_keys(root)

    # /Names 내부 JavaScript 제거
    names = safe_get(root.get("/Names"))
    if names:
        js_section = safe_get(names.get("/JavaScript"))
        if js_section:
            del names["/JavaScript"]
            removed_keys.append("/Names/JavaScript")

    # /OpenAction 제거
    if "/OpenAction" in root:
        del root["/OpenAction"]
        removed_keys.append("/OpenAction")

    # /AA 제거
    if "/AA" in root:
        del root["/AA"]
        removed_keys.append("/AA")

    # 제거한 게 없고 탐지만 된 경우
    if not removed_keys and found_keys:
        removed_keys = found_keys

    os.makedirs(output_dir, exist_ok=True)
    filename = os.path.splitext(os.path.basename(file_path))[0]
    clean_file = os.path.join(output_dir, f"{filename}_clean.pdf")
    with open(clean_file, "wb") as f:
        writer.write(f)

    return clean_file, removed_keys