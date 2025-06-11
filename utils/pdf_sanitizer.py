import os
from PyPDF2 import PdfReader, PdfWriter
from PyPDF2.generic import IndirectObject
import config


def safe_get(obj):
    """
    PyPDF2의 IndirectObject를 실제 객체로 안전하게 변환합니다.

    PyPDF2 내부 객체 구조에 직접 접근 시 발생할 수 있는 참조 오류를 방지하기 위한
    헬퍼(Helper) 함수입니다.

    :param obj: 변환할 PyPDF2 객체
    :return: 실제 객체 (Resolved Object)
    """
    return obj.get_object() if isinstance(obj, IndirectObject) else obj


def find_javascript_keys(obj, found=None, path=""):
    """
    PDF 객체 트리 내에서 JavaScript 또는 자동 실행과 관련된 키를 재귀적으로 탐색합니다.

    분석 목적으로, 파일 내에 잠재적으로 위험한 요소가 어떤 경로에 위치하는지
    식별하기 위해 사용됩니다.

    :param obj: 탐색을 시작할 PDF 객체
    :param found: 발견된 키의 경로를 저장할 리스트 (재귀 호출 시 사용)
    :param path: 현재 객체의 경로 (재귀 호출 시 사용)
    :return: 발견된 모든 위험 요소의 경로를 담은 리스트
    """
    if found is None:
        found = []

    if isinstance(obj, dict):
        for k, v in obj.items():
            key_str = str(k)
            full_path = f"{path}/{key_str}".replace("//", "/") if path else key_str
            # 악성 행위에 사용될 수 있는 표준 PDF 키워드 목록
            if key_str in ["/JavaScript", "/JS", "/OpenAction", "/AA", "/URI", "/Launch", "/SubmitForm"]:
                found.append(full_path)
            find_javascript_keys(v, found, full_path)

    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            find_javascript_keys(item, found, f"{path}[{i}]")

    return found


def extract_pdf_javascript(file_path: str) -> dict:
    """
    PDF 파일 내에 포함된 JavaScript 코드를 다양한 위치에서 추출하여 반환합니다.

    :param file_path: 분석할 PDF 파일의 경로
    :return: 추출된 JavaScript 코드를 담은 딕셔너리. {위치: 코드} 형태.
    """
    js_contents = {}
    try:
        reader = PdfReader(file_path)
        root = safe_get(reader.trailer.get("/Root"))
        if not root:
            return js_contents

        # Case 1: 문서 레벨의 JavaScript (/Names 카탈로그)
        if "/Names" in root:
            names = safe_get(root["/Names"])
            if "/JavaScript" in names:
                js_tree = safe_get(names["/JavaScript"])
                if "/Names" in js_tree:
                    js_names = safe_get(js_tree["/Names"])
                    for i in range(0, len(js_names), 2):
                        if i + 1 < len(js_names):
                            name = str(js_names[i])
                            js_obj = safe_get(js_names[i + 1])
                            if "/JS" in js_obj:
                                js_code = safe_get(js_obj["/JS"])
                                js_contents[name] = js_code.get_data().decode('utf-8', 'ignore') if hasattr(js_code,
                                                                                                            'get_data') else str(
                                    js_code)

        # Case 2: 문서 열람 시 자동 실행되는 JavaScript (/OpenAction)
        if "/OpenAction" in root:
            action = safe_get(root["/OpenAction"])
            if isinstance(action, dict) and "/JS" in action:
                js_code = safe_get(action["/JS"])
                js_contents["OpenAction"] = js_code.get_data().decode('utf-8', 'ignore') if hasattr(js_code,
                                                                                                    'get_data') else str(
                    js_code)

        # Case 3: 페이지 단위 이벤트 기반 JavaScript
        for page_num, page in enumerate(reader.pages):
            page_obj = page.get_object()

            # Additional Actions (페이지 열기/닫기 등)
            if "/AA" in page_obj:
                aa = safe_get(page_obj["/AA"])
                for trigger, action in aa.items():
                    if isinstance(action, dict) and "/JS" in action:
                        js_code = safe_get(action["/JS"])
                        js_contents[f"Page{page_num}_{trigger}"] = js_code.get_data().decode('utf-8',
                                                                                             'ignore') if hasattr(
                            js_code, 'get_data') else str(js_code)

            # 주석(Annotation) 객체 내의 스크립트
            if "/Annots" in page_obj:
                for annot_ref in safe_get(page_obj["/Annots"]):
                    annot = safe_get(annot_ref)
                    if isinstance(annot, dict) and "/A" in annot:
                        action = safe_get(annot["/A"])
                        if isinstance(action, dict) and "/JS" in action:
                            js_code = safe_get(action["/JS"])
                            js_contents[f"Page{page_num}_Annotation"] = js_code.get_data().decode('utf-8',
                                                                                                  'ignore') if hasattr(
                                js_code, 'get_data') else str(js_code)

    except Exception as e:
        print(f"오류: JavaScript 추출 중 예외가 발생했습니다 - {e}")
    return js_contents


def remove_javascript_recursive(obj, removed_keys):
    """
    PDF 객체 트리에서 잠재적으로 위험한 키워드를 재귀적으로 탐색하고 삭제합니다.
    이 함수는 전달된 객체(obj)를 직접 수정(in-place modification)합니다.

    :param obj: 수정을 진행할 PDF 객체 (dict 또는 list)
    :param removed_keys: 제거된 키의 이름을 기록할 리스트
    """
    if isinstance(obj, dict):
        keys_to_remove = []
        for key in obj:
            # 위험 키워드 목록에 포함되는 경우, 삭제 목록에 추가
            if str(key) in ["/JavaScript", "/JS", "/OpenAction", "/AA", "/URI", "/Launch", "/SubmitForm"]:
                keys_to_remove.append(key)
                removed_keys.append(str(key))
            else:
                remove_javascript_recursive(obj.get(key), removed_keys)
        # 식별된 위험 키워드를 객체에서 실제로 제거
        for key in keys_to_remove:
            del obj[key]
    elif isinstance(obj, list):
        for item in obj:
            remove_javascript_recursive(item, removed_keys)


def sanitize_pdf(file_path: str, output_dir: str = None) -> tuple[str, list[str]]:
    """
    지정된 PDF 파일에서 JavaScript, 자동 실행 액션 등 잠재적으로 위험한 요소를
    제거하여 안전한 PDF 파일을 생성합니다.

    :param file_path: 무해화를 진행할 원본 PDF 파일 경로
    :param output_dir: 무해화된 파일을 저장할 디렉토리
    :return: (무해화된 파일 경로, 제거된 요소 목록) 튜플
    """
    if output_dir is None:
        output_dir = config.DIRECTORIES['sanitized_output']

    filename = os.path.splitext(os.path.basename(file_path))[0]
    clean_file = os.path.join(output_dir, f"{filename}_clean.pdf")
    removed_keys = []

    try:
        reader = PdfReader(file_path)
        writer = PdfWriter()

        # 원본 PDF의 모든 페이지를 새로운 writer 객체로 복사
        for page in reader.pages:
            writer.add_page(page)

        # 문서의 루트(Root) 객체를 시작점으로 하여 위험 요소 재귀적 제거
        # PyPDF2 4.x.x 버전 이상과의 호환성을 위해 writer._trailer를 사용
        root = reader.trailer.get("/Root")
        if root:
            remove_javascript_recursive(root, removed_keys)

        # 무해화된 내용을 새로운 파일로 저장
        os.makedirs(output_dir, exist_ok=True)
        with open(clean_file, "wb") as f:
            writer.write(f)

    except Exception as e:
        print(f"오류: PDF 무해화 중 예외가 발생했습니다 - {e}")
        return file_path, []

    # 제거된 키 목록에서 중복을 제거한 후 최종 결과 반환
    return clean_file, list(set(removed_keys))