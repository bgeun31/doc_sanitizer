# main.py - GUI 레이아웃 가운데 정렬

import customtkinter as ctk
from tkinter import filedialog, messagebox
import os
import threading
import time
import subprocess
import sys
import asyncio
from datetime import datetime
import json

from PyPDF2 import PdfReader
from PyPDF2.generic import IndirectObject
from utils.office_macro import remove_macro, is_macro_present
from utils.pdf_sanitizer import sanitize_pdf, find_javascript_keys
from utils.hwp_sanitizer import sanitize_hwp
from utils.model_manager import get_model_manager
from utils.malware_classifier import MalwareClassifier
from utils.virustotal_checker import create_virustotal_checker
from dotenv import load_dotenv

load_dotenv()
import config
from utils import aws_helper
from utils.model_trainer import ModelTrainer
from utils.aws_helper import get_s3_model_info

# CustomTkinter 테마 설정
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")


def bootstrap_models():
    """첫 실행 때 S3에서 모델 다운로드"""
    if not config.USE_AWS:
        print("[BOOT] USE_AWS=false → S3 동기화 건너뜀")
        return

    os.makedirs("models", exist_ok=True)

    targets = {
        "models/ensemble_model.pkl": "models/ensemble_model.pkl",
        "models/scaler.pkl": "models/scaler.pkl",
        "models/model_meta.json": "models/model_meta.json"
    }

    for s3_key, local_path in targets.items():
        if not os.path.exists(local_path):
            print(f"[BOOT] S3 → {local_path} 다운로드 시도")
            try:
                aws_helper.download(s3_key, local_path)
                if os.path.exists(local_path):
                    print(f"[BOOT] {local_path} 다운로드 성공")
                else:
                    print(f"[BOOT] {local_path} 다운로드 실패")
            except Exception as e:
                print(f"[BOOT] {local_path} 다운로드 오류: {e}")
        else:
            print(f"[BOOT] {local_path} 이미 존재 → 건너뜀")


# 내장 서버 클래스
class EmbeddedServer:
    def __init__(self, app_instance):
        self.app = app_instance
        self.server_process = None
        self.server_running = False

    def start_server(self):
        """백그라운드에서 서버 시작"""

        def run_server():
            try:
                import uvicorn
                from retrain_server import app as server_app

                self.app.model_log_append("내장 서버 시작 중...")

                # 서버 설정
                config_dict = {
                    "app": server_app,
                    "host": "127.0.0.1",
                    "port": int(os.getenv("SERVER_PORT", "8000")),
                    "log_level": "error",  # 로그 최소화
                    "access_log": False
                }

                # 서버 실행
                self.server_running = True
                self.app.model_log_append("내장 서버 시작 완료")
                self.app.server_connected = True
                self.app.update_server_status("내장 서버 연결됨", "#00FF00")

                uvicorn.run(**config_dict)

            except Exception as e:
                self.app.model_log_append(f"내장 서버 시작 실패: {e}")
                self.server_running = False

        thread = threading.Thread(target=run_server, daemon=True)
        thread.start()

        # 서버 시작 대기
        time.sleep(2)

    def stop_server(self):
        """서버 중지"""
        if self.server_process:
            self.server_process.terminate()
            self.server_running = False


bootstrap_models()


class DocSanitizerApp:
    def __init__(self):
        # 메인 윈도우 설정
        self.root = ctk.CTk()
        self.root.title("문서형 악성코드 무해화 시스템 v2.2")
        self.root.geometry("1200x800")
        self.root.resizable(False, False)

        # 전역 변수
        self.uploaded_files = []
        self.model_manager = get_model_manager()
        self.malware_classifier = MalwareClassifier()
        self.virustotal_checker = create_virustotal_checker()
        self.sanitization_history = []
        self.server_connected = False

        # 내장 서버 초기화
        self.embedded_server = EmbeddedServer(self)

        # UI 생성
        self.create_ui()

        # 초기화
        self.log_append("문서형 악성코드 무해화 시스템 v2.2 시작")
        self.root.after(1000, self.initialize_system)

    def create_ui(self):
        """UI 구성 요소 생성"""
        # 메인 탭뷰 생성
        self.tabview = ctk.CTkTabview(self.root, width=1180, height=780)
        self.tabview.pack(fill="both", expand=True, padx=10, pady=10)

        # 탭 추가
        self.tab_process = self.tabview.add("무해화 처리")
        self.tab_model = self.tabview.add("모델 정보")

        # 각 탭 UI 생성
        self.create_process_tab()
        self.create_model_tab()

    def create_process_tab(self):
        """무해화 처리 탭 UI"""
        # 파일 리스트 영역
        file_frame = ctk.CTkFrame(self.tab_process, corner_radius=10)
        file_frame.pack(fill="x", padx=20, pady=(15, 5))

        file_label = ctk.CTkLabel(file_frame, text="업로드된 문서",
                                  font=ctk.CTkFont(size=16, weight="bold"))
        file_label.pack(pady=(10, 5))

        # 파일 리스트박스 (스크롤 가능한 프레임으로 구현)
        self.file_list_frame = ctk.CTkScrollableFrame(file_frame, height=150)
        self.file_list_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        # 버튼 영역
        button_frame = ctk.CTkFrame(self.tab_process, corner_radius=10)
        button_frame.pack(fill="x", padx=20, pady=5)

        # 버튼 컨테이너 (가운데 정렬용)
        button_container = ctk.CTkFrame(button_frame, fg_color="transparent")
        button_container.pack(pady=10)

        # 버튼들
        self.upload_scan_btn = ctk.CTkButton(
            button_container,
            text="문서 업로드 및 검사",
            command=self.upload_and_scan_files,
            font=ctk.CTkFont(size=14),
            height=40,
            width=150,
            corner_radius=20
        )
        self.upload_scan_btn.pack(side="left", padx=10)

        self.sanitize_btn = ctk.CTkButton(
            button_container,
            text="무해화 및 저장",
            command=self.start_sanitization,
            font=ctk.CTkFont(size=14),
            height=40,
            width=150,
            corner_radius=20
        )
        self.sanitize_btn.pack(side="left", padx=10)

        self.clear_btn = ctk.CTkButton(
            button_container,
            text="로그 초기화",
            command=self.clear_logs,
            font=ctk.CTkFont(size=14),
            height=40,
            width=150,
            corner_radius=20,
            fg_color="#dc3545",
            hover_color="#c82333"
        )
        self.clear_btn.pack(side="left", padx=10)

        self.download_history_btn = ctk.CTkButton(
            button_container,
            text="내역 다운로드",
            command=self.download_sanitization_history,
            font=ctk.CTkFont(size=14),
            height=40,
            width=150,
            corner_radius=20,
            fg_color="#28a745",
            hover_color="#218838"
        )
        self.download_history_btn.pack(side="left", padx=10)

        # 시스템 로그 영역
        log_frame = ctk.CTkFrame(self.tab_process, corner_radius=10)
        log_frame.pack(fill="both", expand=True, padx=20, pady=5)

        log_label = ctk.CTkLabel(log_frame, text="검사 프로그램 로그",
                                 font=ctk.CTkFont(size=14, weight="bold"))
        log_label.pack(pady=(10, 5))

        self.log_text = ctk.CTkTextbox(log_frame, height=120, corner_radius=8)
        self.log_text.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        # 히스토리 영역
        history_frame = ctk.CTkFrame(self.tab_process, corner_radius=10)
        history_frame.pack(fill="both", expand=True, padx=20, pady=(5, 15))

        history_label = ctk.CTkLabel(history_frame, text="탐지/무해화 내역 히스토리",
                                     font=ctk.CTkFont(size=14, weight="bold"))
        history_label.pack(pady=(10, 5))

        self.history_text = ctk.CTkTextbox(history_frame, height=200, corner_radius=8)
        self.history_text.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    def create_model_tab(self):
        """모델 정보 탭 UI (가운데 정렬 적용)"""
        # 모델 상태 프레임
        status_frame = ctk.CTkFrame(self.tab_model, corner_radius=10)
        status_frame.pack(fill="x", padx=20, pady=(15, 5))

        status_label = ctk.CTkLabel(status_frame, text="AI 모델 관리",
                                    font=ctk.CTkFont(size=18, weight="bold"))
        status_label.pack(pady=(10, 5))

        # 서버 연결 상태 표시
        self.server_status_label = ctk.CTkLabel(
            status_frame,
            text="내장 서버 초기화 중...",
            font=ctk.CTkFont(size=12),
            text_color="#FFA500"
        )
        self.server_status_label.pack(pady=(0, 10))

        # <<< 변경된 부분 시작 (가운데 정렬을 위한 레이아웃 수정) >>>
        # --- 샘플 수량 입력 UI ---
        # pack()을 사용하여 가운데 정렬될 컨테이너 프레임
        retrain_options_container = ctk.CTkFrame(status_frame, fg_color="transparent")
        retrain_options_container.pack(pady=10)

        # grid()를 사용하여 라벨과 입력창을 깔끔하게 정렬할 내부 프레임
        retrain_options_grid = ctk.CTkFrame(retrain_options_container, fg_color="transparent")
        retrain_options_grid.pack()

        # 악성 샘플 입력
        malware_label = ctk.CTkLabel(retrain_options_grid, text="악성 샘플 수:")
        malware_label.grid(row=0, column=0, padx=(0, 10), pady=5, sticky="e")
        self.malware_entry = ctk.CTkEntry(retrain_options_grid, width=150)
        self.malware_entry.insert(0, "200")
        self.malware_entry.grid(row=0, column=1, padx=(0, 20), pady=5)

        # 정상 샘플 입력
        clean_label = ctk.CTkLabel(retrain_options_grid, text="정상 샘플 수:")
        clean_label.grid(row=1, column=0, padx=(0, 10), pady=5, sticky="e")
        self.clean_entry = ctk.CTkEntry(retrain_options_grid, width=150)
        self.clean_entry.insert(0, "120")
        self.clean_entry.grid(row=1, column=1, padx=(0, 20), pady=5)

        # 버튼 컨테이너 (가운데 정렬용)
        btn_container = ctk.CTkFrame(status_frame, fg_color="transparent")
        btn_container.pack(pady=(10, 20))
        # <<< 변경된 부분 끝 >>>

        self.info_btn = ctk.CTkButton(
            btn_container,
            text="모델 정보",
            command=self.show_model_info,
            font=ctk.CTkFont(size=14),
            height=40,
            width=150,
            corner_radius=20
        )
        self.info_btn.pack(side="left", padx=10)

        # 모델 재훈련 버튼
        self.retrain_btn = ctk.CTkButton(
            btn_container,
            text="모델 재훈련",
            command=self.retrain_model_locally,
            font=ctk.CTkFont(size=14),
            height=40,
            width=150,
            corner_radius=20,
            fg_color=["#3B8ED0", "#1F6AA5"],
            hover_color=["#36719F", "#144870"]
        )
        self.retrain_btn.pack(side="left", padx=10)

        # 모델 관리 로그 영역
        model_log_frame = ctk.CTkFrame(self.tab_model, corner_radius=10)
        model_log_frame.pack(fill="both", expand=True, padx=20, pady=(5, 15))

        model_log_label = ctk.CTkLabel(model_log_frame, text="모델 관리 로그",
                                       font=ctk.CTkFont(size=14, weight="bold"))
        model_log_label.pack(pady=(10, 5))

        self.model_log_text = ctk.CTkTextbox(model_log_frame, corner_radius=8)
        self.model_log_text.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    def initialize_system(self):
        """시스템 초기화 - 내장 서버 시작"""

        def init_thread():
            try:
                self.model_log_append("시스템 초기화 시작")

                # 내장 서버 시작
                self.embedded_server.start_server()

                # 모델 상태 업데이트
                self.update_model_status()

                # API 상태 확인 (VirusTotal 포함)
                self.check_api_status()

                self.model_log_append("시스템 초기화 완료")

            except Exception as e:
                self.model_log_append(f"시스템 초기화 오류: {str(e)}")
                self.update_server_status("시스템 초기화 실패", "#FF0000")

        thread = threading.Thread(target=init_thread, daemon=True)
        thread.start()

    def check_api_status(self):
        """API 상태 확인 (VirusTotal 문제 해결)"""
        try:
            # VirusTotal 체커 생성 및 테스트
            if self.virustotal_checker and self.virustotal_checker.is_available():
                if self.virustotal_checker.test_connection():
                    self.model_log_append("VirusTotal API 연결 성공")
                else:
                    self.model_log_append("VirusTotal API 연결 실패 - 키 확인 필요")
            else:
                self.model_log_append("VirusTotal API 키가 설정되지 않음")

            # 다른 API들도 확인
            from utils.api_client import APIClient
            api_client = APIClient()

            if api_client.test_malware_bazaar_connection():
                self.model_log_append("MalwareBazaar API 연결 성공")
            else:
                self.model_log_append("MalwareBazaar API 연결 실패")

            if api_client.test_triage_connection():
                self.model_log_append("Tria.ge API 연결 성공")
            else:
                self.model_log_append("Tria.ge API 연결 실패")

        except Exception as e:
            self.model_log_append(f"API 상태 확인 오류: {e}")

    def update_server_status(self, message, color):
        """서버 상태 업데이트"""
        self.server_status_label.configure(text=message, text_color=color)
        if "연결됨" in message:
            self.retrain_btn.configure(state="normal")
        else:
            self.retrain_btn.configure(state="disabled")

    def download_sanitization_history(self):
        """무해화 내역을 txt 파일로 다운로드"""
        if not self.sanitization_history:
            messagebox.showwarning("경고", "다운로드할 무해화 내역이 없습니다.")
            return

        try:
            from tkinter import filedialog
            file_path = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("텍스트 파일", "*.txt"), ("모든 파일", "*.*")],
                title="무해화 내역 저장"
            )

            if file_path:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write("=== 문서형 악성코드 무해화 내역 ===\n\n")
                    for entry in self.sanitization_history:
                        f.write(f"시간: {entry['timestamp']}\n")
                        f.write(f"원본 파일: {entry['original_file']}\n")
                        f.write(f"파일 유형: {entry['file_type']}\n")
                        f.write(f"무해화 결과: {entry['result']}\n")
                        f.write(f"저장 위치: {entry['clean_file']}\n")
                        f.write(f"제거된 요소: {', '.join(entry['removed_elements'])}\n")
                        f.write("-" * 50 + "\n\n")

                messagebox.showinfo("완료", f"무해화 내역이 저장되었습니다:\n{file_path}")

        except Exception as e:
            messagebox.showerror("오류", f"내역 저장 중 오류가 발생했습니다:\n{str(e)}")

    def update_file_list(self):
        """파일 리스트 UI 업데이트"""
        # 기존 위젯들 제거
        for widget in self.file_list_frame.winfo_children():
            widget.destroy()

        # 새 파일 목록 표시
        for i, file_path in enumerate(self.uploaded_files):
            file_name = os.path.basename(file_path)
            file_item = ctk.CTkLabel(
                self.file_list_frame,
                text=f"{i + 1}. {file_name}",
                font=ctk.CTkFont(size=12),
                anchor="w"
            )
            file_item.pack(fill="x", padx=5, pady=2)

    def log_append(self, text):
        """로그에 텍스트 추가"""
        timestamp = time.strftime("[%H:%M:%S] ")
        self.log_text.insert("end", timestamp + text + "\n")
        self.log_text.see("end")
        self.root.update()

    def history_append(self, text):
        """히스토리에 텍스트 추가"""
        timestamp = time.strftime("[%H:%M:%S] ")
        self.history_text.insert("end", timestamp + text + "\n")
        self.history_text.see("end")
        self.root.update()

    def model_log_append(self, text):
        """모델 로그에 텍스트 추가"""
        timestamp = time.strftime("[%H:%M:%S] ")
        self.model_log_text.insert("end", timestamp + text + "\n")
        self.model_log_text.see("end")
        self.root.update()

    def clear_logs(self):
        """로그 초기화"""
        self.log_text.delete("1.0", "end")
        self.history_text.delete("1.0", "end")
        self.model_log_text.delete("1.0", "end")
        self.log_append("검사 프로그램 로그가 초기화되었습니다.")
        self.model_log_append("모델 관리 로그가 초기화되었습니다.")

    def update_model_status(self):
        """모델 상태 업데이트"""
        if self.model_manager.is_model_available():
            if self.model_manager.load_model():
                self.upload_scan_btn.configure(state="normal")
            else:
                self.upload_scan_btn.configure(state="disabled")
        else:
            self.upload_scan_btn.configure(state="disabled")

    def upload_and_scan_files(self):
        """파일 업로드 후 즉시 검사"""
        files = filedialog.askopenfilenames(
            title="무해화할 문서 선택",
            filetypes=[
                ("지원 문서 형식", "*.docx *.docm *.xlsx *.xlsm *.pptx *.pptm *.pdf *.hwp *.hwpx *.hwpml"),
                ("모든 파일", "*.*")
            ]
        )

        if not files:
            return

        self.uploaded_files.clear()
        self.uploaded_files.extend(files)
        self.update_file_list()

        self.log_append(f"{len(files)}개 파일이 업로드되어 검사를 시작합니다.")
        self.ai_scan_threats()

    def create_progress_window(self, title, message):
        """진행률 윈도우 생성"""
        progress_window = ctk.CTkToplevel(self.root)
        progress_window.title(title)
        progress_window.geometry("400x150")
        progress_window.resizable(False, False)
        progress_window.transient(self.root)
        progress_window.grab_set()

        # 중앙 정렬
        progress_window.lift()
        progress_window.focus()

        progress_label = ctk.CTkLabel(
            progress_window,
            text=message,
            font=ctk.CTkFont(size=14),
            wraplength=350
        )
        progress_label.pack(pady=30)

        progress_bar = ctk.CTkProgressBar(progress_window, width=300)
        progress_bar.pack(pady=10)
        progress_bar.set(0)
        progress_bar.start()

        return progress_window, progress_bar

    def ai_scan_threats(self):
        """AI 모델 + 룰 기반 + VirusTotal 통합 탐지 (수정됨)"""
        if not self.uploaded_files:
            messagebox.showwarning("경고", "먼저 스캔할 파일을 선택하세요.")
            return

        self.log_text.delete("1.0", "end")
        self.history_text.delete("1.0", "end")

        progress_window, progress_bar = self.create_progress_window(
            "통합 악성코드 탐지",
            "AI + 룰 기반 + VirusTotal 통합 스캔 중...\n잠시만 기다려주세요."
        )

        # VirusTotal 상태 확인 (수정됨)
        virustotal_available = False
        if self.virustotal_checker:
            virustotal_available = self.virustotal_checker.is_available() and self.virustotal_checker.test_connection()

        def scan_thread():
            try:
                self.log_text.insert("end", "=== 통합 악성코드 탐지 시작 ===\n")
                if virustotal_available:
                    self.log_text.insert("end", "VirusTotal API 활성화됨\n")
                else:
                    self.log_text.insert("end", "VirusTotal API 비활성화 (의심 파일만 AI+룰 기반 검사)\n")
                self.log_text.insert("end", "=" * 50 + "\n")

                for i, file_path in enumerate(self.uploaded_files):
                    file_name = os.path.basename(file_path)
                    self.log_text.insert("end", f"\n[{i + 1}/{len(self.uploaded_files)}] 1차 분석: {file_name}\n")
                    self.root.update()

                    is_suspicious = False
                    ai_result = None
                    rule_threats = []

                    # AI 분석
                    if self.model_manager.is_model_available() and self.model_manager.load_model():
                        ai_result = self.model_manager.predict_file(file_path)

                        if "error" not in ai_result:
                            prediction = ai_result['prediction']
                            confidence = ai_result['confidence']
                            malware_prob = ai_result.get('malware_probability', 0)

                            self.log_text.insert("end", f"[AI] 예측: {prediction} (신뢰도: {confidence:.3f})\n")

                            if prediction == "악성":
                                is_suspicious = True
                                self.log_text.insert("end", f"      └ 악성 확률: {malware_prob:.3f}\n")
                        else:
                            self.log_text.insert("end", f"[AI] 오류: {ai_result['error']}\n")

                    # 룰 기반 분석
                    ext = os.path.splitext(file_path)[1].lower()

                    try:
                        if ext in (".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm"):
                            if is_macro_present(file_path):
                                rule_threats.append("매크로 탐지")
                                is_suspicious = True

                        elif ext == ".pdf":
                            reader = PdfReader(file_path)
                            root_obj = reader.trailer.get("/Root", {})
                            if isinstance(root_obj, IndirectObject):
                                root_obj = root_obj.get_object()

                            found_keys = find_javascript_keys(root_obj)
                            if found_keys:
                                rule_threats.extend(found_keys)
                                is_suspicious = True

                        elif ext in (".hwp", ".hwpx", ".hwpml"):
                            with open(file_path, "rb") as f:
                                data = f.read()
                            for pattern in [b'Shell', b'cmd', b'urlmon', b'http', b'javascript']:
                                if pattern in data:
                                    rule_threats.append(pattern.decode())
                                    is_suspicious = True

                        if rule_threats:
                            self.log_text.insert("end", f"[룰] 탐지: {', '.join(rule_threats)}\n")

                    except Exception as e:
                        self.log_text.insert("end", f"[룰] 검사 오류: {str(e)}\n")

                    malware_type_info = "분류 안됨"
                    if is_suspicious:
                        try:
                            # MalwareClassifier를 사용해 악성코드 유형 분류
                            malware_type_info = self.malware_classifier.classify_malware(file_path)
                            self.log_text.insert("end", f"[분류] 악성코드 유형: {malware_type_info}\n")
                        except Exception as classify_error:
                            self.log_text.insert("end", f"[분류] 오류: {str(classify_error)}\n")

                    # VirusTotal 검증 (수정됨)
                    virustotal_result = None
                    final_verdict = "정상"

                    if is_suspicious and virustotal_available:
                        self.log_text.insert("end", f"[VT] 의심 파일 → VirusTotal 재검증 중...\n")
                        self.root.update()

                        try:
                            virustotal_result = self.virustotal_checker.comprehensive_check(file_path)

                            if "error" not in virustotal_result:
                                if virustotal_result.get("found"):
                                    malicious = virustotal_result.get('malicious', 0)
                                    suspicious_vt = virustotal_result.get('suspicious', 0)
                                    total = virustotal_result.get('total_engines', 0)

                                    if total > 0:
                                        detection_rate = (malicious + suspicious_vt) / total
                                        self.log_text.insert("end",
                                                             f"[VT] 탐지율: {malicious + suspicious_vt}/{total} ({detection_rate:.1%})\n")

                                        if malicious >= 5:
                                            final_verdict = "고위험 악성"
                                        elif malicious >= 2 or suspicious_vt >= 3:
                                            final_verdict = "의심"
                                        else:
                                            final_verdict = "낮은 위험"
                                    else:
                                        self.log_text.insert("end", f"[VT] 검사 결과 없음\n")
                                        final_verdict = "미확인"
                                else:
                                    self.log_text.insert("end", f"[VT] 데이터베이스에 없는 파일\n")
                                    final_verdict = "미확인"
                            else:
                                self.log_text.insert("end", f"[VT] 검사 실패: {virustotal_result['error']}\n")
                                final_verdict = "AI+룰 기반 의심"

                        except Exception as vt_error:
                            self.log_text.insert("end", f"[VT] 오류: {str(vt_error)}\n")
                            final_verdict = "AI+룰 기반 의심"

                    elif is_suspicious and not virustotal_available:
                        final_verdict = "AI+룰 기반 의심"

                    # 결과 정리
                    if final_verdict != "정상":
                        if final_verdict == "고위험 악성":
                            self.log_text.insert("end", f"[최종] 고위험 악성 파일 확인!\n")
                            self.history_text.insert("end", f"{file_name} (고위험 악성)\n")
                        elif final_verdict == "의심":
                            self.log_text.insert("end", f"[최종] 의심스러운 파일\n")
                            self.history_text.insert("end", f"{file_name} (의심)\n")
                        else:
                            self.log_text.insert("end", f"[최종] 주의 필요 ({final_verdict})\n")
                            self.history_text.insert("end", f"{file_name} ({final_verdict})\n")

                        self.history_text.insert("end", f"  └ 분류: {malware_type_info}\n")

                        if ai_result and ai_result.get('prediction') == "악성":
                            self.history_text.insert("end", f"  └ AI: 악성 예측 ({ai_result.get('confidence', 0):.3f})\n")

                        if rule_threats:
                            self.history_text.insert("end", f"  └ 룰: {', '.join(rule_threats)}\n")

                        if virustotal_result and "error" not in virustotal_result and virustotal_result.get("found"):
                            malicious = virustotal_result.get('malicious', 0)
                            total = virustotal_result.get('total_engines', 0)
                            if total > 0:
                                self.history_text.insert("end", f"  └ VT: {malicious}/{total}개 엔진 탐지\n")

                    else:
                        self.log_text.insert("end", f"[최종] 안전한 파일\n")

                    self.log_text.insert("end", "-" * 50 + "\n")
                    self.log_text.see("end")
                    self.root.update()

                    if is_suspicious and virustotal_available:
                        time.sleep(1)

                self.log_text.insert("end", "\n=== 통합 스캔 완료 ===\n")

            except Exception as e:
                self.log_text.insert("end", f"\n[오류] 스캔 중 오류: {str(e)}\n")
            finally:
                progress_bar.stop()
                progress_window.destroy()

        thread = threading.Thread(target=scan_thread)
        thread.daemon = True
        thread.start()

    def start_sanitization(self):
        """문서 무해화 및 clean 폴더에 저장"""
        if not self.uploaded_files:
            messagebox.showwarning("경고", "먼저 무해화할 파일을 선택하세요.")
            return

        self.log_append("=== 문서 무해화 시작 ===")

        for file_path in self.uploaded_files:
            ext = os.path.splitext(file_path)[1].lower()
            file_name = os.path.basename(file_path)
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

            try:
                self.log_append(f"[INFO] 문서 처리: {file_name}")

                removed_elements = []
                result_msg = ""
                clean_file = ""

                if ext in (".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm"):
                    clean_file, removed = remove_macro(file_path)
                    if removed:
                        removed_elements.append("vbaProject.bin (매크로)")
                        result_msg = "매크로 제거됨"
                        self.log_append(f"[완료] 매크로 제거 완료: → {os.path.basename(clean_file)}")
                        self.history_append(f"{file_name} -> [제거] 매크로 (vbaProject.bin)")
                    else:
                        result_msg = "제거할 매크로 없음"
                        self.log_append("[완료] 제거할 매크로가 없습니다.")

                elif ext == ".pdf":
                    clean_file, removed_keys = sanitize_pdf(file_path)
                    if removed_keys:
                        removed_elements.extend(removed_keys)
                        result_msg = "JavaScript 관련 요소 제거됨"
                        self.log_append(f"[완료] PDF 스크립트 요소 제거 완료: → {os.path.basename(clean_file)}")
                        self.history_append(f"{file_name} -> [제거] {', '.join(removed_keys)}")
                    else:
                        result_msg = "제거할 JavaScript 요소 없음"
                        self.log_append("[완료] 제거할 JavaScript 요소가 없습니다.")

                elif ext in (".hwp", ".hwpx", ".hwpml"):
                    clean_file, removed_strings = sanitize_hwp(file_path)
                    if removed_strings:
                        removed_elements.extend(removed_strings)
                        result_msg = "위험 의심 문자열 제거됨"
                        self.log_append(f"[완료] HWP 위험 의심 문자열 제거 완료: → {os.path.basename(clean_file)}")
                        self.history_append(f"{file_name} -> [제거] {', '.join(removed_strings)}")
                    else:
                        result_msg = "제거할 위험 의심 문자열 없음"
                        self.log_append("[완료] 제거할 위험 의심 문자열이 없습니다.")
                else:
                    result_msg = "지원되지 않는 파일 형식"
                    self.log_append("[오류] 지원되지 않는 파일 형식입니다")

                # 무해화 내역 저장
                if clean_file:
                    self.sanitization_history.append({
                        'timestamp': timestamp,
                        'original_file': file_name,
                        'file_type': ext,
                        'result': result_msg,
                        'clean_file': clean_file,
                        'removed_elements': removed_elements if removed_elements else ['없음']
                    })

                    # 정상 샘플을 서버에 저장
                    self._save_clean_sample_to_server(clean_file, original_name=file_name)

            except Exception as e:
                self.log_append(f"[오류] 처리 중 오류 발생: {str(e)}")

        self.log_append("=== 무해화 완료 ===")
        messagebox.showinfo("완료", "문서 무해화가 완료되었습니다!\n정리된 파일은 sample/clean 폴더에 저장되었습니다.")

    def _save_clean_sample_to_server(self, clean_file_path: str, original_name: str):
        """무해화된 파일을 정상 샘플로 서버에 저장"""
        try:
            import hashlib
            import shutil

            # 파일을 clear 폴더에 복사
            clean_samples_dir = config.DIRECTORIES['clean_samples']
            os.makedirs(clean_samples_dir, exist_ok=True)

            # 새 파일명 생성 (중복 방지)
            timestamp = int(time.time())
            file_ext = os.path.splitext(original_name)[1]
            new_filename = f"sanitized_{timestamp}_{original_name}"

            dest_path = os.path.join(clean_samples_dir, new_filename)
            shutil.copy2(clean_file_path, dest_path)

            # 해시 계산
            with open(dest_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()

            # RDS에 메타데이터 저장
            from utils import db, aws_helper

            # S3 업로드
            s3_key = None
            if config.USE_AWS:
                s3_key = aws_helper.upload_virus_sample(dest_path, file_hash)

            # RDS에 정상 샘플로 저장
            db.save_virus_sample(
                file_path=dest_path,
                file_hash=file_hash,
                is_malicious=False,  # 정상 파일
                source='sanitized_document',
                malware_family='clean_document',
                threat_category='clean',
                s3_key=s3_key
            )

            self.log_append(f"[서버] 정상 샘플로 저장: {new_filename}")

        except Exception as e:
            self.log_append(f"[서버] 정상 샘플 저장 실패: {e}")

    def retrain_model_locally(self):
        """GUI에서 입력받은 수량으로 로컬 모델 재훈련"""

        # 입력값 읽기 및 검증
        try:
            malware_target_count = int(self.malware_entry.get())
            clean_target_count = int(self.clean_entry.get())
            if malware_target_count < 10 or clean_target_count < 10:
                messagebox.showerror("입력 오류", "악성 및 정상 샘플 수는 최소 10 이상이어야 합니다.")
                return
        except ValueError:
            messagebox.showerror("입력 오류", "샘플 수량은 숫자로만 입력해주세요.")
            return

        def training_thread():
            try:
                self.model_log_append(
                    f"=== GUI 기반 모델 재훈련 시작 (목표: 악성 {malware_target_count}, 정상 {clean_target_count}) ===")
                self.model_log_append("1단계: 새로운 악성코드 샘플 수집 중...")

                from utils.api_client import collect_training_data_with_progress

                def progress_callback(message):
                    self.model_log_append(f"[수집] {message}")
                    self.root.update()

                try:
                    malware_files, clean_files = collect_training_data_with_progress(
                        malware_count=malware_target_count,
                        clean_count=clean_target_count,
                        progress_callback=progress_callback
                    )
                    self.model_log_append(f"수집 완료: 악성 {len(malware_files)}개, 정상 {len(clean_files)}개")
                except Exception as collect_error:
                    self.model_log_append(f"샘플 수집 실패: {collect_error}")
                    return

                self.model_log_append("2단계: AI 모델 훈련 중...")

                from utils.model_trainer import ModelTrainer
                trainer = ModelTrainer()
                success = trainer.train_model()

                if success:
                    self.model_log_append("로컬 모델 훈련 성공!")
                    try:
                        with open("models/model_meta.json") as f:
                            meta = json.load(f)
                        self.model_log_append("--- 훈련 결과 ---")
                        self.model_log_append(f"정확도: {meta.get('accuracy', 0):.3f}")
                        self.model_log_append(
                            f"악성 샘플: {meta.get('malware_samples', 0)}개, 정상 샘플: {meta.get('clean_samples', 0)}개")
                    except Exception as meta_error:
                        self.model_log_append(f"메타 정보 로드 실패: {meta_error}")

                    if config.USE_AWS:
                        self.model_log_append("3단계: S3 업로드 중...")
                        try:
                            upload_files = [
                                ("models/ensemble_model.pkl", "models/ensemble_model.pkl"),
                                ("models/scaler.pkl", "models/scaler.pkl"),
                                ("models/model_meta.json", "models/model_meta.json")
                            ]
                            for local_path, s3_key in upload_files:
                                if os.path.exists(local_path) and aws_helper.upload(local_path, s3_key):
                                    self.model_log_append(f"업로드 완료: {s3_key}")
                        except Exception as aws_error:
                            self.model_log_append(f"AWS 업로드 실패: {aws_error}")
                else:
                    self.model_log_append("로컬 모델 훈련 실패")

                self.model_log_append("=== 모델 재훈련 완료 ===")
                self.update_model_status()
            except Exception as e:
                self.model_log_append(f"재훈련 오류: {str(e)}")

        thread = threading.Thread(target=training_thread)
        thread.daemon = True
        thread.start()

    def show_model_info(self):
        """모델 정보 표시"""

        def info_thread():
            try:
                self.model_log_append("=== AI 모델 정보 조회 시작 ===")

                if config.USE_AWS:
                    self.model_log_append("AWS S3 모델 정보 확인 중...")
                    s3_info = get_s3_model_info("models/ensemble_model.pkl")

                    if "error" not in s3_info:
                        self.model_log_append("--- S3 모델 메타 정보 ---")
                        self.model_log_append(f"업로드 시각: {s3_info['last_modified']}")
                        self.model_log_append(f"SHA256 해시: {s3_info['sha256'][:32]}...")
                        self.model_log_append(f"S3 모델 크기: {s3_info['size_mb']} MB")

                        meta = s3_info.get("meta", {})
                        if meta and "error" not in meta:
                            self.model_log_append("--- S3 모델 학습 정보 ---")
                            self.model_log_append(f"악성 샘플: {meta['malware_samples']}개")
                            self.model_log_append(f"정상 샘플: {meta['clean_samples']}개")
                            self.model_log_append(f"총 샘플: {meta['total_samples']}개")
                            self.model_log_append(f"정확도: {meta.get('accuracy', 0):.3f}")

                            if 'test_accuracy' in meta:
                                self.model_log_append(f"테스트 정확도: {meta['test_accuracy']:.3f}")
                            if 'cv_accuracy' in meta:
                                self.model_log_append(f"CV 정확도: {meta['cv_accuracy']:.3f}")
                            if 'precision' in meta:
                                self.model_log_append(f"정밀도: {meta['precision']:.3f}")
                            if 'recall' in meta:
                                self.model_log_append(f"재현율: {meta['recall']:.3f}")
                            if 'f1_score' in meta:
                                self.model_log_append(f"F1-점수: {meta['f1_score']:.3f}")

                            self.model_log_append(f"훈련 시각: {meta['trained_at']}")
                            self.model_log_append(f"모델 버전: {meta['model_version']}")

                            # 데이터 균형 정보
                            if 'data_balancing' in meta:
                                self.model_log_append(f"데이터 균형 조정: {meta['data_balancing']}")
                        else:
                            self.model_log_append("model_meta.json 없음 또는 파싱 실패")
                    else:
                        self.model_log_append(f"S3 오류: {s3_info['error']}")

                else:
                    self.model_log_append("USE_AWS=false → 로컬 정보만 조회")

                    if os.path.exists("models/ensemble_model.pkl"):
                        model_size = os.path.getsize("models/ensemble_model.pkl") / (1024 * 1024)
                        self.model_log_append(f"로컬 모델 크기: {model_size:.2f} MB")

                        if os.path.exists("models/model_meta.json"):
                            import json
                            with open("models/model_meta.json") as f:
                                meta = json.load(f)
                            self.model_log_append("--- 로컬 모델 학습 정보 ---")
                            self.model_log_append(f"정확도: {meta.get('accuracy', 0):.3f}")

                            if 'test_accuracy' in meta:
                                self.model_log_append(f"테스트 정확도: {meta['test_accuracy']:.3f}")
                            if 'cv_accuracy' in meta:
                                self.model_log_append(f"CV 정확도: {meta['cv_accuracy']:.3f}")
                            if 'precision' in meta:
                                self.model_log_append(f"정밀도: {meta['precision']:.3f}")
                            if 'recall' in meta:
                                self.model_log_append(f"재현율: {meta['recall']:.3f}")
                            if 'f1_score' in meta:
                                self.model_log_append(f"F1-점수: {meta['f1_score']:.3f}")

                            self.model_log_append(f"총 샘플: {meta.get('total_samples', 0)}개")
                            self.model_log_append(f"악성 샘플: {meta.get('malware_samples', 0)}개")
                            self.model_log_append(f"정상 샘플: {meta.get('clean_samples', 0)}개")
                            self.model_log_append(f"마지막 훈련 시각: {meta.get('trained_at', 'N/A')}")
                            self.model_log_append(f"모델 버전: {meta.get('model_version', '1.0')}")
                        else:
                            self.model_log_append("로컬 모델은 존재하나 메타 정보가 없습니다.")
                    else:
                        self.model_log_append("로컬 모델 파일 없음")

                self.model_log_append("=== 모델 정보 조회 완료 ===")

            except Exception as e:
                self.model_log_append(f"정보 조회 오류: {str(e)}")

        thread = threading.Thread(target=info_thread)
        thread.daemon = True
        thread.start()

    def run(self):
        """애플리케이션 실행"""
        self.root.mainloop()


if __name__ == "__main__":
    app = DocSanitizerApp()
    app.run()