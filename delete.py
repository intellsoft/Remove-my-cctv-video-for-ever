import sys
import os
import subprocess
import platform
import psutil

# برای بررسی دسترسی ادمین
if platform.system() == "Windows":
    import ctypes

from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QLabel,
    QFileDialog, QListWidget, QMessageBox, QComboBox, QTextEdit,
    QProgressBar, QHBoxLayout, QListWidgetItem, QDialog, QDialogButtonBox, QStyle
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QIcon

# --- استایل شیت برای زیباسازی برنامه ---
STYLESHEET = """
QWidget {
    background-color: #2c3e50;
    color: #ecf0f1;
    font-family: 'Segoe UI', Arial, sans-serif;
    font-size: 10pt;
}
QPushButton {
    background-color: #3498db;
    color: white;
    border: none;
    padding: 8px 16px;
    border-radius: 4px;
}
QPushButton:hover {
    background-color: #2980b9;
}
QPushButton:disabled {
    background-color: #95a5a6;
    color: #bdc3c7;
}
QListWidget {
    background-color: #34495e;
    border: 1px solid #2c3e50;
    border-radius: 4px;
    padding: 5px;
}
QListWidget::item:selected {
    background-color: #3498db;
    color: white;
}
QComboBox {
    border: 1px solid #3498db;
    border-radius: 4px;
    padding: 5px;
}
QComboBox::drop-down {
    border: none;
}
QTextEdit {
    background-color: #34495e;
    border: 1px solid #2c3e50;
    border-radius: 4px;
}
QProgressBar {
    border: 1px solid #2c3e50;
    border-radius: 4px;
    text-align: center;
    background-color: #34495e;
}
QProgressBar::chunk {
    background-color: #27ae60;
    border-radius: 3px;
}
QLabel#credit_label {
    color: #95a5a6;
    font-size: 8pt;
}
"""

# ثابت‌ها برای تعریف متدهای حذف
SECURE_METHODS = {
    "Simple Overwrite (1-pass)": {
        "passes": 1,
        "description": "یک‌بار بازنویسی با داده‌های تصادفی. سریع اما با امنیت پایه.",
        "strength": "پایین"
    },
    "NIST 800-88 (3-pass)": {
        "passes": 3,
        "description": "سه‌مرحله‌ای با بازنویسی تصادفی. استاندارد امنیتی معتبر.",
        "strength": "بالا"
    },
    "Gutmann (35-pass)": {
        "passes": 35,
        "description": "۳۵ مرحله بازنویسی با الگوهای مختلف. امنیت فوق‌العاده بالا اما بسیار کند.",
        "strength": "بسیار بالا"
    }
}

def is_admin():
    """بررسی می‌کند که آیا اسکریپت با دسترسی ادمین اجرا شده است یا خیر."""
    try:
        if platform.system() == "Windows":
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else: # for Linux and macOS
            return os.geteuid() == 0
    except Exception:
        return False

class EraseThread(QThread):
    """تردی برای انجام عملیات حذف به صورت غیرهمزمان."""
    progress = pyqtSignal(str, int)
    finished_report = pyqtSignal(list, list)
    
    def __init__(self, files_to_erase, passes):
        super().__init__()
        self.files_to_erase = files_to_erase
        self.passes = passes
        self.running = True
        self.successful_deletions = []
        self.failed_deletions = []

    def stop(self):
        self.running = False
        self.progress.emit("عملیات لغو شد...", 100)

    def run(self):
        total_items = len(self.files_to_erase)
        for i, path in enumerate(self.files_to_erase):
            if not self.running: break
            
            self.progress.emit(f"درحال پردازش: {os.path.basename(path)}", int((i / total_items) * 100))

            if os.path.isfile(path):
                self.secure_delete_file(path)
            elif os.path.isdir(path):
                for root, dirs, files in os.walk(path, topdown=False):
                    if not self.running: break
                    for name in files:
                        if not self.running: break
                        file_path = os.path.join(root, name)
                        self.secure_delete_file(file_path)
                    for name in dirs:
                        if not self.running: break
                        dir_path = os.path.join(root, name)
                        try:
                            os.rmdir(dir_path)
                            self.successful_deletions.append(f"{dir_path} (پوشه)")
                        except OSError as e:
                            self.failed_deletions.append(f"{dir_path} (پوشه): {e}")
                if self.running:
                    try:
                        os.rmdir(path)
                        self.successful_deletions.append(f"{path} (پوشه اصلی)")
                    except OSError: pass

        if self.running:
            self.progress.emit("عملیات کامل شد.", 100)
        self.finished_report.emit(self.successful_deletions, self.failed_deletions)

    def secure_delete_file(self, filepath):
        if not self.running: return
        try:
            with open(filepath, 'rb+') as f:
                size = os.path.getsize(filepath)
                for _ in range(self.passes):
                    if not self.running: return
                    f.seek(0)
                    f.write(os.urandom(size))
                    f.flush()
            
            os.remove(filepath)
            self.successful_deletions.append(filepath)
        except Exception as e:
            self.failed_deletions.append(f"{filepath}: {e}")

class SecureEraser(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("پاک‌سازی ایمن اطلاعات")
        self.setGeometry(200, 200, 700, 580)
        self.thread = None
        self.init_ui()
        self.check_permissions()
        self.setStyleSheet(STYLESHEET)

    def init_ui(self):
        self.layout = QVBoxLayout()
        self.layout.setSpacing(10)
        self.layout.setContentsMargins(15, 15, 15, 15)

        select_layout = QHBoxLayout()
        self.select_file_btn = QPushButton(" انتخاب فایل‌ها")
        self.select_file_btn.setIcon(self.style().standardIcon(QStyle.SP_FileIcon))
        self.select_file_btn.clicked.connect(self.select_files)
        select_layout.addWidget(self.select_file_btn)
        
        self.select_folder_btn = QPushButton(" انتخاب پوشه")
        self.select_folder_btn.setIcon(self.style().standardIcon(QStyle.SP_DirIcon))
        self.select_folder_btn.clicked.connect(self.select_folder)
        select_layout.addWidget(self.select_folder_btn)
        self.layout.addLayout(select_layout)

        self.file_list = QListWidget()
        self.file_list.setSelectionMode(QListWidget.ExtendedSelection)
        self.file_list.setAcceptDrops(True)
        self.file_list.dragEnterEvent = self.drag_enter_event
        self.file_list.dropEvent = self.drop_event
        self.layout.addWidget(self.file_list)
        
        self.remove_selected_btn = QPushButton(" حذف مورد از لیست")
        self.remove_selected_btn.setIcon(self.style().standardIcon(QStyle.SP_DialogDiscardButton))
        self.remove_selected_btn.clicked.connect(self.remove_selected_from_list)
        self.layout.addWidget(self.remove_selected_btn)
        
        self.detect_partitions_btn = QPushButton(" شناسایی پارتیشن‌ها")
        self.detect_partitions_btn.setIcon(self.style().standardIcon(QStyle.SP_DriveHDIcon))
        self.detect_partitions_btn.clicked.connect(self.detect_partitions)
        self.layout.addWidget(self.detect_partitions_btn)

        self.method_combo = QComboBox()
        self.method_combo.addItems(SECURE_METHODS.keys())
        self.method_combo.currentTextChanged.connect(self.show_method_info)
        self.layout.addWidget(self.method_combo)

        self.method_info = QTextEdit()
        self.method_info.setReadOnly(True)
        self.method_info.setMaximumHeight(70)
        self.layout.addWidget(self.method_info)

        action_layout = QHBoxLayout()
        self.erase_btn = QPushButton(" شروع پاک‌سازی ایمن")
        self.erase_btn.setIcon(self.style().standardIcon(QStyle.SP_TrashIcon))
        self.erase_btn.setStyleSheet("background-color: #c0392b;")
        self.erase_btn.clicked.connect(self.start_erasure)
        action_layout.addWidget(self.erase_btn)

        self.cancel_btn = QPushButton(" لغو عملیات")
        self.cancel_btn.setIcon(self.style().standardIcon(QStyle.SP_DialogCancelButton))
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.clicked.connect(self.cancel_erasure)
        action_layout.addWidget(self.cancel_btn)
        self.layout.addLayout(action_layout)

        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(False)
        self.layout.addWidget(self.progress_bar)

        self.status_label = QLabel("برای شروع، فایل یا پوشه‌ای را انتخاب کنید.")
        self.status_label.setAlignment(Qt.AlignCenter)
        self.layout.addWidget(self.status_label)
        
        credit_label = QLabel("برنامه نویس : محمدعلی عباسپور <a href='https://intellsoft.ir' style='color: #3498db; text-decoration: none;'>intellsoft.ir</a>")
        credit_label.setObjectName("credit_label")
        credit_label.setTextFormat(Qt.RichText)
        credit_label.setTextInteractionFlags(Qt.TextBrowserInteraction)
        credit_label.setOpenExternalLinks(True)
        credit_label.setAlignment(Qt.AlignCenter)
        self.layout.addWidget(credit_label)
        
        self.setLayout(self.layout)
        self.show_method_info()

    def check_permissions(self):
        if not is_admin():
            QMessageBox.warning(self, "هشدار دسترسی", 
                                "برنامه با دسترسی عادی اجرا شده است.\n"
                                "برای عملکرد کامل، به خصوص برای شناسایی و حذف درایوها، "
                                "توصیه می‌شود برنامه را با دسترسی مدیر (Run as Administrator) اجرا کنید.")

    def drag_enter_event(self, event):
        if event.mimeData().hasUrls(): event.acceptProposedAction()

    def drop_event(self, event):
        for url in event.mimeData().urls():
            path = url.toLocalFile()
            if os.path.exists(path): self.file_list.addItem(path)

    def select_files(self):
        files, _ = QFileDialog.getOpenFileNames(self, "انتخاب فایل‌ها برای حذف")
        if files:
            for f in files: self.file_list.addItem(f)

    def select_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "انتخاب پوشه برای حذف")
        if folder: self.file_list.addItem(folder)

    def remove_selected_from_list(self):
        for item in self.file_list.selectedItems():
            self.file_list.takeItem(self.file_list.row(item))

    def show_method_info(self):
        method = self.method_combo.currentText()
        if method in SECURE_METHODS:
            info = SECURE_METHODS[method]
            self.method_info.setPlainText(f"توضیحات: {info['description']}\nقدرت حذف: {info['strength']}")

    def start_erasure(self):
        files = [self.file_list.item(i).text() for i in range(self.file_list.count())]
        if not files:
            QMessageBox.warning(self, "خطا", "هیچ موردی برای حذف انتخاب نشده است.")
            return

        reply = QMessageBox.question(self, "تأیید نهایی",
                                     f"شما در حال حذف دائمی {len(files)} مورد هستید.\n"
                                     "این عملیات **غیرقابل بازگشت** است. آیا مطمئن هستید؟",
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            method = self.method_combo.currentText()
            passes = SECURE_METHODS[method]['passes']
            self.set_ui_for_erasure(True)
            self.thread = EraseThread(files, passes)
            self.thread.progress.connect(self.update_progress)
            self.thread.finished_report.connect(self.erasure_finished)
            self.thread.finished.connect(lambda: self.set_ui_for_erasure(False))
            self.thread.start()

    def cancel_erasure(self):
        if self.thread and self.thread.isRunning():
            self.thread.stop()

    def update_progress(self, message, percent):
        self.progress_bar.setValue(percent)
        self.status_label.setText(message)

    def erasure_finished(self, successes, failures):
        self.file_list.clear()
        report_message = f"عملیات کامل شد.\n\nموارد موفق: {len(successes)}\nموارد ناموفق: {len(failures)}"
        if failures:
            report_message += "\n\nلیست خطاها:\n" + "\n".join(failures[:10])
        QMessageBox.information(self, "گزارش نهایی", report_message)
        self.status_label.setText("عملیات پایان یافت.")
    
    def set_ui_for_erasure(self, is_running):
        self.erase_btn.setEnabled(not is_running)
        self.cancel_btn.setEnabled(is_running)
        self.select_file_btn.setEnabled(not is_running)
        self.select_folder_btn.setEnabled(not is_running)
        self.detect_partitions_btn.setEnabled(not is_running)
        
    def detect_partitions(self):
        try:
            partitions = psutil.disk_partitions(all=False)
            if not partitions:
                QMessageBox.information(self, "اطلاع", "هیچ پارتیشن قابل دسترسی یافت نشد.")
                return

            dialog = DiskSelectionDialog(partitions, self)
            if dialog.exec_() == QDialog.Accepted:
                for path in dialog.get_selected_paths():
                    self.file_list.addItem(path)
        except Exception as e:
            QMessageBox.critical(self, "خطا", str(e))

class DiskSelectionDialog(QDialog):
    """دیالوگی برای انتخاب پارتیشن‌های استاندارد."""
    def __init__(self, partitions, parent=None):
        super().__init__(parent)
        self.setWindowTitle("انتخاب پارتیشن برای اضافه کردن به لیست")
        self.resize(600, 400)
        self.setStyleSheet(STYLESHEET)
        
        self.selected_paths = []
        layout = QVBoxLayout(self)
        self.list_widget = QListWidget()
        self.list_widget.setSelectionMode(QListWidget.ExtendedSelection)
        for p in partitions:
            try:
                usage = psutil.disk_usage(p.mountpoint)
                item_text = (f"{p.device} | مسیر: {p.mountpoint} | نوع: {p.fstype} | "
                             f"حجم: {usage.total / (1024**3):.2f} GB")
                item = QListWidgetItem(item_text)
                item.setData(Qt.UserRole, p.mountpoint)
                self.list_widget.addItem(item)
            except Exception: continue
        layout.addWidget(self.list_widget)
        
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.accept_selection)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

    def accept_selection(self):
        selected_items = self.list_widget.selectedItems()
        if selected_items:
            self.selected_paths = [item.data(Qt.UserRole) for item in selected_items]
            self.accept()
        else:
            QMessageBox.warning(self, "هشدار", "لطفاً موردی را انتخاب کنید.")

    def get_selected_paths(self):
        return self.selected_paths

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setFont(QFont("Segoe UI", 10))
    window = SecureEraser()
    window.show()
    sys.exit(app.exec_())
