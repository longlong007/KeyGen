#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import secrets
import string
import json
import os
import base64
from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import datetime
import threading
import time

DATA_FILE = "passwords.dat"
CLIPBOARD_CLEAR_DELAY = 30
SALT_FILE = "salt.bin"

# 安全相关常量
PBKDF2_ITERATIONS = 100000
ID_LENGTH = 8
MIN_PASSWORD_LENGTH = 8
DEFAULT_PASSWORD_LENGTH = 16
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_SECONDS = 30

class SecurePassManager:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("SecurePass Manager - 安全密码管理器")
        self.root.geometry("900x600")
        self.root.resizable(True, True)

        self.fernet = None
        self.passwords = []
        self._login_attempts = 0
        self._lockout_until = None
        self._clipboard_clear_job = None

        self._load_salt()
        self._show_login_window()

    def _load_salt(self):
        # 只在salt文件存在时加载，不存在时不创建
        # salt文件将在设置主密码成功后才创建
        if os.path.exists(SALT_FILE):
            with open(SALT_FILE, "rb") as f:
                self.salt = f.read()
        else:
            self.salt = None

    def _derive_key(self, password: str) -> bytes:
        if not self.salt:
            raise ValueError("Salt not initialized")
        return self._derive_key_with_salt(password, self.salt)

    def _derive_key_with_salt(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def _copy_to_clipboard(self, password: str, parent=None, message: str = "密码已复制到剪贴板"):
        """复制密码到剪贴板，并在指定时间后自动清除"""
        # 取消之前的清除任务
        if self._clipboard_clear_job:
            self._clipboard_clear_job.cancel()

        # 复制到剪贴板
        self.root.clipboard_clear()
        self.root.clipboard_append(password)

        # 显示提示
        messagebox.showinfo("成功", message, parent=parent)

        # 设置定时清除任务
        def clear_clipboard():
            try:
                current = self.root.clipboard_get()
                if current == password:
                    self.root.clipboard_clear()
            except tk.TclError:
                pass

        self._clipboard_clear_job = threading.Timer(CLIPBOARD_CLEAR_DELAY, clear_clipboard)
        self._clipboard_clear_job.daemon = True
        self._clipboard_clear_job.start()

    def _check_password_strength(self, password: str) -> str:
        """检查密码强度，返回错误信息字符串；密码合格时返回空字符串"""
        if len(password) < MIN_PASSWORD_LENGTH:
            return f"主密码至少需要 {MIN_PASSWORD_LENGTH} 位"
        has_upper = any(c in string.ascii_uppercase for c in password)
        has_lower = any(c in string.ascii_lowercase for c in password)
        has_digit = any(c in string.digits for c in password)
        missing = []
        if not has_upper:
            missing.append("大写字母")
        if not has_lower:
            missing.append("小写字母")
        if not has_digit:
            missing.append("数字")
        if missing:
            return f"主密码需要包含：{'、'.join(missing)}"
        return ""

    def _encrypt(self, data: str) -> str:
        if not self.fernet:
            raise RuntimeError("未初始化加密密钥，无法执行加密操作")
        return self.fernet.encrypt(data.encode()).decode()

    def _decrypt(self, data: str) -> str:
        if not self.fernet:
            raise RuntimeError("未初始化加密密钥，无法执行解密操作")
        return self.fernet.decrypt(data.encode()).decode()

    def _show_login_window(self):
        self.login_win = tk.Toplevel(self.root)
        self.login_win.title("登录 - SecurePass Manager")
        self.login_win.geometry("400x280")
        self.login_win.resizable(False, False)
        self.login_win.transient(self.root)
        self.login_win.grab_set()

        frame = ttk.Frame(self.login_win, padding="30")
        frame.pack(fill=tk.BOTH, expand=True)

        tk.Label(frame, text="SecurePass Manager").pack(pady=(0, 20))

        tk.Label(frame, text="请输入主密码:").pack(anchor=tk.W, pady=(10, 5))
        self.password_entry = ttk.Entry(frame, show="*", width=30)
        self.password_entry.pack(fill=tk.X, pady=(0, 15))
        self.password_entry.bind("<Return>", lambda e: self._try_login())

        self.confirm_label = tk.Label(frame, text="")
        self.confirm_label.pack(pady=(0, 10))

        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=15)

        ttk.Button(btn_frame, text="登录", command=self._try_login).pack(side=tk.LEFT, padx=10, ipadx=10, ipady=5)
        ttk.Button(btn_frame, text="首次设置", command=self._setup_master_password).pack(side=tk.LEFT, padx=10, ipadx=10, ipady=5)

        self.login_win.protocol("WM_DELETE_WINDOW", self._on_close)

    def _setup_master_password(self):
        # 如果salt文件已存在，说明已有主密码，禁止重复设置
        if os.path.exists(SALT_FILE):
            messagebox.showerror("错误", "主密码已设置，请登录", parent=self.login_win)
            return

        pwd = simpledialog.askstring(
            "设置主密码",
            f"请输入新主密码 (至少{MIN_PASSWORD_LENGTH}位，需包含大小写字母和数字):",
            show="*", parent=self.login_win
        )
        if not pwd:
            return

        strength_error = self._check_password_strength(pwd)
        if strength_error:
            messagebox.showerror("错误", strength_error, parent=self.login_win)
            return

        confirm = simpledialog.askstring("确认主密码", "请再次输入主密码:", show="*", parent=self.login_win)
        if confirm != pwd:
            messagebox.showerror("错误", "两次输入的密码不一致", parent=self.login_win)
            return

        # 生成并保存salt文件
        self.salt = os.urandom(16)
        with open(SALT_FILE, "wb") as f:
            f.write(self.salt)

        self.fernet = Fernet(self._derive_key(pwd))
        self._init_password_file()
        self._show_main_window()

    def _try_login(self):
        # 检查是否处于锁定状态
        if self._lockout_until:
            remaining = (self._lockout_until - datetime.datetime.now()).total_seconds()
            if remaining > 0:
                messagebox.showwarning(
                    "账户已锁定",
                    f"登录失败次数过多，请等待 {int(remaining)} 秒后重试",
                    parent=self.login_win
                )
                return
            else:
                self._lockout_until = None
                self._login_attempts = 0

        pwd = self.password_entry.get()
        if not pwd:
            messagebox.showwarning("警告", "请输入主密码", parent=self.login_win)
            return

        # 检查salt文件是否存在
        if not os.path.exists(SALT_FILE):
            messagebox.showinfo("提示", "未找到主密码，请先设置", parent=self.login_win)
            return

        if not os.path.exists(DATA_FILE):
            messagebox.showinfo("提示", "未找到密码文件，请先设置主密码", parent=self.login_win)
            return

        try:
            self.fernet = Fernet(self._derive_key(pwd))
            self._load_passwords()
            self._login_attempts = 0
            self._lockout_until = None
            # 不将明文密码存入实例变量，仅在需要时临时使用
            self._show_main_window()
        except (InvalidToken, json.JSONDecodeError):
            self.fernet = None
            self._login_attempts += 1
            remaining_attempts = MAX_LOGIN_ATTEMPTS - self._login_attempts
            if self._login_attempts >= MAX_LOGIN_ATTEMPTS:
                self._lockout_until = datetime.datetime.now() + datetime.timedelta(seconds=LOCKOUT_SECONDS)
                self._login_attempts = 0
                messagebox.showerror(
                    "错误",
                    f"主密码错误，已连续失败 {MAX_LOGIN_ATTEMPTS} 次，账户锁定 {LOCKOUT_SECONDS} 秒",
                    parent=self.login_win
                )
            else:
                messagebox.showerror(
                    "错误",
                    f"主密码错误或数据文件损坏，还可尝试 {remaining_attempts} 次",
                    parent=self.login_win
                )

    def _init_password_file(self):
        self.passwords = []
        self._save_passwords()

    def _load_passwords(self):
        if not os.path.exists(DATA_FILE):
            self.passwords = []
            return

        try:
            with open(DATA_FILE, "r", encoding="utf-8") as f:
                encrypted_data = f.read()
                if encrypted_data:
                    decrypted = self._decrypt(encrypted_data)
                    self.passwords = json.loads(decrypted)
                else:
                    self.passwords = []
        except OSError as e:
            messagebox.showwarning("警告", f"数据文件读取失败: {str(e)}", parent=self.root)
            self.passwords = []
        # InvalidToken 和 json.JSONDecodeError 不在此捕获，让其向上传播
        # 以便 _try_login 能够正确识别密码错误并阻止登录

    def _save_passwords(self):
        if not self.fernet:
            messagebox.showerror("错误", "未登录，无法保存", parent=self.root)
            return

        data = json.dumps(self.passwords, ensure_ascii=False, indent=2)
        encrypted = self._encrypt(data)

        # 原子写入：先写临时文件，再重命名
        temp_file = DATA_FILE + ".tmp"
        try:
            with open(temp_file, "w", encoding="utf-8") as f:
                f.write(encrypted)
            # 原子重命名覆盖原文件
            os.replace(temp_file, DATA_FILE)
        except OSError as e:
            messagebox.showerror("错误", f"保存失败: {str(e)}", parent=self.root)
            # 清理临时文件
            if os.path.exists(temp_file):
                try:
                    os.remove(temp_file)
                except OSError:
                    pass

    def _show_main_window(self):
        self.login_win.destroy()
        self.root.deiconify()
        self._create_ui()

    def _create_ui(self):
        toolbar = ttk.Frame(self.root)
        toolbar.pack(side=tk.TOP, fill=tk.X, padx=10, pady=10)

        ttk.Button(toolbar, text="生成密码", command=self._show_password_generator).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="添加记录", command=self._add_password_record).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="刷新", command=self._refresh_list).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="修改主密码", command=self._change_master_password).pack(side=tk.LEFT, padx=5)

        search_frame = ttk.Frame(toolbar)
        search_frame.pack(side=tk.RIGHT, padx=5)
        tk.Label(search_frame, text="搜索:").pack(side=tk.LEFT)
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", self._filter_passwords)
        ttk.Entry(search_frame, textvariable=self.search_var, width=20).pack(side=tk.LEFT, padx=5)

        list_frame = ttk.Frame(self.root)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        columns = ("account", "note", "created", "modified")
        self.tree = ttk.Treeview(list_frame, columns=columns, show="headings", selectmode="browse")

        self.tree.heading("account", text="账号/标题")
        self.tree.heading("note", text="备注")
        self.tree.heading("created", text="创建时间")
        self.tree.heading("modified", text="修改时间")

        self.tree.column("account", width=200)
        self.tree.column("note", width=250)
        self.tree.column("created", width=140)
        self.tree.column("modified", width=140)

        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.tree.bind("<Double-1>", self._on_double_click)
        self.tree.bind("<Button-3>", self._show_context_menu)

        self._refresh_list()

        bottom_frame = ttk.Frame(self.root)
        bottom_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=5)
        tk.Label(bottom_frame, text="双击查看密码 | 右键菜单编辑/删除").pack(side=tk.LEFT)

    def _refresh_list(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

        search_text = self.search_var.get().lower()

        for pwd in self.passwords:
            if search_text:
                if (search_text not in pwd.get("account", "").lower() and
                    search_text not in pwd.get("note", "").lower()):
                    continue

            created = pwd.get("created", "")
            modified = pwd.get("modified", "")
            self.tree.insert("", tk.END, values=(
                pwd.get("account", ""),
                pwd.get("note", ""),
                created,
                modified
            ), tags=(pwd.get("id", ""),))

    def _filter_passwords(self, *args):
        self._refresh_list()

    def _show_password_generator(self):
        win = tk.Toplevel(self.root)
        win.title("密码生成器")
        win.geometry("450x400")
        win.transient(self.root)
        win.grab_set()

        frame = ttk.Frame(win, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)

        tk.Label(frame, text="密码长度:").grid(row=0, column=0, sticky=tk.W, pady=10)
        length_var = tk.IntVar(value=16)
        ttk.Spinbox(frame, from_=8, to=64, textvariable=length_var, width=10).grid(row=0, column=1, sticky=tk.W, pady=10)

        upper_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(frame, text="大写字母 (A-Z)", variable=upper_var).grid(row=1, column=0, columnspan=2, sticky=tk.W, pady=5)

        lower_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(frame, text="小写字母 (a-z)", variable=lower_var).grid(row=2, column=0, columnspan=2, sticky=tk.W, pady=5)

        digit_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(frame, text="数字 (0-9)", variable=digit_var).grid(row=3, column=0, columnspan=2, sticky=tk.W, pady=5)

        special_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(frame, text="特殊字符 (!@#$%^&*)", variable=special_var).grid(row=4, column=0, columnspan=2, sticky=tk.W, pady=5)

        tk.Label(frame, text="生成的密码:").grid(row=5, column=0, sticky=tk.W, pady=(20, 5))
        result_var = tk.StringVar()
        result_entry = ttk.Entry(frame, textvariable=result_var, font=("Consolas", 12), width=35, state="readonly")
        result_entry.grid(row=6, column=0, columnspan=2, pady=(0, 10))

        def generate():
            length = length_var.get()
            charset = ""
            if upper_var.get():
                charset += string.ascii_uppercase
            if lower_var.get():
                charset += string.ascii_lowercase
            if digit_var.get():
                charset += string.digits
            if special_var.get():
                charset += "!@#$%^&*()_+-=[]{}|;:,.<>?"

            if not charset:
                messagebox.showwarning("警告", "请至少选择一种字符类型", parent=win)
                return

            password = ''.join(secrets.choice(charset) for _ in range(length))

            has_upper = any(c in string.ascii_uppercase for c in password)
            has_lower = any(c in string.ascii_lowercase for c in password)
            has_digit = any(c in string.digits for c in password)
            has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)

            if upper_var.get() and not has_upper:
                password = password[:-1] + secrets.choice(string.ascii_uppercase)
            if lower_var.get() and not has_lower:
                password = password[:-1] + secrets.choice(string.ascii_lowercase)
            if digit_var.get() and not has_digit:
                password = password[:-1] + secrets.choice(string.digits)
            if special_var.get() and not has_special:
                password = password[:-1] + secrets.choice("!@#$%^&*()_+-=[]{}|;:,.<>?")

            password = ''.join(secrets.choice(password) for _ in range(length))
            result_var.set(password)

        def copy_to_clipboard():
            pwd = result_var.get()
            if pwd:
                self._copy_to_clipboard(pwd, parent=win, message="密码已复制到剪贴板，30秒后将自动清除")

        ttk.Button(frame, text="生成密码", command=generate).grid(row=7, column=0, pady=10, sticky=tk.EW, padx=(0, 5))
        ttk.Button(frame, text="复制密码", command=copy_to_clipboard).grid(row=7, column=1, pady=10, sticky=tk.EW, padx=(5, 0))

        # 保存当前生成的密码，供按钮使用
        current_password = [None]

        def on_generate():
            generate()
            current_password[0] = result_var.get()

        def add_with_password():
            pwd = current_password[0] or result_var.get()
            if pwd:
                copy_to_clipboard()
                win.destroy()
                self._add_password_record(pwd)

        ttk.Button(frame, text="使用此密码添加记录", command=add_with_password).grid(row=8, column=0, columnspan=2, pady=10, sticky=tk.EW)

    def _add_password_record(self, prefill_password=None):
        win = tk.Toplevel(self.root)
        win.title("添加密码记录")
        win.geometry("450x350")
        win.transient(self.root)
        win.grab_set()

        frame = ttk.Frame(win, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)

        tk.Label(frame, text="账号/标题:").grid(row=0, column=0, sticky=tk.W, pady=10)
        account_entry = ttk.Entry(frame, width=35)
        account_entry.grid(row=0, column=1, pady=10)

        tk.Label(frame, text="密码:").grid(row=1, column=0, sticky=tk.W, pady=10)
        password_frame = ttk.Frame(frame)
        password_frame.grid(row=1, column=1, pady=10, sticky=tk.EW)

        # 创建两个 Entry，一个显示明文，一个显示掩码
        # 初始状态：显示掩码，隐藏明文
        password_entry_show = ttk.Entry(password_frame, width=25)
        password_entry_show.pack(side=tk.LEFT, padx=(0, 5))

        password_entry = ttk.Entry(password_frame, width=25, show="*")
        password_entry.pack(side=tk.LEFT, padx=(0, 5))

        ttk.Button(password_frame, text="生成", command=lambda: self._quick_generate(password_entry, password_entry_show)).pack(side=tk.LEFT, padx=5)

        show_var = tk.BooleanVar()
        def toggle_show():
            if show_var.get():
                # 勾选时显示明文
                password_entry.pack_forget()
                password_entry_show.pack(side=tk.LEFT, padx=(0, 5))
            else:
                # 未勾选时显示掩码
                password_entry_show.pack_forget()
                password_entry.pack(side=tk.LEFT, padx=(0, 5))
        ttk.Checkbutton(password_frame, text="显示", variable=show_var, command=toggle_show).pack(side=tk.LEFT)

        # 初始状态：显示掩码
        password_entry_show.pack_forget()

        if prefill_password:
            password_entry.insert(0, prefill_password)
            password_entry_show.insert(0, prefill_password)

        tk.Label(frame, text="备注:").grid(row=2, column=0, sticky=tk.NW, pady=10)
        note_text = tk.Text(frame, width=26, height=5)
        note_text.grid(row=2, column=1, pady=10)

        def save():
            account = account_entry.get().strip()
            password = password_entry.get()
            note = note_text.get("1.0", tk.END).strip()

            if not account:
                messagebox.showwarning("警告", "请输入账号/标题", parent=win)
                return
            if not password:
                messagebox.showwarning("警告", "请输入密码", parent=win)
                return

            now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            record = {
                "id": secrets.token_hex(8),
                "account": account,
                "password": password,
                "note": note,
                "created": now,
                "modified": now
            }

            self.passwords.append(record)
            self._save_passwords()
            self._refresh_list()
            win.destroy()

        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=3, column=0, columnspan=2, pady=20)
        ttk.Button(btn_frame, text="保存", command=save).pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_frame, text="取消", command=win.destroy).pack(side=tk.LEFT, padx=10)

    def _quick_generate(self, entry_hidden, entry_show=None):
        charset = string.ascii_letters + string.digits + "!@#$%^&*"
        password = ''.join(secrets.choice(charset) for _ in range(16))
        entry_hidden.delete(0, tk.END)
        entry_hidden.insert(0, password)
        if entry_show:
            entry_show.delete(0, tk.END)
            entry_show.insert(0, password)

    def _on_double_click(self, event):
        item = self.tree.selection()
        if not item:
            return
        item_id = self.tree.item(item[0])["tags"][0]
        self._show_password_detail(item_id)

    def _show_context_menu(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            menu = tk.Menu(self.root, tearoff=0)
            menu.add_command(label="查看密码", command=lambda: self._show_password_detail(self.tree.item(item)["tags"][0]))
            menu.add_command(label="编辑", command=lambda: self._edit_password_record(self.tree.item(item)["tags"][0]))
            menu.add_command(label="删除", command=lambda: self._delete_password_record(self.tree.item(item)["tags"][0]))
            menu.post(event.x_root, event.y_root)

    def _show_password_detail(self, record_id):
        record = next((p for p in self.passwords if p.get("id") == record_id), None)
        if not record:
            return

        win = tk.Toplevel(self.root)
        win.title(f"密码详情 - {record.get('account', '')}")
        win.geometry("450x300")
        win.transient(self.root)

        frame = ttk.Frame(win, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)

        tk.Label(frame, text="账号/标题:").grid(row=0, column=0, sticky=tk.NW, pady=10)
        tk.Label(frame, text=record.get("account", "")).grid(row=0, column=1, sticky=tk.NW, pady=10)

        tk.Label(frame, text="密码:").grid(row=1, column=0, sticky=tk.NW, pady=10)
        pwd_frame = ttk.Frame(frame)
        pwd_frame.grid(row=1, column=1, sticky=tk.NW, pady=10)

        # 保存原始密码
        original_password = record.get("password", "")

        # 创建两个 Entry，一个显示明文，一个显示掩码
        # 初始状态：显示掩码，隐藏明文
        pwd_entry_show = ttk.Entry(pwd_frame, width=25)
        pwd_entry_show.insert(0, original_password)
        pwd_entry_show.pack(side=tk.LEFT, padx=(0, 5))
        pwd_entry_show.pack_forget()  # 初始隐藏

        pwd_entry_hidden = ttk.Entry(pwd_frame, width=25, show="*")
        pwd_entry_hidden.insert(0, original_password)
        pwd_entry_hidden.pack(side=tk.LEFT, padx=(0, 5))

        show_var = tk.BooleanVar()
        def toggle_show():
            if show_var.get():
                pwd_entry_hidden.pack_forget()
                pwd_entry_show.pack(side=tk.LEFT, padx=(0, 5))
            else:
                pwd_entry_show.pack_forget()
                pwd_entry_hidden.pack(side=tk.LEFT, padx=(0, 5))
        ttk.Checkbutton(pwd_frame, text="显示", variable=show_var, command=toggle_show).pack(side=tk.LEFT, padx=5)
        ttk.Button(pwd_frame, text="复制", command=lambda: self._copy_to_clipboard(record.get("password", ""), parent=win, message="密码已复制到剪贴板，30秒后将自动清除")).pack(side=tk.LEFT, padx=5)

        tk.Label(frame, text="备注:").grid(row=2, column=0, sticky=tk.NW, pady=10)
        tk.Label(frame, text=record.get("note", "无") or "无").grid(row=2, column=1, sticky=tk.NW, pady=10, padx=10)

        tk.Label(frame, text=f"创建时间: {record.get('created', '')}").grid(row=3, column=0, columnspan=2, sticky=tk.W, pady=(20, 5))
        tk.Label(frame, text=f"修改时间: {record.get('modified', '')}").grid(row=4, column=0, columnspan=2, sticky=tk.W, pady=5)

        ttk.Button(frame, text="关闭", command=win.destroy).grid(row=5, column=0, columnspan=2, pady=20)

    def _edit_password_record(self, record_id):
        record = next((p for p in self.passwords if p.get("id") == record_id), None)
        if not record:
            return

        win = tk.Toplevel(self.root)
        win.title("编辑密码记录")
        win.geometry("450x350")
        win.transient(self.root)
        win.grab_set()

        frame = ttk.Frame(win, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)

        tk.Label(frame, text="账号/标题:").grid(row=0, column=0, sticky=tk.W, pady=10)
        account_entry = ttk.Entry(frame, width=35)
        account_entry.insert(0, record.get("account", ""))
        account_entry.grid(row=0, column=1, pady=10)

        tk.Label(frame, text="密码:").grid(row=1, column=0, sticky=tk.W, pady=10)
        password_entry = ttk.Entry(frame, width=35, show="*")
        password_entry.insert(0, record.get("password", ""))
        password_entry.grid(row=1, column=1, pady=10)

        tk.Label(frame, text="备注:").grid(row=2, column=0, sticky=tk.NW, pady=10)
        note_text = tk.Text(frame, width=26, height=5)
        note_text.insert("1.0", record.get("note", ""))
        note_text.grid(row=2, column=1, pady=10)

        def save():
            account = account_entry.get().strip()
            password = password_entry.get()
            note = note_text.get("1.0", tk.END).strip()

            if not account or not password:
                messagebox.showwarning("警告", "账号和密码不能为空", parent=win)
                return

            record["account"] = account
            record["password"] = password
            record["note"] = note
            record["modified"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            self._save_passwords()
            self._refresh_list()
            win.destroy()

        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=3, column=0, columnspan=2, pady=20)
        ttk.Button(btn_frame, text="保存", command=save).pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_frame, text="取消", command=win.destroy).pack(side=tk.LEFT, padx=10)

    def _delete_password_record(self, record_id):
        if not messagebox.askyesno("确认", "确定要删除这条密码记录吗？", parent=self.root):
            return

        self.passwords = [p for p in self.passwords if p.get("id") != record_id]
        self._save_passwords()
        self._refresh_list()

    def _change_master_password(self):
        # 验证当前密码
        current_pwd = simpledialog.askstring("修改主密码", "请输入当前主密码:", show="*", parent=self.root)
        if not current_pwd:
            return

        # 验证当前密码是否正确：用当前 salt 派生密钥后尝试解密实际数据文件
        try:
            test_fernet = Fernet(self._derive_key(current_pwd))
            with open(DATA_FILE, "r", encoding="utf-8") as f:
                encrypted_data = f.read()
            if encrypted_data:
                test_fernet.decrypt(encrypted_data.encode())
        except (InvalidToken, OSError, Exception):
            messagebox.showerror("错误", "当前主密码错误", parent=self.root)
            return

        # 输入新密码
        new_pwd = simpledialog.askstring(
            "修改主密码",
            f"请输入新主密码 (至少{MIN_PASSWORD_LENGTH}位，需包含大小写字母和数字):",
            show="*", parent=self.root
        )
        if not new_pwd:
            return

        strength_error = self._check_password_strength(new_pwd)
        if strength_error:
            messagebox.showerror("错误", strength_error, parent=self.root)
            return

        confirm = simpledialog.askstring("修改主密码", "请再次输入新主密码:", show="*", parent=self.root)
        if confirm != new_pwd:
            messagebox.showerror("错误", "两次输入的密码不一致", parent=self.root)
            return

        if not messagebox.askyesno("确认", "修改主密码将重新加密所有数据，是否继续？", parent=self.root):
            return

        # 事务性保护：先备份旧 salt，失败时回滚
        old_salt = self.salt
        old_fernet = self.fernet
        try:
            new_salt = os.urandom(16)
            new_fernet = Fernet(self._derive_key_with_salt(new_pwd, new_salt))

            # 先在内存中用新密钥重新加密所有数据，确认无误后再写入文件
            data_json = json.dumps(self.passwords, ensure_ascii=False, indent=2)
            new_encrypted = new_fernet.encrypt(data_json.encode()).decode()

            # 内存验证通过后，原子性地写入文件
            # 先写 salt
            salt_temp = SALT_FILE + ".tmp"
            with open(salt_temp, "wb") as f:
                f.write(new_salt)
            os.replace(salt_temp, SALT_FILE)

            # 再写数据文件（原子操作）
            data_temp = DATA_FILE + ".tmp"
            with open(data_temp, "w", encoding="utf-8") as f:
                f.write(new_encrypted)
            os.replace(data_temp, DATA_FILE)

            # 更新运行时状态
            self.salt = new_salt
            self.fernet = new_fernet

            messagebox.showinfo("成功", "主密码修改成功", parent=self.root)
        except Exception as e:
            # 回滚：恢复旧 salt 和 fernet（原子操作）
            self.salt = old_salt
            self.fernet = old_fernet
            try:
                salt_temp = SALT_FILE + ".tmp"
                with open(salt_temp, "wb") as f:
                    f.write(old_salt)
                os.replace(salt_temp, SALT_FILE)
            except OSError:
                pass
            messagebox.showerror("错误", f"修改失败，已回滚: {str(e)}", parent=self.root)

    def _on_close(self):
        # 清除剪贴板定时器
        if self._clipboard_clear_job:
            self._clipboard_clear_job.cancel()

        # 清除内存中的敏感数据
        self.passwords = []
        self.fernet = None
        self.salt = None

        self.root.quit()

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    app = SecurePassManager()
    app.run()
