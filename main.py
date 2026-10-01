import os
import json
import datetime
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
from scanner_core import extract_features, build_prompt, call_llm

def save_report(source: str, features: dict, analysis: dict) -> Path:
    output_dir = Path("output")
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    path = output_dir / f"report_{timestamp}.json"
    report = {"source": source, "scan_time": datetime.datetime.now().isoformat(),
              "features": features, "analysis": analysis}
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    # 同时生成 Markdown 报告
    md_path = output_dir / f"report_{timestamp}.md"
    md_lines = [f"# Web 漏洞分析报告\n\n**来源**: {source}\n**时间**: {report['scan_time']}\n"]
    if isinstance(analysis, list):
        md_lines.append(f"\n共发现 **{len(analysis)}** 个风险点：\n")
        for i, item in enumerate(analysis, 1):
            md_lines.append(f"## {i}. {item.get('vulnerability_type', '未知')} [{item.get('risk_level', '?')}]\n")
            md_lines.append(f"- **位置**: {item.get('location', 'N/A')}\n")
            md_lines.append(f"- **原因**: {item.get('reason', 'N/A')}\n")
            md_lines.append(f"- **修复**: {item.get('fix_suggestion', 'N/A')}\n")
    else:
        md_lines.append(f"\n{analysis}\n")
    md_path.write_text("\n".join(md_lines), encoding="utf-8")
    return path, md_path


class ScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("AI 辅助 Web 漏洞扫描器")
        self.root.geometry("750x550")

        # 文件路径
        frame_top = ttk.Frame(root, padding=10)
        frame_top.pack(fill="x")
        ttk.Label(frame_top, text="HTML 文件：").pack(side="left")
        self.path_var = tk.StringVar()
        self.path_entry = ttk.Entry(frame_top, textvariable=self.path_var, width=50)
        self.path_entry.pack(side="left", padx=5, fill="x", expand=True)
        ttk.Button(frame_top, text="浏览", command=self.browse_file).pack(side="left", padx=2)

        # 拖拽支持
        self.path_entry.bind("<Button-3>", self.show_context_menu)
        root.drop_target_register = None
        try:
            root.tk.call('package', 'require', 'tkdnd')
            root.tk.call('tkdnd::drop_target', 'register', self.path_entry, 'DND_Files')
            root.tk.call('tkdnd::bind', 'bind', self.path_entry, '<Drop:DND_Files>',
                         lambda e: self.path_var.set(e.data.strip('{}')))
        except Exception:
            pass  # tkdnd 没装就用浏览按钮

        # 按钮
        frame_btn = ttk.Frame(root, padding=10)
        frame_btn.pack(fill="x")
        self.btn = ttk.Button(frame_btn, text="开始分析", command=self.start_scan)
        self.btn.pack(side="left", padx=5)
        ttk.Button(frame_btn, text="打开输出目录", command=lambda: os.startfile("output")).pack(side="left", padx=5)

        # 状态 + 日志
        self.status_var = tk.StringVar(value="就绪 — 请选择 HTML 文件后点击「开始分析」")
        ttk.Label(root, textvariable=self.status_var, foreground="gray").pack(anchor="w", padx=10)

        self.log = tk.Text(root, height=20, wrap="word", font=("Consolas", 9))
        self.log.pack(fill="both", expand=True, padx=10, pady=5)
        scrollbar = ttk.Scrollbar(self.log, command=self.log.yview)
        scrollbar.pack(side="right", fill="y")
        self.log.config(yscrollcommand=scrollbar.set)

    def browse_file(self):
        path = filedialog.askopenfilename(filetypes=[("HTML/XML 文件", "*.html *.htm *.xml *.xhtml"), ("所有文件", "*.*")])
        if path:
            self.path_var.set(path)

    def show_context_menu(self, event):
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="粘贴文件路径", command=lambda: self.paste_path())
        menu.post(event.x_root, event.y_root)

    def paste_path(self):
        try:
            self.path_var.set(self.root.clipboard_get().strip())
        except Exception:
            pass

    def log_msg(self, msg):
        self.log.insert("end", msg + "\n")
        self.log.see("end")
        self.root.update()

    def start_scan(self):
        path = self.path_var.get().strip()
        if not path:
            messagebox.showwarning("提示", "请先选择 HTML 文件")
            return
        if not Path(path).is_file():
            messagebox.showerror("错误", f"文件不存在：{path}")
            return
        self.btn.config(state="disabled")
        self.log.delete("1.0", "end")
        threading.Thread(target=self._scan, args=(path,), daemon=True).start()

    def _scan(self, path):
        try:
            self.log_msg(f"[1/3] 读取文件：{path}")
            html = Path(path).read_text(encoding="utf-8")
            self.log_msg(f"[2/3] 提取特征...")
            features = extract_features(html)
            form_count = len(features["forms"])
            self.log_msg(f"  发现 {form_count} 个表单, "
                         f"{len(features['script_blocks'])} 个脚本块, "
                         f"{len(features['inline_events'])} 个内联事件")
            self.log_msg(f"[3/3] 调用大模型分析...")
            self.status_var.set("分析中，请稍候...")
            prompt = build_prompt(path, features)
            analysis = call_llm(prompt)
            json_path, md_path = save_report(path, features, analysis)
            self.log_msg(f"\n✅ 分析完成！")
            self.log_msg(f"  JSON 报告：{json_path}")
            self.log_msg(f"  Markdown 报告：{md_path}")
            if isinstance(analysis, list):
                self.log_msg(f"\n共发现 {len(analysis)} 个风险点：")
                for item in analysis:
                    self.log_msg(f"  [{item.get('risk_level','?')}] {item.get('vulnerability_type','?')} — {item.get('location','')}")
            else:
                self.log_msg(f"\n{analysis}")
            self.status_var.set(f"完成 — 报告已保存至 output/ 目录")
        except Exception as e:
            self.log_msg(f"\n❌ 错误：{e}")
            self.status_var.set("分析失败")
        finally:
            self.btn.config(state="normal")


if __name__ == "__main__":
    root = tk.Tk()
    ScannerApp(root)
    root.mainloop()