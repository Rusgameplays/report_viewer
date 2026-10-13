from __future__ import annotations
import csv
import webbrowser
from pathlib import Path
from typing import Any
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from report import build_report

APP_TITLE = "Результат сканирования"
REQUIRED_COLUMNS = ["Хост", "Уязвимость", "Уязвимая сущность", "CVSS", "Как устранить", "Есть эксплойт"]
HEADER_ALIASES = {
    "хост": "Хост",
    "уязвимость": "Уязвимость",
    "уязвимая сущность": "Уязвимая сущность",
    "cvss": "CVSS",
    "как устранить": "Как устранить",
    "есть эксплойт": "Есть эксплойт",
    "есть ли эксплойт": "Есть эксплойт",
    "эксплойт": "Есть эксплойт",
}

def normalize_header(value: str) -> str:
    return " ".join((value or "").strip().casefold().replace("ё", "е").split())

def parse_bool(value: Any) -> bool | None:
    normalized = str(value if value is not None else "").strip().casefold()
    if normalized in {"да", "есть", "true", "1", "yes", "y", "✓", "да, есть"}:
        return True
    if normalized in {"нет", "отсутствует", "false", "0", "no", "n", "✗"}:
        return False
    return None

def read_csv_file(path: Path) -> list[dict[str, Any]]:
    raw = path.read_bytes()
    text = None
    for encoding in ("utf-8-sig", "utf-8", "cp1251"):
        try:
            text = raw.decode(encoding)
            break
        except UnicodeDecodeError:
            continue
    if text is None:
        raise ValueError("Не удалось определить кодировку CSV. Сохраните файл в UTF-8.")

    try:
        delimiter = csv.Sniffer().sniff(text[:8192], delimiters=",;\t").delimiter
    except csv.Error:
        sample = text[:8192]
        delimiter = ";" if sample.count(";") > sample.count(",") else ","

    reader = csv.DictReader(text.splitlines(), delimiter=delimiter)
    if not reader.fieldnames:
        raise ValueError("В CSV нет строки заголовков.")

    mapped = {}
    for header in reader.fieldnames:
        canonical = HEADER_ALIASES.get(normalize_header(header))
        if canonical:
            mapped[header] = canonical

    missing = [col for col in REQUIRED_COLUMNS if col not in mapped.values()]
    if missing:
        raise ValueError(
            "Не найдены обязательные столбцы: " + ", ".join(missing)
            + "\\n\\nВ файле обнаружены заголовки: " + ", ".join(reader.fieldnames)
        )

    rows = []
    for line_no, raw_row in enumerate(reader, start=2):
        row = {canonical: (raw_row.get(original) or "").strip()
               for original, canonical in mapped.items()}
        if not any(row.get(col, "") for col in REQUIRED_COLUMNS):
            continue
        cvss_raw = row.get("CVSS", "")
        try:
            cvss = float(cvss_raw.replace(",", ".")) if cvss_raw else None
        except ValueError:
            cvss = None
        if cvss is not None and not 0 <= cvss <= 10:
            cvss = None
        row["_cvss"] = cvss
        row["_exploit"] = parse_bool(row.get("Есть эксплойт", ""))
        row["_source_line"] = line_no
        rows.append(row)

    if not rows:
        raise ValueError("В CSV не найдено ни одной строки с данными.")
    return rows

def main() -> None:
    root = tk.Tk()
    root.title(APP_TITLE)
    root.geometry("820x520")
    root.minsize(700, 450)

    selected_path = tk.StringVar(value="Файл не выбран")
    status_text = tk.StringVar(value="Загрузите CSV-файл с данными об уязвимостях.")
    loaded_rows = []
    loaded_path = None

    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass
    style.configure("Title.TLabel", font=("Segoe UI", 18, "bold"))
    style.configure("Sub.TLabel", font=("Segoe UI", 10))
    style.configure("Action.TButton", padding=(12, 8))

    outer = ttk.Frame(root, padding=22)
    outer.pack(fill="both", expand=True)
    ttk.Label(outer, text="Отчёт по уязвимостям", style="Title.TLabel").pack(anchor="w")
    ttk.Label(
        outer,
        text="Загрузите CSV и сформируйте автономную HTML-страницу с поиском, фильтрами и сортировкой.",
        style="Sub.TLabel", wraplength=740
    ).pack(anchor="w", pady=(6, 20))

    file_box = ttk.LabelFrame(outer, text="Источник данных", padding=14)
    file_box.pack(fill="x", pady=(0, 14))
    ttk.Label(file_box, textvariable=selected_path, wraplength=700).pack(anchor="w")
    controls = ttk.Frame(file_box)
    controls.pack(anchor="w", pady=(12, 0))

    def choose_file():
        nonlocal loaded_rows, loaded_path
        filename = filedialog.askopenfilename(
            parent=root, title="Выберите CSV с уязвимостями",
            filetypes=[("CSV", "*.csv"), ("Все файлы", "*.*")]
        )
        if not filename:
            return
        try:
            rows = read_csv_file(Path(filename))
        except Exception as exc:
            messagebox.showerror("Ошибка чтения CSV", str(exc), parent=root)
            return
        loaded_rows, loaded_path = rows, Path(filename)
        selected_path.set(str(loaded_path))
        pentest_count = sum(not str(row.get("Уязвимая сущность", "")).strip() for row in loaded_rows)
        mode = "; включён режим только с эксплойтами" if len(loaded_rows) > 3500 else ""
        status_text.set(f"Загружено записей: {len(loaded_rows)}; результатов пентеста без уязвимой сущности: {pentest_count}{mode}")
        generate_button.configure(state="normal")

    ttk.Button(controls, text="Выбрать CSV…", command=choose_file, style="Action.TButton").pack(side="left")

    def generate():
        if not loaded_rows or loaded_path is None:
            messagebox.showwarning("Нет данных", "Сначала выберите CSV-файл.", parent=root)
            return
        destination = filedialog.asksaveasfilename(
            parent=root, title="Сохранить HTML-отчёт",
            defaultextension=".html", initialfile=f"{loaded_path.stem}_report.html",
            filetypes=[("HTML", "*.html")]
        )
        if not destination:
            return
        try:
            build_report(loaded_rows, Path(destination), loaded_path.name)
        except Exception as exc:
            messagebox.showerror("Ошибка создания отчёта", str(exc), parent=root)
            return
        output = Path(destination)
        status_text.set(f"HTML создан: {output}")
        if messagebox.askyesno("Отчёт готов", "Открыть HTML-отчёт в браузере?", parent=root):
            webbrowser.open(output.resolve().as_uri())

    generate_button = ttk.Button(
        controls, text="Создать HTML-отчёт…", command=generate,
        style="Action.TButton", state="disabled"
    )
    generate_button.pack(side="left", padx=(10, 0))

    info = ttk.LabelFrame(outer, text="Формат CSV", padding=14)
    info.pack(fill="x", pady=(0, 14))
    ttk.Label(
        info,
        text=("Обязательные столбцы: Хост, Уязвимость, Уязвимая сущность, CVSS, Как устранить, Есть эксплойт.\n"
              "Строки без значения в столбце «Уязвимая сущность» попадут в виджет «Результат по итогам пентеста».\n"
              "Если записей больше 3500, вместо полного списка доступен список только уязвимостей с эксплойтами.\n"
              "Поддерживаются разделители запятая, точка с запятой и табуляция; кодировки UTF-8 и Windows-1251.\n"
              "Для эксплойта подходят значения Да/Нет, Есть/Нет, True/False, 1/0."),
        wraplength=740, justify="left"
    ).pack(anchor="w")
    ttk.Label(outer, textvariable=status_text, wraplength=740).pack(anchor="w", pady=(10, 0))
    root.mainloop()

if __name__ == "__main__":
    main()
