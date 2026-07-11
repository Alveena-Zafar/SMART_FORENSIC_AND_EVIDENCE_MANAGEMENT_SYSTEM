import tkinter as tk
from tkinter import ttk, messagebox
import oracledb
import hashlib
import re
from datetime import datetime, date

# ── Oracle Connection Settings ─────────────────────────────
DB_USER     = "forensic_user"       
DB_PASSWORD = "forensic_pass123"      
DB_DSN      = "localhost/ORCLPDB"

# ══════════════════════════════════════════════════════════════
#  COLOUR PALETTE  — Warm Cream + Brown
# ══════════════════════════════════════════════════════════════
BG           = "#F5F1E8"   # cream background
SIDEBAR_BG   = "#2F3437"   # dark charcoal sidebar
CARD_BG      = "#FFFDF8"   # warm white cards
HEADER_BG    = "#EDE9DF"   # slightly deeper cream for headers
ACCENT       = "#7A5C3E"   # brown accent
ACCENT2      = "#8E6A47"   # brown hover
ACCENT_LIGHT = "#E8E0D0"   # light brown tint for highlights
DANGER       = "#A62C2C"   # dark red
SUCCESS      = "#4F772D"   # forest green
WARNING      = "#C47C1A"   # amber
INFO         = "#2E6B9E"   # slate blue
TEXT_DARK    = "#2C2C2C"   # near-black primary text
TEXT_MID     = "#5A5045"   # warm mid text
TEXT_LIGHT   = "#9A8F82"   # muted warm grey
BORDER       = "#D6CEBC"   # warm border
ROW_ALT      = "#F0EBE0"   # alternating row cream
NAV_HOVER    = "#3A3F42"   # slightly lighter charcoal hover
NAV_ACTIVE   = "#46504A"   # active nav
INPUT_BG     = "#FDFAF4"   # near-white input
BADGE_DBA    = "#5B3A9E"   # purple
BADGE_SUP    = "#2E6B3E"   # dark green
BADGE_INV    = "#1A4F8A"   # dark blue
BADGE_LAB    = "#7A4A10"   # dark amber
BADGE_LEG    = "#4A4A4A"   # dark grey

FONT_TITLE = ("Segoe UI Semibold", 16, "bold")
FONT_HEAD  = ("Segoe UI Semibold", 11, "bold")
FONT_SUB   = ("Segoe UI", 10, "bold")
FONT_BODY  = ("Segoe UI", 10)
FONT_SMALL = ("Segoe UI", 9)
FONT_MONO  = ("Consolas", 9)
FONT_TINY  = ("Segoe UI", 8)

STATUS_COLORS = {
    "OPEN":         "#3DBE7A",
    "CLOSED":       "#5A7290",
    "PENDING":      "#E8924A",
    "ARCHIVED":     "#374151",
    "ACTIVE":       "#3DBE7A",
    "CLEARED":      "#5A7290",
    "ARRESTED":     "#E05555",
    "RELEASED":     "#5A7290",
    "COLLECTED":    "#4A9EDB",
    "IN_LAB":       "#E8924A",
    "ANALYZED":     "#3DBE7A",
    "DISPOSED":     "#374151",
    "DRAFT":        "#E8924A",
    "FINAL":        "#3DBE7A",
    "LOW":          "#3DBE7A",
    "MEDIUM":       "#E8924A",
    "HIGH":         "#E05555",
    "CRITICAL":     "#9333EA",
    "COMPLETED":    "#3DBE7A",
    "REJECTED":     "#E05555",
    "IN_PROGRESS":  "#4A9EDB",
    "EXONERATED":   "#3DBE7A",
}

ROLE_ACCESS = {
    "dba":          {"all": True},
    "supervisor":   {"tabs": ["🏠  Dashboard","📁  Cases","🔍  Evidence",
                               "👤  Suspects","🕵  Investigators","💡  Clues",
                               "🔗  Chain of Custody","🧪  Lab Requests",
                               "📋  Forensic Records","👥  Nominated Persons",
                               "📊  Reports"]},
    "investigator": {"tabs": ["🏠  Dashboard","📁  Cases","🔍  Evidence",
                               "👤  Suspects","💡  Clues","🔗  Chain of Custody",
                               "🧪  Lab Requests","📋  Forensic Records",
                               "👥  Nominated Persons","📊  Reports"]},
    "lab_tech":     {"tabs": ["🏠  Dashboard","🔍  Evidence",
                               "🔗  Chain of Custody","🧪  Lab Requests"]},
    "legal":        {"tabs": ["🏠  Dashboard","📁  Cases","🔍  Evidence",
                               "📋  Forensic Records","📊  Reports"]},
}

ROLE_PERMS = {
    "dba":          {"add": True,  "edit": True,  "delete": True,  "read": True},
    "supervisor":   {"add": True,  "edit": True,  "delete": True,  "read": True},
    "investigator": {"add": True,  "edit": True,  "delete": False, "read": True},
    "lab_tech":     {"add": False, "edit": True,  "delete": False, "read": True},
    "legal":        {"add": False, "edit": False, "delete": False, "read": True},
}

_pool = None

def _get_pool():
    global _pool
    if _pool is None:
        _pool = oracledb.create_pool(
            user=DB_USER, password=DB_PASSWORD, dsn=DB_DSN,
            min=2, max=5, increment=1)
    return _pool

class _OracleConn:
    def __init__(self):
        self._conn = _get_pool().acquire()

    def _convert_params(self, params):
        if not params: return params
        date_pat = re.compile(r'^\d{4}-\d{2}-\d{2}$')
        converted = []
        for p in params:
            if isinstance(p, str) and date_pat.match(p):
                try: converted.append(datetime.strptime(p, '%Y-%m-%d').date())
                except: converted.append(p)
            else:
                converted.append(p)
        return converted

    def execute(self, sql, params=None):
        cur = self._conn.cursor()
        if params: cur.execute(sql, self._convert_params(list(params)))
        else: cur.execute(sql)
        return cur

    def cursor(self): return self._conn.cursor()
    def commit(self): self._conn.commit()
    def close(self): _get_pool().release(self._conn)

def get_conn(): return _OracleConn()

def hash_pw(pw): return hashlib.sha256(pw.encode()).hexdigest()

def validate_cnic(cnic):
    return bool(re.match(r'^\d{5}-\d{7}-\d{1}$', cnic.strip()))

def validate_name(name):
    return bool(name) and any(c.isalpha() for c in name)

def validate_date(d):
    try: datetime.strptime(d, '%Y-%m-%d'); return True
    except: return False

def init_db():
    conn = get_conn(); c = conn.cursor()
    try:
        c.execute("""CREATE TABLE SYSTEM_USERS (
            User_ID   NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            Username  VARCHAR2(50) NOT NULL UNIQUE,
            Password  VARCHAR2(100) NOT NULL,
            Role      VARCHAR2(20) NOT NULL CHECK(Role IN ('dba','supervisor','investigator','lab_tech','legal')),
            Full_name VARCHAR2(100),
            Is_active NUMBER(1) DEFAULT 1)""")
        conn.commit()
    except Exception: pass
    c.execute("SELECT COUNT(*) FROM SYSTEM_USERS")
    if c.fetchone()[0] == 0:
        users = [
            ("admin",       hash_pw("admin123"),  "dba",          "System Administrator"),
            ("supervisor1", hash_pw("super123"),  "supervisor",   "Ahmed Supervisor"),
            ("inv1",        hash_pw("inv123"),    "investigator", "Ali Hassan"),
            ("labtech1",    hash_pw("lab123"),    "lab_tech",     "Lab Tech Asad"),
            ("legal1",      hash_pw("legal123"),  "legal",        "Legal Counsel"),
        ]
        for u in users:
            c.execute("INSERT INTO SYSTEM_USERS(Username,Password,Role,Full_name) VALUES(:1,:2,:3,:4)", u)
        conn.commit()
    conn.close()


# ══════════════════════════════════════════════════════════════
#  STYLE INITIALISATION
# ══════════════════════════════════════════════════════════════
def _init_treeview_style():
    style = ttk.Style()
    style.theme_use("clam")
    # Treeview body
    style.configure("Pro.Treeview",
                    background=CARD_BG,
                    fieldbackground=CARD_BG,
                    foreground=TEXT_DARK,
                    rowheight=30,
                    font=FONT_BODY,
                    borderwidth=0,
                    relief="flat")
    # Column headings
    style.configure("Pro.Treeview.Heading",
                    background=HEADER_BG,
                    foreground=ACCENT,
                    font=("Segoe UI Semibold", 9, "bold"),
                    relief="flat",
                    padding=(8, 6))
    style.map("Pro.Treeview",
              background=[("selected", ACCENT_LIGHT)],
              foreground=[("selected", "#2C2C2C")])
    # Scrollbars
    style.configure("Dark.Vertical.TScrollbar",
                    background=BORDER, troughcolor=CARD_BG,
                    arrowcolor=TEXT_MID, borderwidth=0)
    style.configure("Dark.Horizontal.TScrollbar",
                    background=BORDER, troughcolor=CARD_BG,
                    arrowcolor=TEXT_MID, borderwidth=0)
    # Notebook tabs
    style.configure("Dark.TNotebook",
                    background=BG, borderwidth=0)
    style.configure("Dark.TNotebook.Tab",
                    background=HEADER_BG,
                    foreground=TEXT_MID,
                    font=FONT_SMALL,
                    padding=(12, 6),
                    borderwidth=0)
    style.map("Dark.TNotebook.Tab",
              background=[("selected", ACCENT_LIGHT)],
              foreground=[("selected", TEXT_DARK)])
    # Combobox
    style.configure("Dark.TCombobox",
                    fieldbackground=INPUT_BG,
                    background=INPUT_BG,
                    foreground=TEXT_DARK,
                    arrowcolor=ACCENT,
                    borderwidth=1,
                    relief="solid")
    style.map("Dark.TCombobox",
              fieldbackground=[("readonly", INPUT_BG)],
              foreground=[("readonly", TEXT_DARK)],
              selectbackground=[("readonly", ACCENT_LIGHT)],
              selectforeground=[("readonly", TEXT_DARK)])


# ══════════════════════════════════════════════════════════════
#  WIDGET HELPERS
# ══════════════════════════════════════════════════════════════
def styled_btn(parent, text, cmd=None, color=ACCENT, fg="white", small=False):
    """Brown button with white text."""
    b = tk.Button(parent, text=text, command=cmd,
                  bg=color, fg=fg,
                  font=FONT_SMALL if small else FONT_SUB,
                  relief="flat", bd=0,
                  padx=14, pady=6,
                  cursor="hand2",
                  activebackground=ACCENT2,
                  activeforeground="white")
    return b


def danger_btn(parent, text, cmd=None):
    return tk.Button(parent, text=text, command=cmd,
                     bg="#F5E8E8", fg=DANGER,
                     font=FONT_SUB, relief="flat", bd=0,
                     padx=14, pady=6, cursor="hand2",
                     activebackground="#F0D0D0",
                     activeforeground=DANGER)


def ghost_btn(parent, text, cmd=None):
    return tk.Button(parent, text=text, command=cmd,
                     bg=ACCENT_LIGHT, fg=TEXT_MID,
                     font=FONT_SUB, relief="flat", bd=0,
                     padx=14, pady=6, cursor="hand2",
                     activebackground=BORDER,
                     activeforeground=TEXT_DARK)


def label_entry(parent, label, row, default="", width=30, options=None, show=None):
    if label:
        tk.Label(parent, text=label, bg=CARD_BG, fg=TEXT_MID,
                 font=FONT_SMALL).grid(row=row, column=0,
                                        sticky="w", padx=(10, 6), pady=5)
    var = tk.StringVar(value=default)
    if options:
        cb = ttk.Combobox(parent, textvariable=var, values=options,
                          width=width - 2, font=FONT_BODY,
                          state="readonly", style="Dark.TCombobox")
        cb.grid(row=row, column=1, sticky="ew", padx=(0, 10), pady=5)
    else:
        kw = {"show": show} if show else {}
        e = tk.Entry(parent, textvariable=var, width=width,
                     font=FONT_BODY, bg=INPUT_BG, fg=TEXT_DARK,
                     insertbackground=ACCENT,
                     relief="flat", bd=0,
                     highlightbackground=BORDER,
                     highlightthickness=1, **kw)
        e.grid(row=row, column=1, sticky="ew", padx=(0, 10), pady=5, ipady=4)
    return var


def section_header(parent, title, subtitle="", role_badge=None):
    f = tk.Frame(parent, bg=HEADER_BG, pady=14, padx=20)
    f.pack(fill="x", pady=(0, 0))
    # Gold left accent bar
    tk.Frame(f, bg=ACCENT, width=4).pack(side="left", fill="y", padx=(0, 14))
    inner = tk.Frame(f, bg=HEADER_BG); inner.pack(side="left", fill="both", expand=True)
    top_row = tk.Frame(inner, bg=HEADER_BG); top_row.pack(fill="x")
    tk.Label(top_row, text=title, bg=HEADER_BG, fg=TEXT_DARK,
             font=FONT_TITLE).pack(side="left")
    if role_badge:
        rc = {"DBA": BADGE_DBA, "SUPERVISOR": BADGE_SUP,
              "INVESTIGATOR": BADGE_INV, "LAB TECH": BADGE_LAB, "LEGAL": BADGE_LEG}
        bg = rc.get(role_badge.upper(), ACCENT_LIGHT)
        tk.Label(top_row, text=f"  {role_badge}  ",
                 bg=bg, fg="white",
                 font=FONT_TINY, padx=8, pady=3).pack(side="left", padx=10)
    if subtitle:
        tk.Label(inner, text=subtitle, bg=HEADER_BG,
                 fg=TEXT_LIGHT, font=FONT_SMALL).pack(anchor="w", pady=(2, 0))
    # Bottom border
    tk.Frame(parent, bg=BORDER, height=1).pack(fill="x")


def make_tree(parent, columns, heights=12):
    frame = tk.Frame(parent, bg=CARD_BG,
                     highlightbackground=BORDER, highlightthickness=1)
    tree = ttk.Treeview(frame, columns=columns, show="headings",
                        height=heights, style="Pro.Treeview")
    vsb = ttk.Scrollbar(frame, orient="vertical",
                        command=tree.yview,
                        style="Dark.Vertical.TScrollbar")
    hsb = ttk.Scrollbar(frame, orient="horizontal",
                        command=tree.xview,
                        style="Dark.Horizontal.TScrollbar")
    tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
    vsb.pack(side="right", fill="y")
    hsb.pack(side="bottom", fill="x")
    tree.pack(fill="both", expand=True)
    tree.tag_configure("odd",  background=CARD_BG)
    tree.tag_configure("even", background=ROW_ALT)
    return frame, tree


def insert_rows(tree, rows):
    for i, r in enumerate(rows):
        tree.insert("", "end", values=r,
                    tags=("even" if i % 2 == 0 else "odd",))


def stat_card(parent, label, value, color=ACCENT):
    f = tk.Frame(parent, bg=CARD_BG,
                 highlightbackground=color, highlightthickness=1)
    # Top colour band
    tk.Frame(f, bg=color, height=3).pack(fill="x")
    inner = tk.Frame(f, bg=CARD_BG, padx=18, pady=14)
    inner.pack(fill="both", expand=True)
    tk.Label(inner, text=str(value), bg=CARD_BG, fg=color,
             font=("Segoe UI Semibold", 30, "bold")).pack(anchor="w")
    tk.Label(inner, text=label, bg=CARD_BG, fg=TEXT_MID,
             font=FONT_SMALL).pack(anchor="w")
    return f


def clear_frame(frame):
    for w in frame.winfo_children():
        w.destroy()


def read_only_notice(parent):
    bar = tk.Frame(parent, bg="#F0EBD8")
    bar.pack(fill="x", padx=14, pady=(4, 0))
    tk.Label(bar,
             text="  👁  READ-ONLY  —  Your role does not permit modifications.",
             bg="#F0EBD8", fg="#5A7033",
             font=FONT_SMALL, padx=10, pady=7,
             anchor="w").pack(fill="x")


def dialog_base(master, title, width=480):
    """Return (dlg, body) — dlg is the Toplevel, body is the grid container."""
    dlg = tk.Toplevel(master)
    dlg.title(title)
    dlg.configure(bg=CARD_BG)
    dlg.resizable(False, False)
    dlg.grab_set()
    # Gold top accent bar — uses pack on dlg
    tk.Frame(dlg, bg=ACCENT, height=4).pack(fill="x")
    # Body frame — ALL grid children go inside here
    body = tk.Frame(dlg, bg=CARD_BG)
    body.pack(fill="both", expand=True)
    body.columnconfigure(1, weight=1)
    return dlg, body


def dialog_title(body, text):
    tk.Label(body, text=text, bg=CARD_BG, fg=TEXT_DARK,
             font=FONT_HEAD).grid(row=0, columnspan=2,
                                   pady=(16, 8), padx=16, sticky="w")


def dialog_fields_frame(body):
    f = tk.Frame(body, bg=CARD_BG)
    f.grid(row=1, padx=16, pady=4, sticky="ew")
    f.columnconfigure(1, weight=1)
    return f


def save_btn(body, text, cmd):
    tk.Frame(body, bg=BORDER, height=1).grid(
        row=3, columnspan=2, sticky="ew", padx=16, pady=(8, 0))
    btn_row = tk.Frame(body, bg=CARD_BG)
    btn_row.grid(row=4, columnspan=2, pady=12, padx=16, sticky="e")
    styled_btn(btn_row, text, cmd).pack(side="right")


def status_pill(parent, text):
    color = STATUS_COLORS.get(str(text), TEXT_LIGHT)
    tk.Label(parent, text=f"  {text}  ",
             bg=ACCENT_LIGHT,
             fg=color,
             font=("Segoe UI Semibold", 8),
             padx=6, pady=2).pack(side="left", padx=4)


# ══════════════════════════════════════════════════════════════
#  LOGIN WINDOW
# ══════════════════════════════════════════════════════════════
class LoginWindow(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Forensic System — Login")
        self.geometry("480x620")
        self.resizable(False, False)
        self.configure(bg=BG)
        self.logged_user = None
        self._build()
        self.eval('tk::PlaceWindow . center')

    def _build(self):
        # ── Top gold bar ──────────────────────────────────────
        tk.Frame(self, bg=ACCENT, height=4).pack(fill="x")

        # ── Hero panel ───────────────────────────────────────
        hero = tk.Frame(self, bg=SIDEBAR_BG, pady=36)
        hero.pack(fill="x")
        tk.Label(hero, text="🔬", bg=SIDEBAR_BG, fg=ACCENT,
                 font=("Segoe UI", 42)).pack()
        tk.Label(hero, text="S M A R T   F O R E N S I C", bg=SIDEBAR_BG, fg="#F5F1E8",
                 font=("Segoe UI Semibold", 13, "bold")).pack()
        tk.Label(hero, text="Evidence Management System",
                 bg=SIDEBAR_BG, fg="#C8B99A",
                 font=("Segoe UI", 10)).pack(pady=(2, 0))
        tk.Label(hero, text="━" * 30, bg=SIDEBAR_BG, fg="#4A5050",
                 font=("Segoe UI", 8)).pack(pady=(10, 0))

        # ── Login card ───────────────────────────────────────
        card = tk.Frame(self, bg=CARD_BG, padx=40, pady=30)
        card.pack(fill="both", expand=True, padx=24, pady=20)

        tk.Label(card, text="SIGN IN TO YOUR ACCOUNT",
                 bg=CARD_BG, fg=TEXT_MID,
                 font=("Segoe UI Semibold", 8)).pack(anchor="w", pady=(0, 16))

        # Username
        tk.Label(card, text="Username", bg=CARD_BG,
                 fg=TEXT_MID, font=FONT_SMALL).pack(anchor="w")
        self.v_user = tk.StringVar()
        e_user = tk.Entry(card, textvariable=self.v_user,
                          font=FONT_BODY, bg=INPUT_BG, fg=TEXT_DARK,
                          insertbackground=ACCENT,
                          relief="flat", bd=0,
                          highlightbackground=BORDER,
                          highlightthickness=1)
        e_user.pack(fill="x", pady=(4, 14), ipady=7)
        e_user.focus()

        # Password
        tk.Label(card, text="Password", bg=CARD_BG,
                 fg=TEXT_MID, font=FONT_SMALL).pack(anchor="w")
        self.v_pass = tk.StringVar()
        e_pass = tk.Entry(card, textvariable=self.v_pass,
                          show="●", font=FONT_BODY,
                          bg=INPUT_BG, fg=TEXT_DARK,
                          insertbackground=ACCENT,
                          relief="flat", bd=0,
                          highlightbackground=BORDER,
                          highlightthickness=1)
        e_pass.pack(fill="x", pady=(4, 8), ipady=7)
        e_pass.bind("<Return>", lambda _: self._login())

        self.err_lbl = tk.Label(card, text="", bg=CARD_BG,
                                fg=DANGER, font=FONT_SMALL)
        self.err_lbl.pack(anchor="w", pady=(0, 6))

        # Sign in button
        tk.Button(card, text="SIGN IN  →",
                  command=self._login,
                  bg=ACCENT, fg="white",
                  font=("Segoe UI Semibold", 10, "bold"),
                  relief="flat", bd=0,
                  pady=11, cursor="hand2",
                  activebackground=ACCENT2,
                  activeforeground="white").pack(fill="x", pady=(4, 0))

        # Divider + credentials hint
        tk.Frame(card, bg=BORDER, height=1).pack(fill="x", pady=(18, 10))
        tk.Label(card, text="DEFAULT CREDENTIALS",
                 bg=CARD_BG, fg=TEXT_MID,
                 font=("Segoe UI Semibold", 7)).pack(anchor="w", pady=(0, 6))
        cred_frame = tk.Frame(card, bg=CARD_BG)
        cred_frame.pack(fill="x")
        for role, user, pw, color in [
            ("DBA",         "admin",       "admin123",  BADGE_DBA),
            ("Supervisor",  "supervisor1", "super123",  BADGE_SUP),
            ("Investigator","inv1",        "inv123",    BADGE_INV),
            ("Lab Tech",    "labtech1",    "lab123",    BADGE_LAB),
            ("Legal",       "legal1",      "legal123",  BADGE_LEG),
        ]:
            row = tk.Frame(cred_frame, bg=CARD_BG)
            row.pack(fill="x", pady=1)
            tk.Label(row, text=f"  {role}", bg=color,
                     fg="white", font=FONT_TINY,
                     width=12, anchor="w",
                     padx=4, pady=3).pack(side="left")
            tk.Label(row,
                     text=f"  {user:<14} {pw}",
                     bg=CARD_BG, fg=TEXT_MID,
                     font=FONT_MONO).pack(side="left")

    def _login(self):
        username = self.v_user.get().strip()
        password  = self.v_pass.get()
        if not username or not password:
            self.err_lbl.config(text="⚠  Please enter username and password.")
            return
        conn = get_conn()
        row = conn.execute(
            "SELECT User_ID,Username,Role,Full_name FROM SYSTEM_USERS "
            "WHERE Username=:1 AND Password=:2 AND Is_active=1",
            (username, hash_pw(password))).fetchone()
        conn.close()
        if row:
            self.logged_user = {
                "id": row[0], "username": row[1],
                "role": row[2], "full_name": row[3]
            }
            self.destroy()
        else:
            self.err_lbl.config(text="⚠  Invalid username or password.")
            self.v_pass.set("")



# ══════════════════════════════════════════════════════════════
#  MAIN APPLICATION SHELL
# ══════════════════════════════════════════════════════════════
class ForensicApp(tk.Tk):
    def __init__(self, user):
        super().__init__()
        self.user  = user
        self.role  = user["role"]
        self.perms = ROLE_PERMS[self.role]
        allowed = ROLE_ACCESS.get(self.role, {})
        self.allowed_tabs = (None if allowed.get("all")
                             else set(allowed.get("tabs", [])))
        self.title("Smart Forensic & Evidence Management System")
        self.geometry("1360x820")
        self.minsize(1000, 640)
        self.configure(bg=BG)
        self._build_ui()
        self.eval('tk::PlaceWindow . center')

    def _can(self, action): return self.perms.get(action, False)

    # ── Top bar ───────────────────────────────────────────────
    def _build_ui(self):
        # Gold top accent
        tk.Frame(self, bg=ACCENT, height=3).pack(fill="x")

        top = tk.Frame(self, bg=SIDEBAR_BG, height=56)
        top.pack(fill="x")
        top.pack_propagate(False)

        # Logo area
        logo_f = tk.Frame(top, bg=ACCENT, width=220, height=56)
        logo_f.pack(side="left")
        logo_f.pack_propagate(False)
        tk.Label(logo_f, text="🔬  FORENSICS",
                 bg=ACCENT, fg="white",
                 font=("Segoe UI Semibold", 11, "bold")).pack(
                     side="left", padx=16, pady=14)

        # System title
        tk.Label(top, text="Smart Forensic & Evidence Management System",
                 bg=SIDEBAR_BG, fg="#F5F1E8",
                 font=("Segoe UI Semibold", 11, "bold")).pack(
                     side="left", padx=20)

        # Right user info
        rf = tk.Frame(top, bg=SIDEBAR_BG)
        rf.pack(side="right", padx=16)

        rc = {"dba": BADGE_DBA, "supervisor": BADGE_SUP,
              "investigator": BADGE_INV, "lab_tech": BADGE_LAB,
              "legal": BADGE_LEG}
        tk.Label(rf,
                 text=f"  {self.role.upper().replace('_', ' ')}  ",
                 bg=rc.get(self.role, ACCENT_LIGHT),
                 fg="white",
                 font=("Segoe UI Semibold", 8),
                 padx=6, pady=3).pack(side="right", padx=(6, 0))

        tk.Label(rf, text=f"👤  {self.user['full_name']}",
                 bg=SIDEBAR_BG, fg="#C8B99A",
                 font=FONT_SMALL).pack(side="right", padx=8)

        tk.Label(rf, text=datetime.now().strftime('%d %b %Y'),
                 bg=SIDEBAR_BG, fg="#8A7A6A",
                 font=FONT_SMALL).pack(side="right", padx=8)

        styled_btn(rf, "⏻  Logout", self._logout,
                   color="#3A3F42", fg="#C8B99A",
                   small=True).pack(side="right", padx=4)

        # Separator
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")

        # Body
        body = tk.Frame(self, bg=BG)
        body.pack(fill="both", expand=True)

        # Sidebar
        self.sidebar = tk.Frame(body, bg=SIDEBAR_BG, width=220)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        # Right border on sidebar
        tk.Frame(body, bg=BORDER, width=1).pack(side="left", fill="y")

        # Content
        self.content = tk.Frame(body, bg=BG)
        self.content.pack(side="left", fill="both", expand=True)

        self._build_sidebar()
        self.show_dashboard()

    # ── Sidebar ───────────────────────────────────────────────
    def _build_sidebar(self):
        # Logo section in sidebar
        logo_area = tk.Frame(self.sidebar, bg=SIDEBAR_BG, pady=20)
        logo_area.pack(fill="x")
        tk.Label(logo_area, text="NAVIGATION",
                 bg=SIDEBAR_BG, fg="#7A8A82",
                 font=("Segoe UI Semibold", 7)).pack(
                     anchor="w", padx=18, pady=(0, 8))

        all_nav = [
            ("🏠  Dashboard",         self.show_dashboard),
            ("📁  Cases",             self.show_cases),
            ("🔍  Evidence",          self.show_evidence),
            ("👤  Suspects",          self.show_suspects),
            ("🕵  Investigators",     self.show_investigators),
            ("💡  Clues",             self.show_clues),
            ("🔗  Chain of Custody",  self.show_custody),
            ("🧪  Lab Requests",      self.show_lab),
            ("📋  Forensic Records",  self.show_records),
            ("👥  Nominated Persons", self.show_nominated),
            ("📊  Reports",           self.show_reports),
            ("🔑  Users",             self.show_users),
        ]
        self.nav_buttons = {}
        for label, cmd in all_nav:
            if self.allowed_tabs and label not in self.allowed_tabs:
                continue
            btn_frame = tk.Frame(self.sidebar, bg=SIDEBAR_BG)
            btn_frame.pack(fill="x")
            # Left accent indicator (hidden by default)
            indicator = tk.Frame(btn_frame, bg=SIDEBAR_BG, width=3)
            indicator.pack(side="left", fill="y")
            b = tk.Button(btn_frame, text=f"  {label}",
                          command=lambda c=cmd, l=label: self._nav_click(c, l),
                          bg=SIDEBAR_BG, fg="#C8B99A",
                          font=FONT_BODY,
                          relief="flat", bd=0,
                          anchor="w", padx=12, pady=10,
                          cursor="hand2",
                          activebackground=NAV_HOVER,
                          activeforeground="#F5F1E8")
            b.pack(side="left", fill="x", expand=True)
            self.nav_buttons[label] = (b, indicator)

        # Bottom info
        tk.Frame(self.sidebar, bg="#3A4040", height=1).pack(
            fill="x", pady=12, padx=14)
        tk.Label(self.sidebar,
                 text=f"Signed in as  {self.user['username']}",
                 bg=SIDEBAR_BG, fg="#7A8A82",
                 font=FONT_TINY).pack(anchor="w", padx=18)
        tk.Label(self.sidebar,
                 text=f"DB  {DB_DSN}",
                 bg=SIDEBAR_BG, fg="#7A8A82",
                 font=FONT_TINY).pack(anchor="w", padx=18, pady=(2, 0))

    def _nav_click(self, cmd, label):
        for lbl, (b, ind) in self.nav_buttons.items():
            if lbl == label:
                b.configure(bg=NAV_ACTIVE, fg="#F5C87A",
                            font=("Segoe UI Semibold", 10, "bold"))
                ind.configure(bg="#F5C87A")
            else:
                b.configure(bg=SIDEBAR_BG, fg="#C8B99A",
                            font=FONT_BODY)
                ind.configure(bg=SIDEBAR_BG)
        clear_frame(self.content)
        cmd()

    def _logout(self): self.destroy(); _run_login()

    # ═══ DASHBOARD ═══════════════════════════════════════════
    def show_dashboard(self):
        page = self.content
        section_header(page, "Dashboard", "Live system overview",
                       role_badge=self.role.upper().replace('_', ' '))

        conn = get_conn(); c = conn.cursor()
        stats = {
            "Total Cases":    c.execute("SELECT COUNT(*) FROM CASES").fetchone()[0],
            "Open Cases":     c.execute("SELECT COUNT(*) FROM CASES WHERE Current_status='OPEN'").fetchone()[0],
            "Total Evidence": c.execute("SELECT COUNT(*) FROM EVIDENCE").fetchone()[0],
            "Suspects":       c.execute("SELECT COUNT(*) FROM SUSPECTS").fetchone()[0],
            "Investigators":  c.execute("SELECT COUNT(*) FROM INVESTIGATORS").fetchone()[0],
            "Lab Requests":   c.execute("SELECT COUNT(*) FROM LABANALYSISREQUEST").fetchone()[0],
        }

        # Stat cards
        cards_row = tk.Frame(page, bg=BG)
        cards_row.pack(fill="x", padx=16, pady=16)
        colors = [ACCENT, INFO, WARNING, DANGER, "#9333EA", SUCCESS]
        for i, (lbl, val) in enumerate(stats.items()):
            sc = stat_card(cards_row, lbl, val, colors[i])
            sc.grid(row=0, column=i, padx=6, pady=0, sticky="nsew")
            cards_row.columnconfigure(i, weight=1)

        # Section label
        lbl_row = tk.Frame(page, bg=BG)
        lbl_row.pack(fill="x", padx=16, pady=(16, 6))
        tk.Label(lbl_row, text="Recent Cases",
                 bg=BG, fg=TEXT_DARK, font=FONT_HEAD).pack(side="left")
        tk.Frame(lbl_row, bg=BORDER, height=1).pack(
            side="left", fill="x", expand=True, padx=14, pady=8)

        cols = ("ID", "Title", "Status", "Opened", "Evidence", "Clues")
        tf, tree = make_tree(page, cols, heights=9)
        for col, w in zip(cols, [60, 260, 100, 110, 90, 70]):
            tree.heading(col, text=col)
            tree.column(col, width=w,
                        anchor="w" if col == "Title" else "center")
        rows = c.execute("""
            SELECT * FROM (
                SELECT c.Case_ID, c.Title, c.Current_status,
                       TO_CHAR(c.Date_opened,'YYYY-MM-DD'),
                       COUNT(DISTINCT e.Evidence_ID),
                       COUNT(DISTINCT cl.Clue_ID)
                FROM CASES c
                LEFT JOIN EVIDENCE e  ON c.Case_ID = e.Case_ID
                LEFT JOIN CLUES    cl ON c.Case_ID = cl.Case_ID
                GROUP BY c.Case_ID, c.Title,
                         c.Current_status, c.Date_opened
                ORDER BY c.Date_opened DESC
            ) WHERE ROWNUM <= 10
        """).fetchall()
        insert_rows(tree, rows)
        tf.pack(fill="both", expand=True, padx=16, pady=(0, 16))
        conn.close()

    # ═══ CASES ═══════════════════════════════════════════════
    def show_cases(self):
        page = self.content
        section_header(page, "Cases", "Manage and track all forensic cases")
        if not self._can("read"): return
        if self.role == "legal": read_only_notice(page)

        # Toolbar
        tb = tk.Frame(page, bg=BG, pady=10)
        tb.pack(fill="x", padx=16)
        if self._can("add"):
            styled_btn(tb, "+  New Case",
                       self.add_case_dialog).pack(side="left", padx=(0, 8))

        # Filter pills
        filter_f = tk.Frame(tb, bg=BG)
        filter_f.pack(side="left")
        tk.Label(filter_f, text="Filter:", bg=BG,
                 fg=TEXT_LIGHT, font=FONT_SMALL).pack(side="left", padx=(0, 6))
        self.case_filter = tk.StringVar(value="ALL")
        for s in ["ALL", "OPEN", "CLOSED", "PENDING", "ARCHIVED"]:
            color = STATUS_COLORS.get(s, TEXT_LIGHT) if s != "ALL" else ACCENT
            tk.Radiobutton(filter_f, text=s, variable=self.case_filter,
                           value=s, bg=BG, fg=TEXT_MID,
                           selectcolor=ACCENT_LIGHT,
                           activebackground=BG,
                           font=FONT_SMALL,
                           command=self._reload_cases).pack(side="left", padx=3)

        # Tree
        cols = ("ID", "Title", "Status", "Opened", "Closed")
        tf, self.case_tree = make_tree(page, cols)
        for col, w in zip(cols, [60, 300, 100, 110, 110]):
            self.case_tree.heading(col, text=col)
            self.case_tree.column(col, width=w,
                                  anchor="w" if col == "Title" else "center")
        tf.pack(fill="both", expand=True, padx=16, pady=(0, 0))

        # Action bar
        act = tk.Frame(page, bg=HEADER_BG, pady=10)
        act.pack(fill="x")
        tk.Frame(act, bg=BORDER, height=1).pack(fill="x")
        btn_row = tk.Frame(act, bg=HEADER_BG)
        btn_row.pack(pady=8, padx=16, anchor="w")
        if self._can("edit"):
            styled_btn(btn_row, "✏  Edit",
                       lambda: self.edit_case_dialog(),
                       color=ACCENT_LIGHT, fg=ACCENT).pack(side="left", padx=(0, 6))
        if self._can("delete"):
            danger_btn(btn_row, "🗑  Delete",
                       lambda: self.delete_case()).pack(side="left", padx=(0, 6))
        ghost_btn(btn_row, "👁  View Details",
                  lambda: self.view_case_detail()).pack(side="left", padx=(0, 6))
        ghost_btn(btn_row, "📋  Status Log",
                  lambda: self.view_case_status_log()).pack(side="left")
        self._reload_cases()

    def _reload_cases(self):
        for row in self.case_tree.get_children():
            self.case_tree.delete(row)
        conn = get_conn()
        filt = self.case_filter.get()
        if filt != "ALL":
            rows = conn.execute(
                "SELECT Case_ID,Title,Current_status,"
                "TO_CHAR(Date_opened,'YYYY-MM-DD'),"
                "NVL(TO_CHAR(Date_closed,'YYYY-MM-DD'),'—') "
                "FROM CASES WHERE Current_status=:1 "
                "ORDER BY Date_opened DESC", (filt,)).fetchall()
        else:
            rows = conn.execute(
                "SELECT Case_ID,Title,Current_status,"
                "TO_CHAR(Date_opened,'YYYY-MM-DD'),"
                "NVL(TO_CHAR(Date_closed,'YYYY-MM-DD'),'—') "
                "FROM CASES ORDER BY Date_opened DESC").fetchall()
        insert_rows(self.case_tree, rows)
        conn.close()

    def add_case_dialog(self):
        dlg, body = dialog_base(self, "Add New Case")
        dialog_title(body, "➕  New Case")
        f = dialog_fields_frame(body)
        v_title  = label_entry(f, "Title *",     0)
        v_status = label_entry(f, "Status",      1, "OPEN",
                               options=["OPEN","PENDING","CLOSED","ARCHIVED"])
        v_opened = label_entry(f, "Date Opened", 2, date.today().isoformat())
        tk.Label(f, text="Description", bg=CARD_BG, fg=TEXT_MID,
                 font=FONT_SMALL).grid(row=3, column=0, sticky="nw",
                                        padx=(10,6), pady=5)
        txt = tk.Text(f, width=30, height=4, font=FONT_BODY,
                      bg=INPUT_BG, fg=TEXT_DARK,
                      insertbackground=ACCENT,
                      relief="flat", bd=0,
                      highlightbackground=BORDER, highlightthickness=1)
        txt.grid(row=3, column=1, sticky="ew", padx=(0,10), pady=5, ipady=4)
        def save():
            title = v_title.get().strip()
            if not title:
                messagebox.showwarning("Input Error","Title is required.",parent=dlg); return
            if title.isdigit():
                messagebox.showwarning("Invalid Title","Title cannot be purely numeric.",parent=dlg); return
            if not validate_date(v_opened.get()):
                messagebox.showwarning("Invalid Date","Use YYYY-MM-DD.",parent=dlg); return
            try:
                conn = get_conn()
                conn.execute("INSERT INTO CASES(Title,Description,Date_opened,Current_status) VALUES(:1,:2,:3,:4)",
                             (title,txt.get("1.0","end").strip(),v_opened.get(),v_status.get()))
                conn.commit(); conn.close(); dlg.destroy(); self._reload_cases()
            except Exception as ex: messagebox.showerror("Save Error",str(ex),parent=dlg)
        save_btn(body, "💾  Save Case", save)

    def edit_case_dialog(self):
        sel = self.case_tree.selection()
        if not sel: messagebox.showinfo("Select","Please select a case first."); return
        cid = self.case_tree.item(sel[0])["values"][0]
        conn = get_conn(); row = conn.execute("SELECT * FROM CASES WHERE Case_ID=:1",(cid,)).fetchone(); conn.close()
        if not row: messagebox.showerror("Error","Case not found."); return
        dlg, body = dialog_base(self, "Edit Case")
        dialog_title(body, f"✏  Edit Case #{cid}")
        f = dialog_fields_frame(body)
        v_title  = label_entry(f,"Title *",0,row[1])
        v_status = label_entry(f,"Status",1,row[5],options=["OPEN","PENDING","CLOSED","ARCHIVED"])
        v_opened = label_entry(f,"Date Opened",2, str(row[3])[:10] if row[3] else "")
        v_closed = label_entry(f,"Date Closed",3, str(row[4])[:10] if row[4] else "")
        tk.Label(f,text="Description",bg=CARD_BG,fg=TEXT_MID,font=FONT_SMALL).grid(row=4,column=0,sticky="nw",padx=(10,6),pady=5)
        txt = tk.Text(f,width=30,height=4,font=FONT_BODY,bg=INPUT_BG,fg=TEXT_DARK,insertbackground=ACCENT,relief="flat",bd=0,highlightbackground=BORDER,highlightthickness=1)
        txt.insert("1.0",row[2] or ""); txt.grid(row=4,column=1,sticky="ew",padx=(0,10),pady=5,ipady=4)
        def save():
            title = v_title.get().strip()
            if not title: messagebox.showwarning("Input Error","Title required.",parent=dlg); return
            if title.isdigit(): messagebox.showwarning("Invalid Title","Title cannot be purely numeric.",parent=dlg); return
            if not validate_date(v_opened.get()): messagebox.showwarning("Invalid Date","Use YYYY-MM-DD format.",parent=dlg); return
            if v_closed.get().strip() and not validate_date(v_closed.get().strip()): messagebox.showwarning("Invalid Date","Closed date must use YYYY-MM-DD format.",parent=dlg); return
            try:
                conn2 = get_conn()
                old_case = conn2.execute("SELECT Current_status FROM CASES WHERE Case_ID=:1",(cid,)).fetchone()
                conn2.execute("UPDATE CASES SET Title=:1,Description=:2,Date_opened=:3,Date_closed=:4,Current_status=:5 WHERE Case_ID=:6",
                              (title,txt.get("1.0","end").strip(),v_opened.get(),v_closed.get().strip() or None,v_status.get(),cid))
                if old_case and old_case[0] != v_status.get():
                    conn2.execute("INSERT INTO CASESTATUSLOG(Case_ID,New_status,Updated_by,Reason) VALUES(:1,:2,:3,:4)",
                                  (cid,v_status.get(),self.user['username'],'Status updated via Edit Case'))
                conn2.commit(); conn2.close(); dlg.destroy(); self._reload_cases()
            except Exception as ex: messagebox.showerror("Save Error",str(ex),parent=dlg)
        save_btn(body, "💾  Update Case", save)

    def delete_case(self):
        sel = self.case_tree.selection()
        if not sel: return
        cid = self.case_tree.item(sel[0])["values"][0]
        if messagebox.askyesno("Confirm Delete",
                f"Delete Case #{cid}?\n\nThis will fail if evidence or clues are linked.",
                icon="warning"):
            conn = get_conn()
            try:
                conn.execute("DELETE FROM CASES WHERE Case_ID=:1",(cid,)); conn.commit(); self._reload_cases()
            except Exception as ex:
                messagebox.showerror("Cannot Delete","Case has linked records.\n\n"+str(ex))
            conn.close()

    def view_case_detail(self):
        sel = self.case_tree.selection()
        if not sel: messagebox.showinfo("Select","Please select a case first."); return
        cid = self.case_tree.item(sel[0])["values"][0]
        conn = get_conn()
        case = conn.execute("SELECT * FROM CASES WHERE Case_ID=:1",(cid,)).fetchone()
        if not case: messagebox.showerror("Error","Case not found."); conn.close(); return
        evidence     = conn.execute("SELECT Evidence_ID,Type,Status,Description FROM EVIDENCE WHERE Case_ID=:1",(cid,)).fetchall()
        investigators = conn.execute("""SELECT p.Full_name,i.Rank,ci.Role FROM CASES_INVESTIGATORS ci
            JOIN INVESTIGATORS i ON ci.Investigator_ID=i.Investigator_ID
            JOIN PERSONS p ON i.Person_ID=p.Person_ID WHERE ci.Case_ID=:1""",(cid,)).fetchall()
        clues   = conn.execute("SELECT Clue_ID,Description,Discovery_date FROM CLUES WHERE Case_ID=:1",(cid,)).fetchall()
        history = conn.execute("SELECT History_ID,Old_status,Title,Changed_at FROM CASES_HISTORY WHERE Case_ID=:1 ORDER BY History_ID DESC",(cid,)).fetchall()
        conn.close()

        dlg = tk.Toplevel(self)
        dlg.title(f"Case #{cid} — {case[1]}")
        dlg.configure(bg=BG); dlg.geometry("780x640"); dlg.grab_set()

        # Header
        tk.Frame(dlg, bg=ACCENT, height=3).pack(fill="x")
        hdr = tk.Frame(dlg, bg=HEADER_BG, pady=16, padx=20)
        hdr.pack(fill="x")
        tk.Frame(hdr, bg=ACCENT, width=4).pack(side="left", fill="y", padx=(0,14))
        hdr_inner = tk.Frame(hdr, bg=HEADER_BG); hdr_inner.pack(side="left", fill="both", expand=True)
        tk.Label(hdr_inner, text=f"Case #{cid}: {case[1]}",
                 bg=HEADER_BG, fg=TEXT_DARK, font=FONT_HEAD).pack(anchor="w")
        status_color = STATUS_COLORS.get(str(case[5]), TEXT_LIGHT)
        tk.Label(hdr_inner, text=f"  Status: {case[5]}  ",
                 bg=status_color, fg="white",
                 font=("Segoe UI Semibold", 8), padx=8, pady=3).pack(anchor="w", pady=(4,0))

        # Info
        tk.Frame(dlg, bg=BORDER, height=1).pack(fill="x")
        info_f = tk.Frame(dlg, bg=CARD_BG, pady=12, padx=20)
        info_f.pack(fill="x")
        info_f.columnconfigure(1, weight=1); info_f.columnconfigure(3, weight=1)
        pairs = [("Opened", case[3]), ("Closed", case[4] or "—"),
                 ("Description", case[2] or "—")]
        for idx, (lbl, val) in enumerate(pairs):
            tk.Label(info_f, text=lbl+":", bg=CARD_BG, fg=TEXT_LIGHT,
                     font=FONT_SMALL).grid(row=idx, column=0, sticky="nw", padx=(0,10), pady=3)
            tk.Label(info_f, text=str(val), bg=CARD_BG, fg=TEXT_DARK,
                     font=FONT_BODY, wraplength=580, anchor="w",
                     justify="left").grid(row=idx, column=1, sticky="w", pady=3)

        # Notebook
        tk.Frame(dlg, bg=BORDER, height=1).pack(fill="x")
        nb = ttk.Notebook(dlg, style="Dark.TNotebook")
        nb.pack(fill="both", expand=True, padx=0, pady=0)
        for tab_name, tab_cols, tab_rows, col_widths in [
            ("Evidence",     ("ID","Type","Status","Description"),        evidence,      [60,110,100,340]),
            ("Investigators",("Name","Rank","Role"),                      investigators, [200,140,140]),
            ("Clues",        ("ID","Description","Date"),                 clues,         [60,400,130]),
            ("Edit History", ("HistID","Old Status","Title","Changed At"),history,        [70,110,240,180]),
        ]:
            tab_f = tk.Frame(nb, bg=BG)
            nb.add(tab_f, text=f"  {tab_name}  ({len(tab_rows)})  ")
            tf2, tree2 = make_tree(tab_f, tab_cols, heights=7)
            for col, w in zip(tab_cols, col_widths):
                tree2.heading(col, text=col); tree2.column(col, width=w, anchor="w")
            insert_rows(tree2, tab_rows)
            tf2.pack(fill="both", expand=True)

    def view_case_status_log(self):
        sel = self.case_tree.selection(); conn = get_conn()
        if sel:
            cid = self.case_tree.item(sel[0])["values"][0]
            rows = conn.execute("SELECT Log_ID,Case_ID,New_status,Updated_by,Updated_at,Reason FROM CASESTATUSLOG WHERE Case_ID=:1 ORDER BY Log_ID DESC",(cid,)).fetchall()
            title_text = f"Status Log — Case #{cid}"
        else:
            rows = conn.execute("SELECT * FROM (SELECT Log_ID,Case_ID,New_status,Updated_by,Updated_at,Reason FROM CASESTATUSLOG ORDER BY Log_ID DESC) WHERE ROWNUM <= 100").fetchall()
            title_text = "Status Log — All Cases (last 100)"
        conn.close()
        dlg = tk.Toplevel(self); dlg.title(title_text)
        dlg.configure(bg=BG); dlg.geometry("760x420"); dlg.grab_set()
        tk.Frame(dlg, bg=ACCENT, height=3).pack(fill="x")
        tk.Label(dlg, text=title_text, bg=HEADER_BG, fg=TEXT_DARK,
                 font=FONT_HEAD, pady=12, padx=20).pack(fill="x")
        tk.Frame(dlg, bg=BORDER, height=1).pack(fill="x")
        cols = ("LogID","CaseID","New Status","Updated By","Updated At","Reason")
        tf, tree = make_tree(dlg, cols, heights=11)
        for col, w in zip(cols, [60,70,110,130,160,200]):
            tree.heading(col, text=col); tree.column(col, width=w, anchor="w")
        if rows: insert_rows(tree, rows)
        else: tree.insert("","end",values=("—","—","No status changes logged yet","—","—","—"))
        tf.pack(fill="both", expand=True, padx=0)
        tk.Label(dlg, text=f"  {len(rows)} record(s)   ·   TRG_CASE_STATUS_AUDIT fires on every status UPDATE",
                 bg=HEADER_BG, fg=TEXT_LIGHT, font=FONT_TINY, pady=6).pack(fill="x")


    # ═══ EVIDENCE ════════════════════════════════════════════
    def show_evidence(self):
        page = self.content
        section_header(page,"Evidence","Track and manage forensic evidence")
        if not self._can("read"): return
        if self.role == "legal": read_only_notice(page)
        tb = tk.Frame(page, bg=BG, pady=10); tb.pack(fill="x", padx=16)
        if self._can("add"):
            styled_btn(tb,"+  Add Evidence",self.add_evidence_dialog).pack(side="left",padx=(0,8))
        cols = ("ID","Case","Type","Status","Collected By","Collection Date")
        tf, self.ev_tree = make_tree(page, cols)
        for col,w in zip(cols,[60,190,120,100,150,120]):
            self.ev_tree.heading(col,text=col); self.ev_tree.column(col,width=w)
        tf.pack(fill="both",expand=True,padx=16)
        act = tk.Frame(page,bg=HEADER_BG,pady=10); act.pack(fill="x")
        tk.Frame(act,bg=BORDER,height=1).pack(fill="x")
        btn_row = tk.Frame(act,bg=HEADER_BG); btn_row.pack(pady=8,padx=16,anchor="w")
        if self._can("edit"):
            styled_btn(btn_row,"✏  Edit",lambda: self.edit_evidence_dialog(),color=ACCENT_LIGHT,fg=ACCENT).pack(side="left",padx=(0,6))
        if self._can("delete"):
            danger_btn(btn_row,"🗑  Delete",lambda: self.delete_evidence()).pack(side="left",padx=(0,6))
        ghost_btn(btn_row,"📋  Audit Log",lambda: self.view_evidence_audit()).pack(side="left")
        self._reload_evidence()

    def _reload_evidence(self):
        for row in self.ev_tree.get_children(): self.ev_tree.delete(row)
        conn = get_conn()
        rows = conn.execute("""SELECT e.Evidence_ID,c.Title,e.Type,e.Status,
                   NVL(e.Collected_by,'—'),NVL(TO_CHAR(e.Collection_date,'YYYY-MM-DD'),'—')
            FROM EVIDENCE e JOIN CASES c ON e.Case_ID=c.Case_ID ORDER BY e.Evidence_ID DESC""").fetchall()
        insert_rows(self.ev_tree, rows); conn.close()

    def add_evidence_dialog(self):
        dlg, body = dialog_base(self,"Add Evidence"); dialog_title(body,"➕  Add Evidence")
        conn = get_conn(); cases = conn.execute("SELECT Case_ID,Title FROM CASES ORDER BY Case_ID").fetchall(); conn.close()
        case_opts = [f"{r[0]} — {r[1]}" for r in cases]
        f = dialog_fields_frame(body)
        v_case   = label_entry(f,"Case *",0,case_opts[0] if case_opts else "",options=case_opts)
        v_type   = label_entry(f,"Type *",1,options=["FIREARM","DIGITAL","CCTV_FOOTAGE","NARCOTICS","DOCUMENT","BIOLOGICAL","OTHER"])
        v_status = label_entry(f,"Status",2,"COLLECTED",options=["COLLECTED","IN_LAB","ANALYZED","ARCHIVED","DISPOSED"])
        v_by     = label_entry(f,"Collected By",3,self.user["full_name"])
        v_date   = label_entry(f,"Collection Date",4,date.today().isoformat())
        tk.Label(f,text="Description",bg=CARD_BG,fg=TEXT_MID,font=FONT_SMALL).grid(row=5,column=0,sticky="nw",padx=(10,6),pady=5)
        txt = tk.Text(f,width=30,height=3,font=FONT_BODY,bg=INPUT_BG,fg=TEXT_DARK,insertbackground=ACCENT,relief="flat",bd=0,highlightbackground=BORDER,highlightthickness=1)
        txt.grid(row=5,column=1,sticky="ew",padx=(0,10),pady=5,ipady=4)
        def save():
            if not v_case.get() or not v_type.get():
                messagebox.showwarning("Input Error","Case and Type required.",parent=dlg); return
            try:
                cid = int(v_case.get().split("—")[0].strip())
                conn2 = get_conn()
                conn2.execute("INSERT INTO EVIDENCE(Case_ID,Type,Description,Collected_by,Collection_date,Status) VALUES(:1,:2,:3,:4,:5,:6)",
                              (cid,v_type.get(),txt.get("1.0","end").strip(),v_by.get(),v_date.get(),v_status.get()))
                conn2.commit(); conn2.close(); dlg.destroy(); self._reload_evidence()
            except Exception as ex: messagebox.showerror("Save Error",str(ex),parent=dlg)
        save_btn(body,"💾  Save Evidence",save)

    def edit_evidence_dialog(self):
        sel = self.ev_tree.selection()
        if not sel: messagebox.showinfo("Select","Select evidence first."); return
        eid = self.ev_tree.item(sel[0])["values"][0]
        conn = get_conn(); row = conn.execute("SELECT * FROM EVIDENCE WHERE Evidence_ID=:1",(eid,)).fetchone(); conn.close()
        dlg, body = dialog_base(self,"Edit Evidence"); dialog_title(body,f"✏  Edit Evidence #{eid}")
        f = dialog_fields_frame(body)
        v_type   = label_entry(f,"Type",0,row[2],options=["FIREARM","DIGITAL","CCTV_FOOTAGE","NARCOTICS","DOCUMENT","BIOLOGICAL","OTHER"])
        v_status = label_entry(f,"Status",1,row[6],options=["COLLECTED","IN_LAB","ANALYZED","ARCHIVED","DISPOSED"])
        v_by     = label_entry(f,"Collected By",2,row[4] or "")
        v_date   = label_entry(f,"Collect Date",3, str(row[5])[:10] if row[5] else "")
        tk.Label(f,text="Description",bg=CARD_BG,fg=TEXT_MID,font=FONT_SMALL).grid(row=4,column=0,sticky="nw",padx=(10,6),pady=5)
        txt = tk.Text(f,width=30,height=3,font=FONT_BODY,bg=INPUT_BG,fg=TEXT_DARK,insertbackground=ACCENT,relief="flat",bd=0,highlightbackground=BORDER,highlightthickness=1)
        txt.insert("1.0",row[3] or ""); txt.grid(row=4,column=1,sticky="ew",padx=(0,10),pady=5,ipady=4)
        def save():
            try:
                conn2 = get_conn()
                old = conn2.execute("SELECT Type,Status FROM EVIDENCE WHERE Evidence_ID=:1",(eid,)).fetchone()
                conn2.execute("UPDATE EVIDENCE SET Type=:1,Description=:2,Collected_by=:3,Collection_date=:4,Status=:5 WHERE Evidence_ID=:6",
                              (v_type.get(),txt.get("1.0","end").strip(),v_by.get(),v_date.get(),v_status.get(),eid))
                if old and old[0] != v_type.get():
                    conn2.execute("INSERT INTO EVIDENCEAUDITLOG(Evidence_ID,Field_changed,Old_value,New_value,Changed_by) VALUES(:1,:2,:3,:4,:5)",
                                  (eid,'TYPE',old[0],v_type.get(),self.user['username']))
                if old and old[1] != v_status.get():
                    conn2.execute("INSERT INTO EVIDENCEAUDITLOG(Evidence_ID,Field_changed,Old_value,New_value,Changed_by) VALUES(:1,:2,:3,:4,:5)",
                                  (eid,'STATUS',old[1],v_status.get(),self.user['username']))
                conn2.commit(); conn2.close(); dlg.destroy(); self._reload_evidence()
            except Exception as ex: messagebox.showerror("Save Error",str(ex),parent=dlg)
        save_btn(body,"💾  Update Evidence",save)

    def delete_evidence(self):
        sel = self.ev_tree.selection()
        if not sel: return
        eid = self.ev_tree.item(sel[0])["values"][0]
        if messagebox.askyesno("Confirm",f"Delete Evidence #{eid}?",icon="warning"):
            conn = get_conn()
            try:
                conn.execute("DELETE FROM EVIDENCE WHERE Evidence_ID=:1",(eid,)); conn.commit()
            except Exception as ex:
                messagebox.showerror("Cannot Delete","Evidence has linked records.\n\n"+str(ex))
            conn.close(); self._reload_evidence()

    def view_evidence_audit(self):
        sel = self.ev_tree.selection(); conn = get_conn()
        if sel:
            eid = self.ev_tree.item(sel[0])["values"][0]
            rows = conn.execute("SELECT Log_ID,Evidence_ID,Field_changed,Old_value,New_value,Changed_by,Changed_at FROM EVIDENCEAUDITLOG WHERE Evidence_ID=:1 ORDER BY Log_ID DESC",(eid,)).fetchall()
            title_text = f"Audit Log — Evidence #{eid}"
        else:
            rows = conn.execute("SELECT * FROM (SELECT Log_ID,Evidence_ID,Field_changed,Old_value,New_value,Changed_by,Changed_at FROM EVIDENCEAUDITLOG ORDER BY Log_ID DESC) WHERE ROWNUM <= 100").fetchall()
            title_text = "Audit Log — All Evidence (last 100)"
        conn.close()
        dlg = tk.Toplevel(self); dlg.title(title_text)
        dlg.configure(bg=BG); dlg.geometry("800x420"); dlg.grab_set()
        tk.Frame(dlg,bg=ACCENT,height=3).pack(fill="x")
        tk.Label(dlg,text=title_text,bg=HEADER_BG,fg=TEXT_DARK,font=FONT_HEAD,pady=12,padx=20).pack(fill="x")
        tk.Frame(dlg,bg=BORDER,height=1).pack(fill="x")
        cols = ("LogID","EvidenceID","Field","Old Value","New Value","Changed By","Changed At")
        tf, tree = make_tree(dlg,cols,heights=11)
        for col,w in zip(cols,[60,80,90,130,130,120,160]):
            tree.heading(col,text=col); tree.column(col,width=w,anchor="w")
        if rows: insert_rows(tree,rows)
        else: tree.insert("","end",values=("—","—","No audit records yet","—","—","—","—"))
        tf.pack(fill="both",expand=True)
        tk.Label(dlg,text=f"  {len(rows)} record(s)   ·   TRG_EVIDENCE_AUDIT fires on Status & Type changes",
                 bg=HEADER_BG,fg=TEXT_LIGHT,font=FONT_TINY,pady=6).pack(fill="x")

    # ═══ SUSPECTS ════════════════════════════════════════════
    def show_suspects(self):
        page = self.content
        section_header(page,"Suspects","Manage suspect profiles and threat assessments")
        tb = tk.Frame(page,bg=BG,pady=10); tb.pack(fill="x",padx=16)
        if self._can("add"):
            styled_btn(tb,"+  Add Suspect",self.add_suspect_dialog).pack(side="left",padx=(0,8))
        cols = ("SuspectID","Name","CNIC","Contact","Threat Level","Status")
        tf, self.sus_tree = make_tree(page,cols)
        for col,w in zip(cols,[80,190,150,130,110,100]):
            self.sus_tree.heading(col,text=col); self.sus_tree.column(col,width=w)
        tf.pack(fill="both",expand=True,padx=16)
        act = tk.Frame(page,bg=HEADER_BG,pady=10); act.pack(fill="x")
        tk.Frame(act,bg=BORDER,height=1).pack(fill="x")
        btn_row = tk.Frame(act,bg=HEADER_BG); btn_row.pack(pady=8,padx=16,anchor="w")
        if self._can("edit"):
            styled_btn(btn_row,"✏  Edit",lambda: self.edit_suspect_dialog(),color=ACCENT_LIGHT,fg=ACCENT).pack(side="left",padx=(0,6))
        if self._can("delete"):
            danger_btn(btn_row,"🗑  Delete",lambda: self.delete_suspect()).pack(side="left")
        self._reload_suspects()

    def _reload_suspects(self):
        for row in self.sus_tree.get_children(): self.sus_tree.delete(row)
        conn = get_conn()
        rows = conn.execute("""SELECT s.Suspect_ID,p.Full_name,p.CNIC,NVL(p.Contact_number,'—'),s.Threat_level,s.Status
            FROM SUSPECTS s JOIN PERSONS p ON s.Person_ID=p.Person_ID ORDER BY s.Suspect_ID""").fetchall()
        insert_rows(self.sus_tree,rows); conn.close()

    def add_suspect_dialog(self):
        dlg, body = dialog_base(self,"Add Suspect"); dialog_title(body,"➕  New Suspect")
        f = dialog_fields_frame(body)
        v_name   = label_entry(f,"Full Name *",0)
        v_cnic   = label_entry(f,"CNIC *",1)
        tk.Label(f,text="Format: 12345-1234567-1",bg=CARD_BG,fg=TEXT_LIGHT,font=FONT_TINY).grid(row=1,column=2,sticky="w",padx=4)
        v_cont   = label_entry(f,"Contact",2)
        v_addr   = label_entry(f,"Address",3)
        v_threat = label_entry(f,"Threat Level",4,"MEDIUM",options=["LOW","MEDIUM","HIGH","CRITICAL"])
        v_status = label_entry(f,"Status",5,"ACTIVE",options=["ACTIVE","CLEARED","ARRESTED","RELEASED"])
        def save():
            if not v_name.get().strip() or not v_cnic.get().strip():
                messagebox.showwarning("Input Error","Name and CNIC required.",parent=dlg); return
            if not validate_name(v_name.get().strip()):
                messagebox.showwarning("Invalid Name","Name must contain letters, not just numbers.",parent=dlg); return
            if not validate_cnic(v_cnic.get()):
                messagebox.showwarning("Invalid CNIC","Format must be: 12345-1234567-1",parent=dlg); return
            try:
                conn = get_conn()
                conn.execute("INSERT INTO PERSONS(Full_name,CNIC,Contact_number,Address) VALUES(:1,:2,:3,:4)",
                             (v_name.get().strip(),v_cnic.get().strip(),v_cont.get(),v_addr.get()))
                pid = conn.execute("SELECT SEQ_PERSON_ID.CURRVAL FROM DUAL").fetchone()[0]
                conn.execute("INSERT INTO SUSPECTS(Person_ID,Threat_level,Status) VALUES(:1,:2,:3)",
                             (pid,v_threat.get(),v_status.get()))
                conn.commit(); conn.close(); dlg.destroy(); self._reload_suspects()
            except Exception as ex: messagebox.showerror("Error",str(ex),parent=dlg)
        save_btn(body,"💾  Save Suspect",save)

    def edit_suspect_dialog(self):
        sel = self.sus_tree.selection()
        if not sel: messagebox.showinfo("Select","Select suspect first."); return
        sid = self.sus_tree.item(sel[0])["values"][0]
        conn = get_conn()
        row = conn.execute("""SELECT p.Full_name,p.CNIC,p.Contact_number,p.Address,
                   s.Threat_level,s.Status,p.Person_ID
            FROM SUSPECTS s JOIN PERSONS p ON s.Person_ID=p.Person_ID WHERE s.Suspect_ID=:1""",(sid,)).fetchone()
        conn.close()
        dlg, body = dialog_base(self,"Edit Suspect"); dialog_title(body,f"✏  Edit Suspect #{sid}")
        f = dialog_fields_frame(body)
        v_name   = label_entry(f,"Full Name",0,row[0]); v_cnic  = label_entry(f,"CNIC",1,row[1])
        v_cont   = label_entry(f,"Contact",2,row[2] or ""); v_addr  = label_entry(f,"Address",3,row[3] or "")
        v_threat = label_entry(f,"Threat",4,row[4],options=["LOW","MEDIUM","HIGH","CRITICAL"])
        v_status = label_entry(f,"Status",5,row[5],options=["ACTIVE","CLEARED","ARRESTED","RELEASED"])
        pid = row[6]
        def save():
            if not v_name.get().strip():
                messagebox.showwarning("Input Error","Name is required.",parent=dlg); return
            if not validate_name(v_name.get().strip()):
                messagebox.showwarning("Invalid Name","Name must contain letters, not just numbers.",parent=dlg); return
            if not validate_cnic(v_cnic.get()):
                messagebox.showwarning("Invalid CNIC","Format must be: 12345-1234567-1",parent=dlg); return
            try:
                conn2 = get_conn()
                conn2.execute("UPDATE PERSONS SET Full_name=:1,CNIC=:2,Contact_number=:3,Address=:4 WHERE Person_ID=:5",
                              (v_name.get().strip(),v_cnic.get().strip(),v_cont.get(),v_addr.get(),pid))
                conn2.execute("UPDATE SUSPECTS SET Threat_level=:1,Status=:2 WHERE Suspect_ID=:3",
                              (v_threat.get(),v_status.get(),sid))
                conn2.commit(); conn2.close(); dlg.destroy(); self._reload_suspects()
            except Exception as ex: messagebox.showerror("Save Error",str(ex),parent=dlg)
        save_btn(body,"💾  Update Suspect",save)

    def delete_suspect(self):
        sel = self.sus_tree.selection()
        if not sel: return
        sid = self.sus_tree.item(sel[0])["values"][0]
        if messagebox.askyesno("Confirm",f"Delete Suspect #{sid}?",icon="warning"):
            conn = get_conn()
            try:
                pid = conn.execute("SELECT Person_ID FROM SUSPECTS WHERE Suspect_ID=:1",(sid,)).fetchone()[0]
                conn.execute("DELETE FROM SUSPECTS WHERE Suspect_ID=:1",(sid,))
                conn.execute("DELETE FROM PERSONS WHERE Person_ID=:1",(pid,))
                conn.commit()
            except Exception as ex: messagebox.showerror("Error",str(ex))
            conn.close(); self._reload_suspects()


    # ═══ INVESTIGATORS ═══════════════════════════════════════
    def show_investigators(self):
        page = self.content
        section_header(page,"Investigators","Manage investigator profiles and assignments")
        tb = tk.Frame(page,bg=BG,pady=10); tb.pack(fill="x",padx=16)
        if self._can("add"):
            styled_btn(tb,"+  Add Investigator",self.add_inv_dialog).pack(side="left",padx=(0,8))
        cols = ("InvID","Name","CNIC","Rank","Department","Batch")
        tf, self.inv_tree = make_tree(page,cols)
        for col,w in zip(cols,[60,190,150,120,180,110]):
            self.inv_tree.heading(col,text=col); self.inv_tree.column(col,width=w)
        tf.pack(fill="both",expand=True,padx=16)
        act = tk.Frame(page,bg=HEADER_BG,pady=10); act.pack(fill="x")
        tk.Frame(act,bg=BORDER,height=1).pack(fill="x")
        btn_row = tk.Frame(act,bg=HEADER_BG); btn_row.pack(pady=8,padx=16,anchor="w")
        if self._can("edit"):
            styled_btn(btn_row,"✏  Edit",lambda: self.edit_inv_dialog(),color=ACCENT_LIGHT,fg=ACCENT).pack(side="left",padx=(0,6))
        if self._can("delete"):
            danger_btn(btn_row,"🗑  Delete",lambda: self.delete_inv()).pack(side="left")
        self._reload_investigators()

    def _reload_investigators(self):
        for row in self.inv_tree.get_children(): self.inv_tree.delete(row)
        conn = get_conn()
        rows = conn.execute("""SELECT i.Investigator_ID,p.Full_name,p.CNIC,NVL(i.Rank,'—'),
                   NVL(i.Department,'—'),NVL(i.Batch_no,'—')
            FROM INVESTIGATORS i JOIN PERSONS p ON i.Person_ID=p.Person_ID ORDER BY i.Investigator_ID""").fetchall()
        insert_rows(self.inv_tree,rows); conn.close()

    def add_inv_dialog(self):
        dlg, body = dialog_base(self,"Add Investigator"); dialog_title(body,"➕  New Investigator")
        f = dialog_fields_frame(body)
        v_name  = label_entry(f,"Full Name *",0); v_cnic  = label_entry(f,"CNIC *",1)
        v_cont  = label_entry(f,"Contact",2); v_addr = label_entry(f,"Address",3)
        v_rank  = label_entry(f,"Rank",4); v_dept  = label_entry(f,"Department",5)
        v_batch = label_entry(f,"Batch No",6)
        def save():
            if not v_name.get().strip() or not v_cnic.get().strip():
                messagebox.showwarning("Input Error","Name and CNIC required.",parent=dlg); return
            if not validate_name(v_name.get().strip()):
                messagebox.showwarning("Invalid Name","Name must contain letters.",parent=dlg); return
            if not validate_cnic(v_cnic.get()):
                messagebox.showwarning("Invalid CNIC","Format must be: 12345-1234567-1",parent=dlg); return
            try:
                conn = get_conn()
                conn.execute("INSERT INTO PERSONS(Full_name,CNIC,Contact_number,Address) VALUES(:1,:2,:3,:4)",
                             (v_name.get().strip(),v_cnic.get().strip(),v_cont.get(),v_addr.get()))
                pid = conn.execute("SELECT SEQ_PERSON_ID.CURRVAL FROM DUAL").fetchone()[0]
                conn.execute("INSERT INTO INVESTIGATORS(Person_ID,Rank,Department,Batch_no) VALUES(:1,:2,:3,:4)",
                             (pid,v_rank.get(),v_dept.get(),v_batch.get()))
                conn.commit(); conn.close(); dlg.destroy(); self._reload_investigators()
            except Exception as ex: messagebox.showerror("Error",str(ex),parent=dlg)
        save_btn(body,"💾  Save Investigator",save)

    def edit_inv_dialog(self):
        sel = self.inv_tree.selection()
        if not sel: messagebox.showinfo("Select","Select investigator first."); return
        iid = self.inv_tree.item(sel[0])["values"][0]
        conn = get_conn()
        row = conn.execute("""SELECT p.Full_name,p.CNIC,p.Contact_number,p.Address,
                   i.Rank,i.Department,i.Batch_no,p.Person_ID
            FROM INVESTIGATORS i JOIN PERSONS p ON i.Person_ID=p.Person_ID WHERE i.Investigator_ID=:1""",(iid,)).fetchone()
        conn.close()
        dlg, body = dialog_base(self,"Edit Investigator"); dialog_title(body,f"✏  Edit Investigator #{iid}")
        f = dialog_fields_frame(body)
        v_name  = label_entry(f,"Full Name",0,row[0]); v_cnic  = label_entry(f,"CNIC",1,row[1])
        v_cont  = label_entry(f,"Contact",2,row[2] or ""); v_addr  = label_entry(f,"Address",3,row[3] or "")
        v_rank  = label_entry(f,"Rank",4,row[4] or ""); v_dept  = label_entry(f,"Department",5,row[5] or "")
        v_batch = label_entry(f,"Batch No",6,row[6] or ""); pid = row[7]
        def save():
            try:
                conn2 = get_conn()
                conn2.execute("UPDATE PERSONS SET Full_name=:1,CNIC=:2,Contact_number=:3,Address=:4 WHERE Person_ID=:5",
                              (v_name.get(),v_cnic.get().strip(),v_cont.get(),v_addr.get(),pid))
                conn2.execute("UPDATE INVESTIGATORS SET Rank=:1,Department=:2,Batch_no=:3 WHERE Investigator_ID=:4",
                              (v_rank.get(),v_dept.get(),v_batch.get(),iid))
                conn2.commit(); conn2.close(); dlg.destroy(); self._reload_investigators()
            except Exception as ex: messagebox.showerror("Save Error",str(ex),parent=dlg)
        save_btn(body,"💾  Update Investigator",save)

    def delete_inv(self):
        sel = self.inv_tree.selection()
        if not sel: return
        iid = self.inv_tree.item(sel[0])["values"][0]
        if messagebox.askyesno("Confirm",f"Delete Investigator #{iid}?",icon="warning"):
            conn = get_conn()
            try:
                pid = conn.execute("SELECT Person_ID FROM INVESTIGATORS WHERE Investigator_ID=:1",(iid,)).fetchone()[0]
                conn.execute("DELETE FROM INVESTIGATORS WHERE Investigator_ID=:1",(iid,))
                conn.execute("DELETE FROM PERSONS WHERE Person_ID=:1",(pid,))
                conn.commit()
            except Exception as ex: messagebox.showerror("Error",str(ex))
            conn.close(); self._reload_investigators()

    # ═══ CLUES ═══════════════════════════════════════════════
    def show_clues(self):
        page = self.content
        section_header(page,"Clues","Track all investigative clues linked to cases and evidence")
        tb = tk.Frame(page,bg=BG,pady=10); tb.pack(fill="x",padx=16)
        if self._can("add"):
            styled_btn(tb,"+  Add Clue",self.add_clue_dialog).pack(side="left",padx=(0,8))
        cols = ("ID","Case","Evidence","Description","Discovered","Recorded By")
        tf, self.clue_tree = make_tree(page,cols)
        for col,w in zip(cols,[50,180,70,290,110,140]):
            self.clue_tree.heading(col,text=col)
            self.clue_tree.column(col,width=w,anchor="w" if col=="Description" else "center")
        tf.pack(fill="both",expand=True,padx=16)
        act = tk.Frame(page,bg=HEADER_BG,pady=10); act.pack(fill="x")
        tk.Frame(act,bg=BORDER,height=1).pack(fill="x")
        btn_row = tk.Frame(act,bg=HEADER_BG); btn_row.pack(pady=8,padx=16,anchor="w")
        if self._can("delete"):
            danger_btn(btn_row,"🗑  Delete",lambda: self.delete_clue()).pack(side="left")
        self._reload_clues()

    def _reload_clues(self):
        for row in self.clue_tree.get_children(): self.clue_tree.delete(row)
        conn = get_conn()
        rows = conn.execute("""SELECT cl.Clue_ID,c.Title,NVL(TO_CHAR(cl.Evidence_ID),'—'),
                   cl.Description,NVL(TO_CHAR(cl.Discovery_date,'YYYY-MM-DD'),'—'),NVL(cl.Recorded_by,'—')
            FROM CLUES cl JOIN CASES c ON cl.Case_ID=c.Case_ID ORDER BY cl.Clue_ID DESC""").fetchall()
        insert_rows(self.clue_tree,rows); conn.close()

    def add_clue_dialog(self):
        dlg, body = dialog_base(self,"Add Clue"); dialog_title(body,"➕  New Clue")
        conn = get_conn()
        cases = conn.execute("SELECT Case_ID,Title FROM CASES").fetchall()
        evids = conn.execute("SELECT Evidence_ID,Type FROM EVIDENCE").fetchall()
        conn.close()
        case_opts = [f"{r[0]} — {r[1]}" for r in cases]
        ev_opts   = ["None"] + [f"{r[0]} — {r[1]}" for r in evids]
        f = dialog_fields_frame(body)
        v_case = label_entry(f,"Case *",0,case_opts[0] if case_opts else "",options=case_opts)
        v_ev   = label_entry(f,"Evidence (opt)",1,"None",options=ev_opts)
        v_by   = label_entry(f,"Recorded By",2,self.user["full_name"])
        v_date = label_entry(f,"Discovery Date",3,date.today().isoformat())
        tk.Label(f,text="Description *",bg=CARD_BG,fg=TEXT_MID,font=FONT_SMALL).grid(row=4,column=0,sticky="nw",padx=(10,6),pady=5)
        txt = tk.Text(f,width=30,height=4,font=FONT_BODY,bg=INPUT_BG,fg=TEXT_DARK,insertbackground=ACCENT,relief="flat",bd=0,highlightbackground=BORDER,highlightthickness=1)
        txt.grid(row=4,column=1,sticky="ew",padx=(0,10),pady=5,ipady=4)
        def save():
            desc = txt.get("1.0","end").strip()
            if not v_case.get() or not desc:
                messagebox.showwarning("Input Error","Case and Description required.",parent=dlg); return
            cid = int(v_case.get().split("—")[0].strip())
            eid = None if v_ev.get()=="None" else int(v_ev.get().split("—")[0].strip())
            try:
                conn2 = get_conn()
                conn2.execute("INSERT INTO CLUES(Case_ID,Evidence_ID,Description,Discovery_date,Recorded_by) VALUES(:1,:2,:3,:4,:5)",
                              (cid,eid,desc,v_date.get(),v_by.get()))
                conn2.commit(); conn2.close(); dlg.destroy(); self._reload_clues()
            except Exception as ex: messagebox.showerror("Error",str(ex),parent=dlg)
        save_btn(body,"💾  Save Clue",save)

    def delete_clue(self):
        sel = self.clue_tree.selection()
        if not sel: return
        cid = self.clue_tree.item(sel[0])["values"][0]
        if messagebox.askyesno("Confirm",f"Delete Clue #{cid}?",icon="warning"):
            conn = get_conn()
            conn.execute("DELETE FROM CLUES WHERE Clue_ID=:1",(cid,))
            conn.commit(); conn.close(); self._reload_clues()

    # ═══ CHAIN OF CUSTODY ════════════════════════════════════
    def show_custody(self):
        page = self.content
        section_header(page,"Chain of Custody","Complete evidence transfer and access audit trail")
        tb = tk.Frame(page,bg=BG,pady=10); tb.pack(fill="x",padx=16)
        if self._can("add"):
            styled_btn(tb,"+  Log Transfer",self.add_custody_dialog).pack(side="left",padx=(0,8))
        cols = ("ID","Evidence","From","To","Access Type","Timestamp","Locked","Reason")
        tf, self.coc_tree = make_tree(page,cols)
        for col,w in zip(cols,[50,80,140,140,100,160,60,190]):
            self.coc_tree.heading(col,text=col); self.coc_tree.column(col,width=w)
        tf.pack(fill="both",expand=True,padx=16)
        self._reload_custody()

    def _reload_custody(self):
        for row in self.coc_tree.get_children(): self.coc_tree.delete(row)
        conn = get_conn()
        rows = conn.execute("""SELECT coc.Transfer_ID,coc.Evidence_ID,
                   NVL(pf.Full_name,'—'),pt.Full_name,
                   NVL(coc.Access_type,'—'),coc.Transfer_timestamp,
                   CASE coc.Is_locked WHEN 'Y' THEN '🔒 Yes' ELSE '🔓 No' END,
                   NVL(coc.Reason,'—')
            FROM CHAINOFCUSTODYLOG coc
            JOIN PERSONS pt ON coc.Transferred_to_id=pt.Person_ID
            LEFT JOIN PERSONS pf ON coc.Transferred_from_id=pf.Person_ID
            ORDER BY coc.Transfer_ID DESC""").fetchall()
        insert_rows(self.coc_tree,rows); conn.close()

    def _get_custody_persons(self, conn):
        investigators = conn.execute("""SELECT P.Person_ID, P.Full_name
            FROM PERSONS P JOIN INVESTIGATORS I ON P.Person_ID=I.Person_ID
            ORDER BY P.Full_name""").fetchall()
        lab_techs = conn.execute("""SELECT P.Person_ID, P.Full_name
            FROM PERSONS P
            JOIN SYSTEM_USERS SU ON LOWER(TRIM(P.Full_name)) = LOWER(TRIM(SU.Full_name))
            WHERE SU.Role = 'lab_tech'
            ORDER BY P.Full_name""").fetchall()
        options = []; seen_ids = set()
        for pid, name in investigators:
            if pid not in seen_ids:
                options.append((pid, f"{pid} — {name}")); seen_ids.add(pid)
        for pid, name in lab_techs:
            if pid not in seen_ids:
                options.append((pid, f"{pid} — {name}  [Lab Tech]")); seen_ids.add(pid)
        return options

    def add_custody_dialog(self):
        dlg, body = dialog_base(self,"Log Custody Transfer"); dialog_title(body,"🔗  New Transfer Log")
        conn = get_conn()
        evids = conn.execute("SELECT Evidence_ID,Type FROM EVIDENCE").fetchall()
        person_options = self._get_custody_persons(conn)
        conn.close()
        ev_opts  = [f"{r[0]} — {r[1]}" for r in evids]
        per_opts = [label for _, label in person_options]
        from_opts = ["None"] + per_opts
        f = dialog_fields_frame(body)
        tk.Label(f,text="Only Investigators & Lab Techs shown in dropdowns.",bg=CARD_BG,fg=TEXT_LIGHT,font=FONT_TINY).grid(row=0,columnspan=3,sticky="w",padx=(10,6),pady=(0,4))
        v_ev     = label_entry(f,"Evidence *",1,ev_opts[0] if ev_opts else "",options=ev_opts)
        v_from   = label_entry(f,"Transferred From",2,"None",options=from_opts)
        v_to     = label_entry(f,"Transferred To *",3,per_opts[0] if per_opts else "",options=per_opts)
        v_type   = label_entry(f,"Access Type",4,"TRANSFER",options=["TRANSFER","ANALYSIS","RE-EXAMINATION","RETURN","DISPOSAL"])
        v_locked = label_entry(f,"Lock Record",5,"N",options=["N","Y"])
        v_reason = label_entry(f,"Reason",6)
        def _pid(val): return int(val.split("—")[0].strip())
        def save():
            if not v_ev.get() or not v_to.get():
                messagebox.showwarning("Input Error","Evidence and To-Person required.",parent=dlg); return
            try:
                eid   = int(v_ev.get().split("—")[0].strip())
                to_id = _pid(v_to.get())
                from_id = None if v_from.get()=="None" else _pid(v_from.get())
                conn2 = get_conn()
                conn2.execute("INSERT INTO CHAINOFCUSTODYLOG(Evidence_ID,Transferred_from_id,Transferred_to_id,Access_type,Reason,Is_locked) VALUES(:1,:2,:3,:4,:5,:6)",
                              (eid,from_id,to_id,v_type.get(),v_reason.get(),v_locked.get()))
                conn2.commit(); conn2.close(); dlg.destroy(); self._reload_custody()
            except Exception as ex: messagebox.showerror("Error",str(ex),parent=dlg)
        save_btn(body,"💾  Save Transfer",save)

    # ═══ LAB REQUESTS ════════════════════════════════════════
    def show_lab(self):
        page = self.content
        section_header(page,"Lab Analysis Requests","Manage forensic laboratory analysis requests")
        tb = tk.Frame(page,bg=BG,pady=10); tb.pack(fill="x",padx=16)
        if self.role in ("dba","supervisor","investigator"):
            styled_btn(tb,"+  New Request",self.add_lab_dialog).pack(side="left",padx=(0,8))
        cols = ("ID","Evidence","Analysis Type","Requested By","Date","Status")
        tf, self.lab_tree = make_tree(page,cols)
        for col,w in zip(cols,[50,90,200,160,110,110]):
            self.lab_tree.heading(col,text=col); self.lab_tree.column(col,width=w)
        tf.pack(fill="both",expand=True,padx=16)
        act = tk.Frame(page,bg=HEADER_BG,pady=10); act.pack(fill="x")
        tk.Frame(act,bg=BORDER,height=1).pack(fill="x")
        btn_row = tk.Frame(act,bg=HEADER_BG); btn_row.pack(pady=8,padx=16,anchor="w")
        if self._can("edit") or self.role=="lab_tech":
            styled_btn(btn_row,"✏  Update Status",lambda: self.update_lab_status(),color=ACCENT_LIGHT,fg=ACCENT).pack(side="left")
        self._reload_lab()

    def _reload_lab(self):
        for row in self.lab_tree.get_children(): self.lab_tree.delete(row)
        conn = get_conn()
        rows = conn.execute("SELECT Request_ID,Evidence_ID,Analysis_type,Requested_by,Request_date,Status FROM LABANALYSISREQUEST ORDER BY Request_ID DESC").fetchall()
        insert_rows(self.lab_tree,rows); conn.close()

    def add_lab_dialog(self):
        dlg, body = dialog_base(self,"New Lab Request"); dialog_title(body,"🧪  Lab Analysis Request")
        conn = get_conn(); evids = conn.execute("SELECT Evidence_ID,Type FROM EVIDENCE").fetchall(); conn.close()
        ev_opts = [f"{r[0]} — {r[1]}" for r in evids]
        f = dialog_fields_frame(body)
        v_ev     = label_entry(f,"Evidence *",0,ev_opts[0] if ev_opts else "",options=ev_opts)
        v_atype  = label_entry(f,"Analysis Type *",1)
        v_reqby  = label_entry(f,"Requested By *",2,self.user["full_name"])
        v_date   = label_entry(f,"Request Date",3,date.today().isoformat())
        v_status = label_entry(f,"Status",4,"PENDING",options=["PENDING","IN_PROGRESS","COMPLETED","REJECTED"])
        def save():
            if not v_ev.get() or not v_atype.get().strip() or not v_reqby.get().strip():
                messagebox.showwarning("Input Error","Evidence, Type and Requester required.",parent=dlg); return
            try:
                eid = int(v_ev.get().split("—")[0].strip())
                conn2 = get_conn()
                conn2.execute("INSERT INTO LABANALYSISREQUEST(Evidence_ID,Analysis_type,Requested_by,Request_date,Status) VALUES(:1,:2,:3,:4,:5)",
                              (eid,v_atype.get(),v_reqby.get(),v_date.get(),v_status.get()))
                conn2.commit(); conn2.close(); dlg.destroy(); self._reload_lab()
            except Exception as ex: messagebox.showerror("Error",str(ex),parent=dlg)
        save_btn(body,"💾  Submit Request",save)

    def update_lab_status(self):
        sel = self.lab_tree.selection()
        if not sel: messagebox.showinfo("Select","Select a request first."); return
        rid = self.lab_tree.item(sel[0])["values"][0]
        dlg, body = dialog_base(self,"Update Lab Status"); dialog_title(body,f"✏  Update Request #{rid}")
        f = dialog_fields_frame(body)
        v_st = label_entry(f,"New Status",0,"PENDING",options=["PENDING","IN_PROGRESS","COMPLETED","REJECTED"])
        def save():
            conn = get_conn()
            conn.execute("UPDATE LABANALYSISREQUEST SET Status=:1 WHERE Request_ID=:2",(v_st.get(),rid))
            conn.commit(); conn.close(); dlg.destroy(); self._reload_lab()
        save_btn(body,"✔  Update Status",save)

    # ═══ FORENSIC RECORDS ════════════════════════════════════
    def show_records(self):
        page = self.content
        section_header(page,"Forensic Records","Official investigation documents and reports")
        if self.role=="legal": read_only_notice(page)
        tb = tk.Frame(page,bg=BG,pady=10); tb.pack(fill="x",padx=16)
        if self._can("add"):
            styled_btn(tb,"+  New Record",self.add_record_dialog).pack(side="left",padx=(0,8))
        cols = ("ID","Case","Record Type","Status","Prepared By","Date")
        tf, self.rec_tree = make_tree(page,cols)
        for col,w in zip(cols,[50,210,180,100,160,110]):
            self.rec_tree.heading(col,text=col); self.rec_tree.column(col,width=w)
        tf.pack(fill="both",expand=True,padx=16)
        act = tk.Frame(page,bg=HEADER_BG,pady=10); act.pack(fill="x")
        tk.Frame(act,bg=BORDER,height=1).pack(fill="x")
        btn_row = tk.Frame(act,bg=HEADER_BG); btn_row.pack(pady=8,padx=16,anchor="w")
        if self._can("edit"):
            styled_btn(btn_row,"✏  Edit",lambda: self.edit_record_dialog(),color=ACCENT_LIGHT,fg=ACCENT).pack(side="left",padx=(0,6))
        if self._can("delete"):
            danger_btn(btn_row,"🗑  Delete",lambda: self.delete_record()).pack(side="left")
        self._reload_records()

    def _reload_records(self):
        for row in self.rec_tree.get_children(): self.rec_tree.delete(row)
        conn = get_conn()
        rows = conn.execute("""SELECT fr.Record_ID,c.Title,fr.Record_type,fr.Status,
                   NVL(fr.Prepared_by,'—'),TO_CHAR(fr.Record_date,'YYYY-MM-DD')
            FROM FORENSIC_RECORD fr JOIN CASES c ON fr.Case_ID=c.Case_ID ORDER BY fr.Record_ID DESC""").fetchall()
        insert_rows(self.rec_tree,rows); conn.close()

    def add_record_dialog(self):
        dlg, body = dialog_base(self,"New Forensic Record"); dialog_title(body,"📋  New Forensic Record")
        conn = get_conn(); cases = conn.execute("SELECT Case_ID,Title FROM CASES").fetchall(); conn.close()
        case_opts = [f"{r[0]} — {r[1]}" for r in cases]
        f = dialog_fields_frame(body)
        v_case   = label_entry(f,"Case *",0,case_opts[0] if case_opts else "",options=case_opts)
        v_rtype  = label_entry(f,"Record Type *",1)
        v_prepby = label_entry(f,"Prepared By",2,self.user["full_name"])
        v_date   = label_entry(f,"Record Date",3,date.today().isoformat())
        v_status = label_entry(f,"Status",4,"DRAFT",options=["DRAFT","FINAL","ARCHIVED"])
        tk.Label(f,text="Description",bg=CARD_BG,fg=TEXT_MID,font=FONT_SMALL).grid(row=5,column=0,sticky="nw",padx=(10,6),pady=5)
        txt = tk.Text(f,width=30,height=4,font=FONT_BODY,bg=INPUT_BG,fg=TEXT_DARK,insertbackground=ACCENT,relief="flat",bd=0,highlightbackground=BORDER,highlightthickness=1)
        txt.grid(row=5,column=1,sticky="ew",padx=(0,10),pady=5,ipady=4)
        def save():
            if not v_case.get() or not v_rtype.get().strip():
                messagebox.showwarning("Input Error","Case and Record Type required.",parent=dlg); return
            try:
                cid = int(v_case.get().split("—")[0].strip())
                conn2 = get_conn()
                conn2.execute("INSERT INTO FORENSIC_RECORD(Case_ID,Record_type,Prepared_by,Record_date,Description,Status) VALUES(:1,:2,:3,:4,:5,:6)",
                              (cid,v_rtype.get(),v_prepby.get(),v_date.get(),txt.get("1.0","end").strip(),v_status.get()))
                conn2.commit(); conn2.close(); dlg.destroy(); self._reload_records()
            except Exception as ex: messagebox.showerror("Error",str(ex),parent=dlg)
        save_btn(body,"💾  Save Record",save)

    def edit_record_dialog(self):
        sel = self.rec_tree.selection()
        if not sel: messagebox.showinfo("Select","Select a record first."); return
        rid = self.rec_tree.item(sel[0])["values"][0]
        conn = get_conn(); row = conn.execute("SELECT * FROM FORENSIC_RECORD WHERE Record_ID=:1",(rid,)).fetchone(); conn.close()
        dlg, body = dialog_base(self,"Edit Record"); dialog_title(body,f"✏  Edit Record #{rid}")
        f = dialog_fields_frame(body)
        v_rtype  = label_entry(f,"Record Type",0,row[2]); v_prepby = label_entry(f,"Prepared By",1,row[4] or "")
        v_date   = label_entry(f,"Record Date",2, str(row[3])[:10] if row[3] else "")
        v_status = label_entry(f,"Status",3,row[6],options=["DRAFT","FINAL","ARCHIVED"])
        tk.Label(f,text="Description",bg=CARD_BG,fg=TEXT_MID,font=FONT_SMALL).grid(row=4,column=0,sticky="nw",padx=(10,6),pady=5)
        txt = tk.Text(f,width=30,height=4,font=FONT_BODY,bg=INPUT_BG,fg=TEXT_DARK,insertbackground=ACCENT,relief="flat",bd=0,highlightbackground=BORDER,highlightthickness=1)
        txt.insert("1.0",row[5] or ""); txt.grid(row=4,column=1,sticky="ew",padx=(0,10),pady=5,ipady=4)
        def save():
            try:
                conn2 = get_conn()
                conn2.execute("UPDATE FORENSIC_RECORD SET Record_type=:1,Prepared_by=:2,Record_date=:3,Description=:4,Status=:5 WHERE Record_ID=:6",
                              (v_rtype.get(),v_prepby.get(),v_date.get(),txt.get("1.0","end").strip(),v_status.get(),rid))
                conn2.commit(); conn2.close(); dlg.destroy(); self._reload_records()
            except Exception as ex: messagebox.showerror("Save Error",str(ex),parent=dlg)
        save_btn(body,"💾  Update Record",save)

    def delete_record(self):
        sel = self.rec_tree.selection()
        if not sel: return
        rid = self.rec_tree.item(sel[0])["values"][0]
        if messagebox.askyesno("Confirm",f"Delete Record #{rid}?",icon="warning"):
            conn = get_conn()
            conn.execute("DELETE FROM FORENSIC_RECORD WHERE Record_ID=:1",(rid,))
            conn.commit(); conn.close(); self._reload_records()


    # ═══ REPORTS ═════════════════════════════════════════════
    def show_reports(self):
        page = self.content
        section_header(page,"Reports & Analytics","Investigative analysis and data insights")

        # Report buttons grid
        btn_area = tk.Frame(page, bg=BG, pady=16)
        btn_area.pack(fill="x", padx=16)
        reports = [
            ("📋  Case Dashboard",           self._report_cases,      ACCENT),
            ("🔗  Chain of Custody",          self._report_coc,        INFO),
            ("🕵  Suspect-Evidence Matrix",   self._report_suspect_ev, WARNING),
            ("🧪  Active Lab Requests",       self._report_lab,        SUCCESS),
            ("📊  Evidence Status Summary",   self._report_ev_summary, DANGER),
            ("📁  Cases by Investigator",     self._report_inv_cases,  "#9333EA"),
        ]
        for i, (label, cmd, color) in enumerate(reports):
            f = tk.Frame(btn_area, bg=CARD_BG,
                         highlightbackground=color, highlightthickness=1)
            f.grid(row=i//3, column=i%3, padx=6, pady=6, sticky="nsew")
            btn_area.columnconfigure(i%3, weight=1)
            tk.Frame(f, bg=color, height=3).pack(fill="x")
            tk.Button(f, text=label, command=cmd,
                      bg=CARD_BG, fg=TEXT_DARK,
                      font=FONT_SUB, relief="flat", bd=0,
                      padx=16, pady=14, cursor="hand2",
                      activebackground=ACCENT_LIGHT,
                      activeforeground=ACCENT).pack(fill="x")

        self.report_frame = tk.Frame(page, bg=BG)
        self.report_frame.pack(fill="both", expand=True, padx=16, pady=(0, 16))

    def _show_report(self, title, cols, rows, widths=None):
        for w in self.report_frame.winfo_children(): w.destroy()
        hdr = tk.Frame(self.report_frame, bg=HEADER_BG, pady=10, padx=14)
        hdr.pack(fill="x")
        tk.Frame(hdr, bg=ACCENT, width=3).pack(side="left", fill="y", padx=(0,10))
        tk.Label(hdr, text=title, bg=HEADER_BG, fg=TEXT_DARK,
                 font=FONT_HEAD).pack(side="left")
        tk.Label(hdr, text=f"{len(rows)} record(s)",
                 bg=HEADER_BG, fg=TEXT_MID,
                 font=FONT_SMALL).pack(side="right")
        tk.Frame(self.report_frame, bg=BORDER, height=1).pack(fill="x")
        tf, tree = make_tree(self.report_frame, cols, heights=11)
        for i, col in enumerate(cols):
            w = widths[i] if widths else 120
            tree.heading(col, text=col)
            tree.column(col, width=w, anchor="w")
        insert_rows(tree, rows)
        tf.pack(fill="both", expand=True)

    def _report_cases(self):
        conn = get_conn()
        rows = conn.execute("""SELECT c.Case_ID,c.Title,c.Current_status,
                   TO_CHAR(c.Date_opened,'YYYY-MM-DD'),
                   COUNT(DISTINCT ci.Investigator_ID),
                   COUNT(DISTINCT e.Evidence_ID),
                   COUNT(DISTINCT cl.Clue_ID)
            FROM CASES c
            LEFT JOIN CASES_INVESTIGATORS ci ON c.Case_ID=ci.Case_ID
            LEFT JOIN EVIDENCE e ON c.Case_ID=e.Case_ID
            LEFT JOIN CLUES cl ON c.Case_ID=cl.Case_ID
            GROUP BY c.Case_ID,c.Title,c.Current_status,c.Date_opened
            ORDER BY c.Date_opened DESC""").fetchall()
        conn.close()
        self._show_report("Case Dashboard",
                          ("ID","Title","Status","Opened","Investigators","Evidence","Clues"),
                          rows,[55,230,100,110,100,90,70])

    def _report_coc(self):
        conn = get_conn()
        rows = conn.execute("""SELECT e.Evidence_ID,e.Type,NVL(pf.Full_name,'—'),
                   pt.Full_name,coc.Access_type,coc.Transfer_timestamp,
                   CASE coc.Is_locked WHEN 'Y' THEN 'Yes' ELSE 'No' END
            FROM CHAINOFCUSTODYLOG coc
            JOIN EVIDENCE e ON coc.Evidence_ID=e.Evidence_ID
            LEFT JOIN PERSONS pf ON coc.Transferred_from_id=pf.Person_ID
            JOIN PERSONS pt ON coc.Transferred_to_id=pt.Person_ID
            ORDER BY coc.Evidence_ID,coc.Transfer_timestamp""").fetchall()
        conn.close()
        self._show_report("Evidence Chain of Custody",
                          ("Ev.ID","Type","From","To","Access Type","Timestamp","Locked"),
                          rows,[60,110,150,150,110,170,70])

    def _report_suspect_ev(self):
        conn = get_conn()
        rows = conn.execute("""SELECT p.Full_name,s.Threat_level,s.Status,
                   e.Type,e.Description,es.Link_status,es.Link_reason
            FROM EVIDENCE_SUSPECT es
            JOIN SUSPECTS s ON es.Suspect_ID=s.Suspect_ID
            JOIN PERSONS p ON s.Person_ID=p.Person_ID
            JOIN EVIDENCE e ON es.Evidence_ID=e.Evidence_ID
            ORDER BY s.Threat_level DESC,p.Full_name""").fetchall()
        conn.close()
        self._show_report("Suspect-Evidence Link Matrix",
                          ("Suspect","Threat","Status","Ev.Type","Evidence Desc","Link Status","Reason"),
                          rows,[140,90,90,110,200,105,160])

    def _report_lab(self):
        conn = get_conn()
        rows = conn.execute("""SELECT lar.Request_ID,e.Type,c.Title,lar.Analysis_type,
                   lar.Requested_by,TO_CHAR(lar.Request_date,'YYYY-MM-DD'),lar.Status
            FROM LABANALYSISREQUEST lar
            JOIN EVIDENCE e ON lar.Evidence_ID=e.Evidence_ID
            JOIN CASES c ON e.Case_ID=c.Case_ID
            WHERE lar.Status IN ('PENDING','IN_PROGRESS')
            ORDER BY lar.Request_date""").fetchall()
        conn.close()
        self._show_report("Active Lab Requests",
                          ("ID","Ev.Type","Case","Analysis","Requested By","Date","Status"),
                          rows,[50,100,180,150,140,110,100])

    def _report_ev_summary(self):
        conn = get_conn()
        rows = conn.execute(
            "SELECT Status,COUNT(*) FROM EVIDENCE GROUP BY Status ORDER BY COUNT(*) DESC"
        ).fetchall()
        conn.close()
        self._show_report("Evidence Status Summary",("Status","Count"),rows,[200,100])

    def _report_inv_cases(self):
        conn = get_conn()
        rows = conn.execute("""SELECT p.Full_name,i.Rank,i.Department,
                   COUNT(DISTINCT ci.Case_ID),
                   NVL(LISTAGG(c.Title,' | ') WITHIN GROUP (ORDER BY c.Title),'—')
            FROM INVESTIGATORS i
            JOIN PERSONS p ON i.Person_ID=p.Person_ID
            LEFT JOIN CASES_INVESTIGATORS ci ON i.Investigator_ID=ci.Investigator_ID
            LEFT JOIN CASES c ON ci.Case_ID=c.Case_ID
            GROUP BY i.Investigator_ID,p.Full_name,i.Rank,i.Department""").fetchall()
        conn.close()
        self._show_report("Cases by Investigator",
                          ("Investigator","Rank","Dept","# Cases","Cases"),
                          rows,[160,110,160,80,400])

    # ═══ NOMINATED PERSONS ═══════════════════════════════════
    def show_nominated(self):
        page = self.content
        section_header(page,"Nominated Persons",
                       "Witnesses, informants and persons of interest formally nominated in a case")
        tb = tk.Frame(page,bg=BG,pady=10); tb.pack(fill="x",padx=16)
        if self._can("add"):
            styled_btn(tb,"+  Nominate Person",self.add_nominated_dialog).pack(side="left",padx=(0,8))
        cols = ("ID","Case","Person","Nominated By","Date","Role","Status")
        tf, self.nom_tree = make_tree(page,cols)
        for col,w in zip(cols,[50,190,160,140,100,140,110]):
            self.nom_tree.heading(col,text=col); self.nom_tree.column(col,width=w)
        tf.pack(fill="both",expand=True,padx=16)
        act = tk.Frame(page,bg=HEADER_BG,pady=10); act.pack(fill="x")
        tk.Frame(act,bg=BORDER,height=1).pack(fill="x")
        btn_row = tk.Frame(act,bg=HEADER_BG); btn_row.pack(pady=8,padx=16,anchor="w")
        if self._can("edit"):
            styled_btn(btn_row,"✏  Update Status",
                       lambda: self.update_nominated_status(),
                       color=ACCENT_LIGHT,fg=ACCENT).pack(side="left")
        self._reload_nominated()

    def _reload_nominated(self):
        for row in self.nom_tree.get_children(): self.nom_tree.delete(row)
        conn = get_conn()
        rows = conn.execute("""SELECT np.Nomination_ID,c.Title,p.Full_name,
                   NVL(np.Nominated_by,'—'),
                   NVL(TO_CHAR(np.Nomination_date,'YYYY-MM-DD'),'—'),
                   NVL(np.Role_in_case,'—'),np.Dissemination_status
            FROM NOMINATED_PERSON np
            JOIN CASES c ON np.Case_ID=c.Case_ID
            JOIN PERSONS p ON np.Person_ID=p.Person_ID
            ORDER BY np.Nomination_ID DESC""").fetchall()
        insert_rows(self.nom_tree,rows); conn.close()

    def add_nominated_dialog(self):
        dlg, body = dialog_base(self,"Nominate Person"); dialog_title(body,"👥  Nominate Person")
        conn = get_conn()
        cases   = conn.execute("SELECT Case_ID,Title FROM CASES").fetchall()
        persons = conn.execute("SELECT Person_ID,Full_name FROM PERSONS ORDER BY Full_name").fetchall()
        conn.close()
        case_opts = [f"{r[0]} — {r[1]}" for r in cases]
        per_opts  = [f"{r[0]} — {r[1]}" for r in persons]
        f = dialog_fields_frame(body)
        v_case   = label_entry(f,"Case *",0,case_opts[0] if case_opts else "",options=case_opts)
        v_person = label_entry(f,"Person *",1,per_opts[0] if per_opts else "",options=per_opts)
        v_nomby  = label_entry(f,"Nominated By",2,self.user["full_name"])
        v_date   = label_entry(f,"Date",3,date.today().isoformat())
        v_role   = label_entry(f,"Role in Case",4)
        v_status = label_entry(f,"Status",5,"PENDING",
                               options=["PENDING","APPROVED","REJECTED","DISSEMINATED"])
        def save():
            if not v_case.get() or not v_person.get():
                messagebox.showwarning("Input Error","Case and Person required.",parent=dlg); return
            try:
                cid = int(v_case.get().split("—")[0].strip())
                pid = int(v_person.get().split("—")[0].strip())
                conn2 = get_conn()
                conn2.execute(
                    "INSERT INTO NOMINATED_PERSON(Case_ID,Person_ID,Nominated_by,"
                    "Nomination_date,Role_in_case,Dissemination_status) VALUES(:1,:2,:3,:4,:5,:6)",
                    (cid,pid,v_nomby.get(),v_date.get(),v_role.get(),v_status.get()))
                conn2.commit(); conn2.close(); dlg.destroy(); self._reload_nominated()
            except Exception as ex: messagebox.showerror("Error",str(ex),parent=dlg)
        save_btn(body,"💾  Save Nomination",save)

    def update_nominated_status(self):
        sel = self.nom_tree.selection()
        if not sel: messagebox.showinfo("Select","Select a nomination first."); return
        nid = self.nom_tree.item(sel[0])["values"][0]
        dlg, body = dialog_base(self,"Update Nomination")
        dialog_title(body,f"✏  Update Nomination #{nid}")
        f = dialog_fields_frame(body)
        v_st = label_entry(f,"New Status",0,"PENDING",
                           options=["PENDING","APPROVED","REJECTED","DISSEMINATED"])
        def save():
            conn = get_conn()
            conn.execute("UPDATE NOMINATED_PERSON SET Dissemination_status=:1 WHERE Nomination_ID=:2",
                         (v_st.get(),nid))
            conn.commit(); conn.close(); dlg.destroy(); self._reload_nominated()
        save_btn(body,"✔  Update Status",save)

    # ═══ USER MANAGEMENT ═════════════════════════════════════
    def show_users(self):
        page = self.content
        section_header(page,"User Management","System accounts and role assignments")
        if self.role not in ("dba","supervisor"):
            err = tk.Frame(page, bg=BG, pady=60)
            err.pack(fill="x", padx=40)
            tk.Label(err, text="⛔", bg=BG, fg=DANGER,
                     font=("Segoe UI", 36)).pack()
            tk.Label(err, text="Access Denied",
                     bg=BG, fg=DANGER, font=FONT_TITLE).pack(pady=(8,4))
            tk.Label(err,
                     text="Only DBA and Supervisors can manage user accounts.",
                     bg=BG, fg=TEXT_MID, font=FONT_BODY).pack()
            return

        tb = tk.Frame(page,bg=BG,pady=10); tb.pack(fill="x",padx=16)
        styled_btn(tb,"+  Add User",self.add_user_dialog).pack(side="left",padx=(0,8))

        cols = ("ID","Username","Full Name","Role","Active")
        tf, self.usr_tree = make_tree(page,cols)
        for col,w in zip(cols,[50,140,220,120,70]):
            self.usr_tree.heading(col,text=col); self.usr_tree.column(col,width=w)
        tf.pack(fill="both",expand=True,padx=16)

        act = tk.Frame(page,bg=HEADER_BG,pady=10); act.pack(fill="x")
        tk.Frame(act,bg=BORDER,height=1).pack(fill="x")
        btn_row = tk.Frame(act,bg=HEADER_BG); btn_row.pack(pady=8,padx=16,anchor="w")
        styled_btn(btn_row,"✏  Edit / Reset Password",
                   lambda: self.edit_user_dialog(),
                   color=ACCENT_LIGHT,fg=ACCENT).pack(side="left",padx=(0,6))
        styled_btn(btn_row,"🔒  Deactivate",
                   lambda: self.toggle_user(0),
                   color="#F5E8D8",fg=WARNING).pack(side="left",padx=(0,6))
        styled_btn(btn_row,"🔓  Activate",
                   lambda: self.toggle_user(1),
                   color="#E8F0D8",fg=SUCCESS).pack(side="left")
        self._reload_users()

    def _reload_users(self):
        for row in self.usr_tree.get_children(): self.usr_tree.delete(row)
        conn = get_conn()
        rows = conn.execute(
            "SELECT User_ID,Username,Full_name,Role,"
            "CASE Is_active WHEN 1 THEN 'Yes' ELSE 'No' END "
            "FROM SYSTEM_USERS ORDER BY User_ID").fetchall()
        insert_rows(self.usr_tree,rows); conn.close()

    def add_user_dialog(self):
        dlg, body = dialog_base(self,"Add System User"); dialog_title(body,"➕  New System User")
        f = dialog_fields_frame(body)
        v_user = label_entry(f,"Username *",0)
        v_name = label_entry(f,"Full Name",1)
        v_role = label_entry(f,"Role *",2,"investigator",
                             options=["dba","supervisor","investigator","lab_tech","legal"])
        v_pw   = label_entry(f,"Password *",3,show="●")
        v_pw2  = label_entry(f,"Confirm Pwd",4,show="●")
        def save():
            if not v_user.get().strip() or not v_pw.get():
                messagebox.showwarning("Input Error","Username and Password required.",parent=dlg); return
            if v_pw.get() != v_pw2.get():
                messagebox.showwarning("Mismatch","Passwords do not match.",parent=dlg); return
            try:
                conn = get_conn()
                conn.execute(
                    "INSERT INTO SYSTEM_USERS(Username,Password,Role,Full_name) VALUES(:1,:2,:3,:4)",
                    (v_user.get().strip(),hash_pw(v_pw.get()),v_role.get(),v_name.get()))
                conn.commit(); conn.close(); dlg.destroy(); self._reload_users()
            except Exception as ex: messagebox.showerror("Error",str(ex),parent=dlg)
        save_btn(body,"💾  Create User",save)

    def edit_user_dialog(self):
        sel = self.usr_tree.selection()
        if not sel: messagebox.showinfo("Select","Select a user first."); return
        uid = self.usr_tree.item(sel[0])["values"][0]
        conn = get_conn()
        row = conn.execute(
            "SELECT Username,Full_name,Role FROM SYSTEM_USERS WHERE User_ID=:1",(uid,)).fetchone()
        conn.close()
        dlg, body = dialog_base(self,"Edit User"); dialog_title(body,f"✏  Edit User #{uid}")
        f = dialog_fields_frame(body)
        v_name = label_entry(f,"Full Name",0,row[1] or "")
        v_role = label_entry(f,"Role",1,row[2],
                             options=["dba","supervisor","investigator","lab_tech","legal"])
        tk.Label(f,text="New Password",bg=CARD_BG,fg=TEXT_MID,
                 font=FONT_SMALL).grid(row=2,column=0,sticky="w",padx=(10,6),pady=5)
        tk.Label(f,text="(leave blank to keep current)",bg=CARD_BG,fg=TEXT_LIGHT,
                 font=FONT_TINY).grid(row=2,column=1,sticky="w",padx=(0,10))
        v_pw = label_entry(f,"",3,show="●")
        def save():
            try:
                conn2 = get_conn()
                conn2.execute(
                    "UPDATE SYSTEM_USERS SET Full_name=:1,Role=:2 WHERE User_ID=:3",
                    (v_name.get(),v_role.get(),uid))
                if v_pw.get():
                    conn2.execute(
                        "UPDATE SYSTEM_USERS SET Password=:1 WHERE User_ID=:2",
                        (hash_pw(v_pw.get()),uid))
                conn2.commit(); conn2.close(); dlg.destroy(); self._reload_users()
            except Exception as ex: messagebox.showerror("Save Error",str(ex),parent=dlg)
        save_btn(body,"💾  Update User",save)

    def toggle_user(self,active):
        sel = self.usr_tree.selection()
        if not sel: return
        uid = self.usr_tree.item(sel[0])["values"][0]
        if uid == self.user["id"]:
            messagebox.showwarning("Warning","You cannot deactivate your own account."); return
        conn = get_conn()
        conn.execute("UPDATE SYSTEM_USERS SET Is_active=:1 WHERE User_ID=:2",(active,uid))
        conn.commit(); conn.close(); self._reload_users()


# ══════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════
def _run_login():
    init_db()
    login = LoginWindow()
    _init_treeview_style()
    login.mainloop()
    if login.logged_user:
        app = ForensicApp(login.logged_user)
        app.mainloop()

if __name__ == "__main__":
    _run_login()