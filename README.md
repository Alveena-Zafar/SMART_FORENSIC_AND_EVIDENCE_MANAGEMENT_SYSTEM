# 🕵️ Smart Forensic & Evidence Management System

> **Database Systems (DBS) Course Project — Semester 4, UET Taxila**
> A role-based desktop application for managing criminal cases, evidence, suspects, and chain-of-custody records — built on a fully normalized Oracle database with audit-logging triggers, and a Python (Tkinter) GUI on top.
---

## 📌 Table of Contents
- [Overview](#-overview)
- [Key Features](#-key-features)
- [Database Design](#️-database-design)
- [Tech Stack](#️-tech-stack)
- [Prerequisites](#-prerequisites)
- [Project Structure](#-project-structure)
- [Getting Started](#-getting-started)
- [Demo Logins](#-demo-logins)
- [What We Learned](#-what-we-learned)
- [Authors](#-authors)

---

## 🧠 Overview

Investigation agencies need a system that keeps evidence tamper-proof, tracks who touched what and when, and restricts access by role. This project models that end-to-end: from a **3NF-normalized relational schema** to a **desktop client** with **role-based dashboards** for five different types of users — DBA, Supervisor, Investigator, Lab Tech, and Legal.

This project demonstrates:
- Designing a relational database schema in Third Normal Form (3NF)
- Role-Based Access Control (RBAC) enforced at both UI and query level
- Immutable audit logging via PL/SQL triggers
- Chain-of-custody tracking for physical/digital evidence
- Connecting a Python desktop client to an Oracle backend

---

## ✨ Key Features

- **Role-Based Access Control** — five roles, each with a different set of visible tabs and permissions (add/edit/delete/read)
- **Case & Evidence Management** — full lifecycle tracking for cases, evidence items, suspects, and clues
- **Chain of Custody Logging** — every evidence handoff recorded, with triggers that lock historical entries from tampering
- **Audit Trails** — dedicated audit-log tables plus auto-populated history tables (`CASES_HISTORY`, `EVIDENCE_HISTORY`, `SUSPECTS_HISTORY`)
- **Lab Analysis Requests** — workflow for sending evidence to a lab and tracking results
- **Reports Dashboard** — aggregated view across cases, evidence, and investigators

---

## 🗄️ Database Design

The schema is normalized to **Third Normal Form (3NF)** to eliminate redundancy and update anomalies. **18 tables**, grouped as:

| Category | Tables |
|---|---|
| **Core Entities** | `PERSONS`, `INVESTIGATORS`, `SUSPECTS`, `CASES`, `EVIDENCE`, `CLUES` |
| **Relationships** | `CASES_INVESTIGATORS`, `EVIDENCE_SUSPECT` |
| **Logging / Audit** | `CASESTATUSLOG`, `EVIDENCEAUDITLOG`, `CHAINOFCUSTODYLOG`, `EVIDENCEPHYSICALSTATE` |
| **Workflow** | `LABANALYSISREQUEST`, `FORENSIC_RECORD`, `NOMINATED_PERSON` |
| **History (auto-versioning)** | `CASES_HISTORY`, `EVIDENCE_HISTORY`, `SUSPECTS_HISTORY` |

**21 PL/SQL triggers** handle primary-key auto-generation, audit logging on update/delete, and write-protection on historical/audit tables — so even a DBA can't quietly edit the paper trail.

---

## 🛠️ Tech Stack

- **Database:** Oracle Database (PL/SQL — tables, triggers, constraints)
- **Client:** Python 3
- **GUI:** Tkinter (`ttk`)
- **DB Driver:** `python-oracledb`
- **Security:** SHA-256 password hashing (`hashlib`)

---

## ⚠️ Prerequisites

- **Oracle Database** (or Oracle XE) running locally, with a PDB accessible
- **Python 3.9+**

---

## 📁 Project Structure
```
final_project/
├── 01_create_tables.sql     # Schema: tables, PKs, FKs, constraints
├── 02_triggers.sql          # PL/SQL triggers: audit logs, history, PK generation
├── 03_sample_data.sql       # Seed data for demo/testing
├── forensic_gui_oracle.py   # Main Tkinter application
├── requirements.txt
└── README.md
```

---

## ⚡ Getting Started

```bash
# 1. Clone the repository
git clone https://github.com/Alveena-Zafar/smart-forensic-evidence-system.git
cd smart-forensic-evidence-system

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run the SQL scripts in order against your Oracle instance
#    01_create_tables.sql → 02_triggers.sql → 03_sample_data.sql

# 4. Run the app
python forensic_gui_oracle.py
```

### 🔐 Configuration note
Database credentials (`DB_USER`, `DB_PASSWORD`, `DB_DSN`) are currently constants at the top of `forensic_gui_oracle.py`, set for local demo convenience. Before any real deployment, move them into a `.env` file (via `python-dotenv`) so credentials never sit in source control.

---

## 👥 Demo Logins

| Role | Username | Password |
|---|---|---|
| DBA | `admin` | `admin123` |
| Supervisor | `supervisor1` | `super123` |
| Investigator | `inv1` | `inv123` |
| Lab Tech | `labtech1` | `lab123` |
| Legal | `legal1` | `legal123` |

*(Demo credentials only — reset before any real deployment.)*

---

## 📖 What We Learned

- **Normalization pays off** — 3NF design made the trigger logic and audit trail far simpler to reason about
- **Triggers as guardrails** — PL/SQL triggers can enforce data integrity rules that application code shouldn't be trusted to enforce alone
- **RBAC at two layers** — UI-level tab restriction plus permission checks means neither layer alone is the single point of failure
- **Chain of custody ≠ a text field** — modeling it as its own logged, append-only table was the difference between "looks done" and "actually tamper-evident"

---

## 👩‍💻 Authors

**Alveena Zafar** & **Ayela Hamid**

This project was designed and developed collaboratively as part of the Database Systems course, Semester 4, UET Taxila.

-GitHub: github.com/Alveena-Zafar
-GitHub: github.com/ayelahamid-prog

---

## 📄 License

This project was built for academic purposes as part of a university Database Systems course.

<div align="center">

Made by Alveena Zafar & Ayela Hamid

</div>
