-- ============================================================
--  SMART FORENSIC & EVIDENCE MANAGEMENT SYSTEM
--  FILE 3: SAMPLE DATA — all 15 tables
--  Authors : Alveena Zafar (24-SE-24) & Ayela Hamid (24-SE-56)
-- ============================================================

-- ── PERSONS ─────────────────────────────────────────────────
INSERT INTO PERSONS (Full_name, CNIC, Contact_number, Address)
VALUES ('Ali Hassan',    '35201-1234567-1', '0300-1234567', 'House 12, Street 4, Lahore');
INSERT INTO PERSONS (Full_name, CNIC, Contact_number, Address)
VALUES ('Sara Khan',     '35202-7654321-2', '0311-9876543', 'Flat 3B, Block 9, Karachi');
INSERT INTO PERSONS (Full_name, CNIC, Contact_number, Address)
VALUES ('Bilal Malik',   '35203-1122334-3', '0321-1122334', 'Plot 7, G-10, Islamabad');
INSERT INTO PERSONS (Full_name, CNIC, Contact_number, Address)
VALUES ('Zara Ahmed',    '35204-4455667-4', '0333-4455667', 'Gulberg III, Lahore');
INSERT INTO PERSONS (Full_name, CNIC, Contact_number, Address)
VALUES ('Omar Farooq',   '35205-9988776-5', '0345-9988776', 'DHA Phase 5, Lahore');
INSERT INTO PERSONS (Full_name, CNIC, Contact_number, Address)
VALUES ('Hina Rashid',   '35206-3344556-6', '0312-3344556', 'F-7/2, Islamabad');
INSERT INTO PERSONS (Full_name, CNIC, Contact_number, Address)
VALUES ('Lab Tech Asad', '35207-7788990-7', '0301-7788990', 'I-8/3, Islamabad');

-- ── INVESTIGATORS (ISA subtype — Person_ID 1 & 2) ───────────
INSERT INTO INVESTIGATORS (Person_ID, Batch_no, Rank, Department)
VALUES (1, 'BATCH-2019', 'Inspector', 'Homicide Unit');
INSERT INTO INVESTIGATORS (Person_ID, Batch_no, Rank, Department)
VALUES (2, 'BATCH-2021', 'Sub-Inspector', 'Cyber Forensics');

-- ── SUSPECTS (ISA subtype — Person_ID 3, 4, 5) ──────────────
INSERT INTO SUSPECTS (Person_ID, Threat_level, Status)
VALUES (3, 'HIGH',   'ACTIVE');
INSERT INTO SUSPECTS (Person_ID, Threat_level, Status)
VALUES (4, 'MEDIUM', 'ACTIVE');
INSERT INTO SUSPECTS (Person_ID, Threat_level, Status)
VALUES (5, 'LOW',    'CLEARED');

-- ── CASES ───────────────────────────────────────────────────
INSERT INTO CASES (Title, Description, Date_opened, Current_status)
VALUES ('Operation Nightfall',
        'Armed robbery at National Bank Gulberg. Three suspects fled on motorcycle.',
        DATE '2025-01-10', 'OPEN');
INSERT INTO CASES (Title, Description, Date_opened, Current_status)
VALUES ('Cyber Fraud 2025-A',
        'Large-scale online banking fraud targeting multiple accounts.',
        DATE '2025-02-15', 'OPEN');
INSERT INTO CASES (Title, Description, Date_opened, Date_closed, Current_status)
VALUES ('Drug Bust Shadman',
        'Narcotics recovered from warehouse. Case closed after conviction.',
        DATE '2024-11-01', DATE '2025-03-20', 'CLOSED');

-- ── CASES_INVESTIGATORS ─────────────────────────────────────
INSERT INTO CASES_INVESTIGATORS (Case_ID, Investigator_ID, Role, Assigned_date, Assigned_by)
VALUES (1, 1, 'Lead Investigator', DATE '2025-01-10', 'SSP Lahore');
INSERT INTO CASES_INVESTIGATORS (Case_ID, Investigator_ID, Role, Assigned_date, Assigned_by)
VALUES (1, 2, 'Digital Forensics',  DATE '2025-01-12', 'SSP Lahore');
INSERT INTO CASES_INVESTIGATORS (Case_ID, Investigator_ID, Role, Assigned_date, Assigned_by)
VALUES (2, 2, 'Lead Investigator', DATE '2025-02-15', 'DIG Cyber Crime');
INSERT INTO CASES_INVESTIGATORS (Case_ID, Investigator_ID, Role, Assigned_date, Assigned_by)
VALUES (3, 1, 'Lead Investigator', DATE '2024-11-01', 'SSP Lahore');

-- ── EVIDENCE ────────────────────────────────────────────────
INSERT INTO EVIDENCE (Case_ID, Type, Description, Collected_by, Collection_date, Status)
VALUES (1, 'FIREARM',      'Glock 17 pistol, serial number scratched off',             'Ali Hassan', DATE '2025-01-10', 'IN_LAB');
INSERT INTO EVIDENCE (Case_ID, Type, Description, Collected_by, Collection_date, Status)
VALUES (1, 'CCTV_FOOTAGE', 'Bank exterior camera 21:30-22:00 recording',               'Sara Khan',  DATE '2025-01-11', 'ANALYZED');
INSERT INTO EVIDENCE (Case_ID, Type, Description, Collected_by, Collection_date, Status)
VALUES (2, 'DIGITAL',      'Laptop seized from suspect Zara Ahmed — transaction logs', 'Sara Khan',  DATE '2025-02-16', 'IN_LAB');
INSERT INTO EVIDENCE (Case_ID, Type, Description, Collected_by, Collection_date, Status)
VALUES (3, 'NARCOTICS',    '5kg white powder, field-tested positive for heroin',       'Ali Hassan', DATE '2024-11-01', 'ARCHIVED');

-- ── EVIDENCE_SUSPECT ────────────────────────────────────────
-- Pistol (1) → Bilal (Suspect 1): Active
INSERT INTO EVIDENCE_SUSPECT (Evidence_ID, Suspect_ID, Link_reason, Linked_by, Link_status)
VALUES (1, 1, 'Fingerprints on pistol grip match suspect profile', 'Ali Hassan', 'ACTIVE');
-- Laptop (3) → Zara (Suspect 2): Active
INSERT INTO EVIDENCE_SUSPECT (Evidence_ID, Suspect_ID, Link_reason, Linked_by, Link_status)
VALUES (3, 2, 'Laptop registered in suspect name; login credentials found', 'Sara Khan', 'ACTIVE');
-- CCTV (2) → Omar (Suspect 3): Exonerated — alibi confirmed
INSERT INTO EVIDENCE_SUSPECT
    (Evidence_ID, Suspect_ID, Link_reason, Linked_by, Link_status, Exoneration_reason, Exoneration_date)
VALUES (2, 3, 'Physical resemblance to suspect in footage', 'Ali Hassan',
        'EXONERATED', 'Alibi confirmed by multiple witnesses', DATE '2025-01-25');

-- ── CLUES ───────────────────────────────────────────────────
INSERT INTO CLUES (Case_ID, Evidence_ID, Description, Discovery_date, Recorded_by)
VALUES (1, 1, 'Ballistic report: firearm used in two prior incidents in 2024', DATE '2025-01-15', 'Forensic Lab');
INSERT INTO CLUES (Case_ID, Evidence_ID, Description, Discovery_date, Recorded_by)
VALUES (1, 2, 'Motorcycle plate partially visible in CCTV: LHR-xxxx ending 89', DATE '2025-01-12', 'Sara Khan');
INSERT INTO CLUES (Case_ID, Evidence_ID, Description, Discovery_date, Recorded_by)
VALUES (2, NULL, 'IP addresses traced to a VPN provider registered in UAE', DATE '2025-02-18', 'Cyber Unit');

-- ── CASESTATUSLOG (initial entries — triggers will add more) ─
INSERT INTO CASESTATUSLOG (Case_ID, New_status, Updated_by, Updated_at, Reason)
VALUES (1, 'OPEN', 'Ali Hassan', TIMESTAMP '2025-01-10 09:00:00', 'Case registered');
INSERT INTO CASESTATUSLOG (Case_ID, New_status, Updated_by, Updated_at, Reason)
VALUES (3, 'OPEN', 'Ali Hassan', TIMESTAMP '2024-11-01 08:30:00', 'Drug bust case registered');
INSERT INTO CASESTATUSLOG (Case_ID, New_status, Updated_by, Updated_at, Reason)
VALUES (3, 'CLOSED', 'Court Officer', TIMESTAMP '2025-03-20 14:00:00', 'Conviction secured');

-- ── EVIDENCEAUDITLOG (initial entries — triggers will add more)
INSERT INTO EVIDENCEAUDITLOG (Evidence_ID, Field_changed, Old_value, New_value, Changed_by, Changed_at)
VALUES (1, 'STATUS', 'COLLECTED', 'IN_LAB', 'Ali Hassan', TIMESTAMP '2025-01-13 10:00:00');
INSERT INTO EVIDENCEAUDITLOG (Evidence_ID, Field_changed, Old_value, New_value, Changed_by, Changed_at)
VALUES (4, 'STATUS', 'COLLECTED', 'ARCHIVED', 'Court Officer', TIMESTAMP '2025-03-21 09:00:00');

-- ── CHAINOFCUSTODYLOG ────────────────────────────────────────
-- Pistol (1): Investigator Ali (1) → Lab Tech Asad (7)
INSERT INTO CHAINOFCUSTODYLOG
    (Evidence_ID, Transferred_from_id, Transferred_to_id, Access_type, Reason, Is_locked)
VALUES (1, 1, 7, 'TRANSFER', 'Sent to ballistics lab for analysis', 'N');
-- CCTV (2): Sara (2) → Ali (1) for review
INSERT INTO CHAINOFCUSTODYLOG
    (Evidence_ID, Transferred_from_id, Transferred_to_id, Access_type, Reason, Is_locked)
VALUES (2, 2, 1, 'ANALYSIS', 'Review by lead investigator', 'N');

-- ── EVIDENCEPHYSICALSTATE ────────────────────────────────────
INSERT INTO EVIDENCEPHYSICALSTATE
    (Evidence_ID, Measurement_date, Quantity_remaining, Visual_condition, Degradation_notes, Measured_by)
VALUES (1, DATE '2025-01-14', 1, 'INTACT', 'No visible degradation; serial number chemically removed', 'Lab Tech Asad');
INSERT INTO EVIDENCEPHYSICALSTATE
    (Evidence_ID, Measurement_date, Quantity_remaining, Visual_condition, Degradation_notes, Measured_by)
VALUES (4, DATE '2024-11-05', 4.850, 'PARTIALLY_CONSUMED', 'Sample taken for chemical analysis; remainder sealed', 'Lab Tech Asad');

-- ── LABANALYSISREQUEST ───────────────────────────────────────
INSERT INTO LABANALYSISREQUEST
    (Evidence_ID, State_ID, Requested_by, Request_date, Analysis_type, Status)
VALUES (1, 1, 'Ali Hassan', DATE '2025-01-14', 'BALLISTICS', 'IN_PROGRESS');
INSERT INTO LABANALYSISREQUEST
    (Evidence_ID, State_ID, Requested_by, Request_date, Analysis_type, Status)
VALUES (4, 2, 'Ali Hassan', DATE '2024-11-05', 'CHEMICAL_NARCOTICS', 'COMPLETED');

-- ── FORENSIC_RECORD ─────────────────────────────────────────
INSERT INTO FORENSIC_RECORD (Case_ID, Record_type, Record_date, Prepared_by, Description, Status)
VALUES (1, 'PRELIMINARY_REPORT', DATE '2025-01-15', 'Ali Hassan',
        'Initial scene assessment and evidence catalogue for Operation Nightfall.', 'FINAL');
INSERT INTO FORENSIC_RECORD (Case_ID, Record_type, Record_date, Prepared_by, Description, Status)
VALUES (3, 'CLOSURE_REPORT', DATE '2025-03-20', 'Ali Hassan',
        'Full case summary including conviction outcome and evidence disposal plan.', 'FINAL');

-- ── NOMINATED_PERSON ─────────────────────────────────────────
INSERT INTO NOMINATED_PERSON (Case_ID, Person_ID, Nominated_by, Nomination_date, Role_in_case, Dissemination_status)
VALUES (1, 6, 'Ali Hassan', DATE '2025-01-20', 'Witness (bank teller)', 'APPROVED');
INSERT INTO NOMINATED_PERSON (Case_ID, Person_ID, Nominated_by, Nomination_date, Role_in_case, Dissemination_status)
VALUES (2, 7, 'Sara Khan',  DATE '2025-02-20', 'Technical Expert',      'PENDING');

COMMIT;
PROMPT ✓  Sample data inserted into all 15 tables successfully.
