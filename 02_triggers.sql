--  Triggers included:
--  1.  PK auto-assign     — 13 triggers (one per table)
--  2.  Audit logging      — 2 triggers  (case status + evidence fields)
--  3.  History snapshots  — 3 triggers  (cases, evidence, suspects)
--  4.  Append-only guard  — 2 triggers  (protect audit log tables)
--  5.  Custody lock guard — 1 trigger   (locked records cannot change)
--  TOTAL: 21 triggers
-- ============================================================

-- ════════════════════════════════════════════════════════════
--  SECTION 1: PK AUTO-ASSIGN TRIGGERS
--  Each trigger assigns the next sequence value as PK
--  when a row is inserted without specifying the PK.
-- ════════════════════════════════════════════════════════════

CREATE OR REPLACE TRIGGER TRG_PERSONS_PK
BEFORE INSERT ON PERSONS
FOR EACH ROW
BEGIN
    IF :NEW.Person_ID IS NULL THEN
        :NEW.Person_ID := SEQ_PERSON_ID.NEXTVAL;
    END IF;
END;
/

CREATE OR REPLACE TRIGGER TRG_INVESTIGATORS_PK
BEFORE INSERT ON INVESTIGATORS
FOR EACH ROW
BEGIN
    IF :NEW.Investigator_ID IS NULL THEN
        :NEW.Investigator_ID := SEQ_INVESTIGATOR_ID.NEXTVAL;
    END IF;
END;
/

CREATE OR REPLACE TRIGGER TRG_SUSPECTS_PK
BEFORE INSERT ON SUSPECTS
FOR EACH ROW
BEGIN
    IF :NEW.Suspect_ID IS NULL THEN
        :NEW.Suspect_ID := SEQ_SUSPECT_ID.NEXTVAL;
    END IF;
END;
/

CREATE OR REPLACE TRIGGER TRG_CASES_PK
BEFORE INSERT ON CASES
FOR EACH ROW
BEGIN
    IF :NEW.Case_ID IS NULL THEN
        :NEW.Case_ID := SEQ_CASE_ID.NEXTVAL;
    END IF;
END;
/

CREATE OR REPLACE TRIGGER TRG_EVIDENCE_PK
BEFORE INSERT ON EVIDENCE
FOR EACH ROW
BEGIN
    IF :NEW.Evidence_ID IS NULL THEN
        :NEW.Evidence_ID := SEQ_EVIDENCE_ID.NEXTVAL;
    END IF;
END;
/

CREATE OR REPLACE TRIGGER TRG_CLUES_PK
BEFORE INSERT ON CLUES
FOR EACH ROW
BEGIN
    IF :NEW.Clue_ID IS NULL THEN
        :NEW.Clue_ID := SEQ_CLUE_ID.NEXTVAL;
    END IF;
END;
/

CREATE OR REPLACE TRIGGER TRG_CSL_PK
BEFORE INSERT ON CASESTATUSLOG
FOR EACH ROW
BEGIN
    IF :NEW.Log_ID IS NULL THEN
        :NEW.Log_ID := SEQ_LOG_ID_CASE.NEXTVAL;
    END IF;
END;
/

CREATE OR REPLACE TRIGGER TRG_EAL_PK
BEFORE INSERT ON EVIDENCEAUDITLOG
FOR EACH ROW
BEGIN
    IF :NEW.Log_ID IS NULL THEN
        :NEW.Log_ID := SEQ_LOG_ID_EVIDENCE.NEXTVAL;
    END IF;
END;
/

CREATE OR REPLACE TRIGGER TRG_COCL_PK
BEFORE INSERT ON CHAINOFCUSTODYLOG
FOR EACH ROW
BEGIN
    IF :NEW.Transfer_ID IS NULL THEN
        :NEW.Transfer_ID := SEQ_TRANSFER_ID.NEXTVAL;
    END IF;
END;
/

CREATE OR REPLACE TRIGGER TRG_EPS_PK
BEFORE INSERT ON EVIDENCEPHYSICALSTATE
FOR EACH ROW
BEGIN
    IF :NEW.State_ID IS NULL THEN
        :NEW.State_ID := SEQ_STATE_ID.NEXTVAL;
    END IF;
END;
/

CREATE OR REPLACE TRIGGER TRG_LAR_PK
BEFORE INSERT ON LABANALYSISREQUEST
FOR EACH ROW
BEGIN
    IF :NEW.Request_ID IS NULL THEN
        :NEW.Request_ID := SEQ_REQUEST_ID.NEXTVAL;
    END IF;
END;
/

CREATE OR REPLACE TRIGGER TRG_FR_PK
BEFORE INSERT ON FORENSIC_RECORD
FOR EACH ROW
BEGIN
    IF :NEW.Record_ID IS NULL THEN
        :NEW.Record_ID := SEQ_RECORD_ID.NEXTVAL;
    END IF;
END;
/

CREATE OR REPLACE TRIGGER TRG_NP_PK
BEFORE INSERT ON NOMINATED_PERSON
FOR EACH ROW
BEGIN
    IF :NEW.Nomination_ID IS NULL THEN
        :NEW.Nomination_ID := SEQ_NOMINATION_ID.NEXTVAL;
    END IF;
END;
/

-- ════════════════════════════════════════════════════════════
--  SECTION 2: AUDIT LOGGING TRIGGERS
--  These fire AFTER every UPDATE and automatically write
--  a log entry so every change is permanently recorded.
-- ════════════════════════════════════════════════════════════

-- ── Trigger: log CASES status changes → CASESTATUSLOG ───────
-- Fires whenever Current_status changes on any case row.
-- The NVL(...,'~') trick ensures it fires even if old value was NULL.
CREATE OR REPLACE TRIGGER TRG_CASE_STATUS_AUDIT
AFTER UPDATE OF Current_status ON CASES
FOR EACH ROW
BEGIN
    IF NVL(:OLD.Current_status, '~') != NVL(:NEW.Current_status, '~') THEN
        INSERT INTO CASESTATUSLOG
            (Log_ID, Case_ID, New_status, Updated_by, Updated_at, Reason)
        VALUES
            (SEQ_LOG_ID_CASE.NEXTVAL,
             :NEW.Case_ID,
             :NEW.Current_status,
             SYS_CONTEXT('USERENV', 'SESSION_USER'),
             SYSTIMESTAMP,
             'Auto-logged by TRG_CASE_STATUS_AUDIT');
    END IF;
END;
/

-- ── Trigger: log EVIDENCE field changes → EVIDENCEAUDITLOG ──
-- Fires whenever Status OR Type changes on any evidence row.
-- Each changed field gets its own separate log row.
CREATE OR REPLACE TRIGGER TRG_EVIDENCE_AUDIT
AFTER UPDATE ON EVIDENCE
FOR EACH ROW
DECLARE
    v_user VARCHAR2(100) := SYS_CONTEXT('USERENV', 'SESSION_USER');
BEGIN
    -- Log STATUS change
    IF NVL(:OLD.Status, '~') != NVL(:NEW.Status, '~') THEN
        INSERT INTO EVIDENCEAUDITLOG
            (Log_ID, Evidence_ID, Field_changed, Old_value, New_value, Changed_by, Changed_at)
        VALUES
            (SEQ_LOG_ID_EVIDENCE.NEXTVAL, :NEW.Evidence_ID,
             'STATUS', :OLD.Status, :NEW.Status, v_user, SYSTIMESTAMP);
    END IF;

    -- Log TYPE change
    IF NVL(:OLD.Type, '~') != NVL(:NEW.Type, '~') THEN
        INSERT INTO EVIDENCEAUDITLOG
            (Log_ID, Evidence_ID, Field_changed, Old_value, New_value, Changed_by, Changed_at)
        VALUES
            (SEQ_LOG_ID_EVIDENCE.NEXTVAL, :NEW.Evidence_ID,
             'TYPE', :OLD.Type, :NEW.Type, v_user, SYSTIMESTAMP);
    END IF;

    -- Log COLLECTED_BY change
    IF NVL(:OLD.Collected_by, '~') != NVL(:NEW.Collected_by, '~') THEN
        INSERT INTO EVIDENCEAUDITLOG
            (Log_ID, Evidence_ID, Field_changed, Old_value, New_value, Changed_by, Changed_at)
        VALUES
            (SEQ_LOG_ID_EVIDENCE.NEXTVAL, :NEW.Evidence_ID,
             'COLLECTED_BY', :OLD.Collected_by, :NEW.Collected_by, v_user, SYSTIMESTAMP);
    END IF;
END;
/

-- ════════════════════════════════════════════════════════════
--  SECTION 3: HISTORY SNAPSHOT TRIGGERS
--  These fire BEFORE every UPDATE and save the ENTIRE old row
--  into history tables. This means previous records are NEVER
--  lost — every update is fully recoverable.
-- ════════════════════════════════════════════════════════════

-- ── Trigger: snapshot CASES row before UPDATE → CASES_HISTORY
CREATE OR REPLACE TRIGGER TRG_CASES_HISTORY
BEFORE UPDATE ON CASES
FOR EACH ROW
BEGIN
    INSERT INTO CASES_HISTORY
        (Case_ID, Title, Description, Date_opened, Date_closed, Old_status)
    VALUES
        (:OLD.Case_ID, :OLD.Title, :OLD.Description,
         :OLD.Date_opened, :OLD.Date_closed, :OLD.Current_status);
END;
/

-- ── Trigger: snapshot EVIDENCE row before UPDATE → EVIDENCE_HISTORY
CREATE OR REPLACE TRIGGER TRG_EVIDENCE_HISTORY
BEFORE UPDATE ON EVIDENCE
FOR EACH ROW
BEGIN
    INSERT INTO EVIDENCE_HISTORY
        (Evidence_ID, Case_ID, Old_type, Old_description,
         Old_collected_by, Old_collection_date, Old_status)
    VALUES
        (:OLD.Evidence_ID, :OLD.Case_ID, :OLD.Type, :OLD.Description,
         :OLD.Collected_by, :OLD.Collection_date, :OLD.Status);
END;
/

-- ── Trigger: snapshot SUSPECTS row before UPDATE → SUSPECTS_HISTORY
CREATE OR REPLACE TRIGGER TRG_SUSPECTS_HISTORY
BEFORE UPDATE ON SUSPECTS
FOR EACH ROW
BEGIN
    INSERT INTO SUSPECTS_HISTORY
        (Suspect_ID, Old_threat_level, Old_status)
    VALUES
        (:OLD.Suspect_ID, :OLD.Threat_level, :OLD.Status);
END;
/

-- ════════════════════════════════════════════════════════════
--  SECTION 4: APPEND-ONLY GUARD TRIGGERS
--  Audit log tables are forensic records — nobody can ever
--  edit or delete them. These triggers enforce that at DB level.
-- ════════════════════════════════════════════════════════════

-- ── Protect CASESTATUSLOG ────────────────────────────────────
CREATE OR REPLACE TRIGGER TRG_PROTECT_CASESTATUSLOG
BEFORE DELETE OR UPDATE ON CASESTATUSLOG
FOR EACH ROW
BEGIN
    RAISE_APPLICATION_ERROR(-20001,
        'CASESTATUSLOG is append-only. DELETE and UPDATE are not permitted on audit records.');
END;
/

-- ── Protect EVIDENCEAUDITLOG ─────────────────────────────────
CREATE OR REPLACE TRIGGER TRG_PROTECT_EVIDENCEAUDITLOG
BEFORE DELETE OR UPDATE ON EVIDENCEAUDITLOG
FOR EACH ROW
BEGIN
    RAISE_APPLICATION_ERROR(-20002,
        'EVIDENCEAUDITLOG is append-only. DELETE and UPDATE are not permitted on audit records.');
END;
/

-- ════════════════════════════════════════════════════════════
--  SECTION 5: CHAIN OF CUSTODY LOCK TRIGGER
--  Once a custody record has Is_locked = 'Y' (signature
--  recorded), it cannot be modified by anyone — ever.
--  This satisfies the proposal's chain-of-custody requirement.
-- ════════════════════════════════════════════════════════════

CREATE OR REPLACE TRIGGER TRG_CUSTODY_LOCK
BEFORE UPDATE ON CHAINOFCUSTODYLOG
FOR EACH ROW
BEGIN
    IF :OLD.Is_locked = 'Y' THEN
        RAISE_APPLICATION_ERROR(-20003,
            'Chain of custody record ' || :OLD.Transfer_ID ||
            ' is permanently locked. No modifications are permitted after signing.');
    END IF;
END;
/

COMMIT;