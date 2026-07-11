-- ════════════════════════════════════════════════════════════
--  SEQUENCES
-- ════════════════════════════════════════════════════════════
CREATE SEQUENCE SEQ_PERSON_ID       START WITH 1 INCREMENT BY 1 NOCACHE NOCYCLE;
CREATE SEQUENCE SEQ_INVESTIGATOR_ID START WITH 1 INCREMENT BY 1 NOCACHE NOCYCLE;
CREATE SEQUENCE SEQ_SUSPECT_ID      START WITH 1 INCREMENT BY 1 NOCACHE NOCYCLE;
CREATE SEQUENCE SEQ_CASE_ID         START WITH 1 INCREMENT BY 1 NOCACHE NOCYCLE;
CREATE SEQUENCE SEQ_EVIDENCE_ID     START WITH 1 INCREMENT BY 1 NOCACHE NOCYCLE;
CREATE SEQUENCE SEQ_CLUE_ID         START WITH 1 INCREMENT BY 1 NOCACHE NOCYCLE;
CREATE SEQUENCE SEQ_LOG_ID_CASE     START WITH 1 INCREMENT BY 1 NOCACHE NOCYCLE;
CREATE SEQUENCE SEQ_LOG_ID_EVIDENCE START WITH 1 INCREMENT BY 1 NOCACHE NOCYCLE;
CREATE SEQUENCE SEQ_TRANSFER_ID     START WITH 1 INCREMENT BY 1 NOCACHE NOCYCLE;
CREATE SEQUENCE SEQ_STATE_ID        START WITH 1 INCREMENT BY 1 NOCACHE NOCYCLE;
CREATE SEQUENCE SEQ_REQUEST_ID      START WITH 1 INCREMENT BY 1 NOCACHE NOCYCLE;
CREATE SEQUENCE SEQ_RECORD_ID       START WITH 1 INCREMENT BY 1 NOCACHE NOCYCLE;
CREATE SEQUENCE SEQ_NOMINATION_ID   START WITH 1 INCREMENT BY 1 NOCACHE NOCYCLE;

-- ════════════════════════════════════════════════════════════
--  TABLE 1 : PERSONS  (supertype — ISA hierarchy)
-- ════════════════════════════════════════════════════════════
CREATE TABLE PERSONS (
    Person_ID      NUMBER        CONSTRAINT pk_persons PRIMARY KEY,
    Full_name      VARCHAR2(100) NOT NULL,
    CNIC           VARCHAR2(15)  NOT NULL
        CONSTRAINT uq_persons_cnic UNIQUE
        CONSTRAINT chk_cnic CHECK (REGEXP_LIKE(CNIC, '^\d{5}-\d{7}-\d{1}$')),
    Contact_number VARCHAR2(20),
    Address        VARCHAR2(255)
);
COMMENT ON TABLE PERSONS IS 'Supertype for Investigators and Suspects (ISA hierarchy).';

-- ════════════════════════════════════════════════════════════
--  TABLE 2 : INVESTIGATORS  (ISA subtype)
-- ════════════════════════════════════════════════════════════
CREATE TABLE INVESTIGATORS (
    Investigator_ID NUMBER        CONSTRAINT pk_investigators PRIMARY KEY,
    Person_ID       NUMBER        NOT NULL
        CONSTRAINT fk_inv_person REFERENCES PERSONS(Person_ID)
        CONSTRAINT uq_inv_person UNIQUE,
    Batch_no        VARCHAR2(20),
    Rank            VARCHAR2(50),
    Department      VARCHAR2(100)
);

-- ════════════════════════════════════════════════════════════
--  TABLE 3 : SUSPECTS  (ISA subtype)
-- ════════════════════════════════════════════════════════════
CREATE TABLE SUSPECTS (
    Suspect_ID   NUMBER        CONSTRAINT pk_suspects PRIMARY KEY,
    Person_ID    NUMBER        NOT NULL
        CONSTRAINT fk_sus_person REFERENCES PERSONS(Person_ID)
        CONSTRAINT uq_sus_person UNIQUE,
    Threat_level VARCHAR2(20)
        CONSTRAINT chk_threat CHECK (Threat_level IN ('LOW','MEDIUM','HIGH','CRITICAL')),
    Status       VARCHAR2(30)  DEFAULT 'ACTIVE'
        CONSTRAINT chk_sus_status CHECK (Status IN ('ACTIVE','CLEARED','ARRESTED','RELEASED'))
);

-- ════════════════════════════════════════════════════════════
--  TABLE 4 : CASES
-- ════════════════════════════════════════════════════════════
CREATE TABLE CASES (
    Case_ID        NUMBER         CONSTRAINT pk_cases PRIMARY KEY,
    Title          VARCHAR2(200)  NOT NULL,
    Description    CLOB,
    Date_opened    DATE           DEFAULT SYSDATE NOT NULL,
    Date_closed    DATE,
    Current_status VARCHAR2(30)   DEFAULT 'OPEN'
        CONSTRAINT chk_case_status CHECK (Current_status IN ('OPEN','CLOSED','PENDING','ARCHIVED')),
    CONSTRAINT chk_case_dates CHECK (Date_closed IS NULL OR Date_closed >= Date_opened)
);

-- ════════════════════════════════════════════════════════════
--  TABLE 5 : CASES_INVESTIGATORS  (junction)
-- ════════════════════════════════════════════════════════════
CREATE TABLE CASES_INVESTIGATORS (
    Case_ID         NUMBER        NOT NULL
        CONSTRAINT fk_ci_case REFERENCES CASES(Case_ID),
    Investigator_ID NUMBER        NOT NULL
        CONSTRAINT fk_ci_inv  REFERENCES INVESTIGATORS(Investigator_ID),
    Role            VARCHAR2(50),
    Assigned_date   DATE          DEFAULT SYSDATE,
    Assigned_by     VARCHAR2(100),
    CONSTRAINT pk_cases_inv PRIMARY KEY (Case_ID, Investigator_ID)
);

-- ════════════════════════════════════════════════════════════
--  TABLE 6 : EVIDENCE
-- ════════════════════════════════════════════════════════════
CREATE TABLE EVIDENCE (
    Evidence_ID     NUMBER         CONSTRAINT pk_evidence PRIMARY KEY,
    Case_ID         NUMBER         NOT NULL
        CONSTRAINT fk_ev_case REFERENCES CASES(Case_ID),
    Type            VARCHAR2(50)   NOT NULL,
    Description     VARCHAR2(500),
    Collected_by    VARCHAR2(100),
    Collection_date DATE,
    Status          VARCHAR2(30)   DEFAULT 'COLLECTED'
        CONSTRAINT chk_ev_status CHECK (
            Status IN ('COLLECTED','IN_LAB','ANALYZED','ARCHIVED','DISPOSED')
        ),
    Image           VARCHAR2(500)
);

-- ════════════════════════════════════════════════════════════
--  TABLE 7 : EVIDENCE_SUSPECT  (junction — soft exoneration)
-- ════════════════════════════════════════════════════════════
CREATE TABLE EVIDENCE_SUSPECT (
    Evidence_ID        NUMBER        NOT NULL
        CONSTRAINT fk_es_ev  REFERENCES EVIDENCE(Evidence_ID),
    Suspect_ID         NUMBER        NOT NULL
        CONSTRAINT fk_es_sus REFERENCES SUSPECTS(Suspect_ID),
    Link_reason        VARCHAR2(500),
    Linked_by          VARCHAR2(100),
    Linked_at          DATE          DEFAULT SYSDATE,
    Link_status        VARCHAR2(30)  DEFAULT 'ACTIVE'
        CONSTRAINT chk_link_status CHECK (Link_status IN ('ACTIVE','EXONERATED','PENDING')),
    Exoneration_reason VARCHAR2(500),
    Exoneration_date   DATE,
    -- Enforce: exoneration fields must be filled when status = EXONERATED
    CONSTRAINT chk_exoneration CHECK (
        Link_status != 'EXONERATED'
        OR (Exoneration_reason IS NOT NULL AND Exoneration_date IS NOT NULL)
    ),
    CONSTRAINT pk_evidence_suspect PRIMARY KEY (Evidence_ID, Suspect_ID)
);

-- ════════════════════════════════════════════════════════════
--  TABLE 8 : CLUES
-- ════════════════════════════════════════════════════════════
CREATE TABLE CLUES (
    Clue_ID        NUMBER         CONSTRAINT pk_clues PRIMARY KEY,
    Case_ID        NUMBER         NOT NULL
        CONSTRAINT fk_clue_case REFERENCES CASES(Case_ID),
    Evidence_ID    NUMBER
        CONSTRAINT fk_clue_ev REFERENCES EVIDENCE(Evidence_ID),
    Description    VARCHAR2(1000) NOT NULL,
    Discovery_date DATE,
    Recorded_by    VARCHAR2(100)
);

-- ════════════════════════════════════════════════════════════
--  TABLE 9 : CASESTATUSLOG  (append-only audit)
-- ════════════════════════════════════════════════════════════
CREATE TABLE CASESTATUSLOG (
    Log_ID     NUMBER        CONSTRAINT pk_csl PRIMARY KEY,
    Case_ID    NUMBER        NOT NULL
        CONSTRAINT fk_csl_case REFERENCES CASES(Case_ID),
    New_status VARCHAR2(30)  NOT NULL,
    Updated_by VARCHAR2(100) NOT NULL,
    Updated_at TIMESTAMP     DEFAULT SYSTIMESTAMP NOT NULL,
    Reason     VARCHAR2(500)
);

-- ════════════════════════════════════════════════════════════
--  TABLE 10 : EVIDENCEAUDITLOG  (append-only audit)
-- ════════════════════════════════════════════════════════════
CREATE TABLE EVIDENCEAUDITLOG (
    Log_ID        NUMBER        CONSTRAINT pk_eal PRIMARY KEY,
    Evidence_ID   NUMBER        NOT NULL
        CONSTRAINT fk_eal_ev REFERENCES EVIDENCE(Evidence_ID),
    Field_changed VARCHAR2(100) NOT NULL,
    Old_value     VARCHAR2(500),
    New_value     VARCHAR2(500),
    Changed_by    VARCHAR2(100) NOT NULL,
    Changed_at    TIMESTAMP     DEFAULT SYSTIMESTAMP NOT NULL
);

-- ════════════════════════════════════════════════════════════
--  TABLE 11 : CHAINOFCUSTODYLOG
-- ════════════════════════════════════════════════════════════
CREATE TABLE CHAINOFCUSTODYLOG (
    Transfer_ID         NUMBER        CONSTRAINT pk_cocl PRIMARY KEY,
    Evidence_ID         NUMBER        NOT NULL
        CONSTRAINT fk_cocl_ev   REFERENCES EVIDENCE(Evidence_ID),
    Transferred_from_id NUMBER
        CONSTRAINT fk_cocl_from REFERENCES PERSONS(Person_ID),
    Transferred_to_id   NUMBER        NOT NULL
        CONSTRAINT fk_cocl_to   REFERENCES PERSONS(Person_ID),
    Transfer_timestamp  TIMESTAMP     DEFAULT SYSTIMESTAMP NOT NULL,
    Access_type         VARCHAR2(30)
        CONSTRAINT chk_access CHECK (
            Access_type IN ('TRANSFER','ANALYSIS','RE-EXAMINATION','RETURN','DISPOSAL')
        ),
    Reason              VARCHAR2(500),
    Signature_proof     VARCHAR2(500),
    Is_locked           CHAR(1)       DEFAULT 'N'
        CONSTRAINT chk_locked CHECK (Is_locked IN ('Y','N'))
);

-- ════════════════════════════════════════════════════════════
--  TABLE 12 : EVIDENCEPHYSICALSTATE  (time-series snapshots)
-- ════════════════════════════════════════════════════════════
CREATE TABLE EVIDENCEPHYSICALSTATE (
    State_ID           NUMBER         CONSTRAINT pk_eps PRIMARY KEY,
    Evidence_ID        NUMBER         NOT NULL
        CONSTRAINT fk_eps_ev REFERENCES EVIDENCE(Evidence_ID),
    Measurement_date   DATE           DEFAULT SYSDATE,
    Quantity_remaining NUMBER(10,3),
    Visual_condition   VARCHAR2(100),
    Degradation_notes  VARCHAR2(1000),
    Measured_by        VARCHAR2(100),
    Photo_proof_path   VARCHAR2(500)
);

-- ════════════════════════════════════════════════════════════
--  TABLE 13 : LABANALYSISREQUEST
-- ════════════════════════════════════════════════════════════
CREATE TABLE LABANALYSISREQUEST (
    Request_ID      NUMBER        CONSTRAINT pk_lar PRIMARY KEY,
    Evidence_ID     NUMBER        NOT NULL
        CONSTRAINT fk_lar_ev    REFERENCES EVIDENCE(Evidence_ID),
    State_ID        NUMBER
        CONSTRAINT fk_lar_state REFERENCES EVIDENCEPHYSICALSTATE(State_ID),
    Requested_by    VARCHAR2(100) NOT NULL,
    Request_date    DATE          DEFAULT SYSDATE,
    Analysis_type   VARCHAR2(100) NOT NULL,
    Revision_number NUMBER(5)     DEFAULT 1,
    Status          VARCHAR2(30)  DEFAULT 'PENDING'
        CONSTRAINT chk_lar_status CHECK (
            Status IN ('PENDING','IN_PROGRESS','COMPLETED','REJECTED')
        )
);

-- ════════════════════════════════════════════════════════════
--  TABLE 14 : FORENSIC_RECORD
-- ════════════════════════════════════════════════════════════
CREATE TABLE FORENSIC_RECORD (
    Record_ID   NUMBER        CONSTRAINT pk_fr PRIMARY KEY,
    Case_ID     NUMBER        NOT NULL
        CONSTRAINT fk_fr_case REFERENCES CASES(Case_ID),
    Record_type VARCHAR2(50)  NOT NULL,
    Record_date DATE          DEFAULT SYSDATE,
    Prepared_by VARCHAR2(100),
    Description CLOB,
    Status      VARCHAR2(30)  DEFAULT 'DRAFT'
        CONSTRAINT chk_fr_status CHECK (Status IN ('DRAFT','FINAL','ARCHIVED'))
);

-- ════════════════════════════════════════════════════════════
--  TABLE 15 : NOMINATED_PERSON
-- ════════════════════════════════════════════════════════════
CREATE TABLE NOMINATED_PERSON (
    Nomination_ID        NUMBER        CONSTRAINT pk_np PRIMARY KEY,
    Case_ID              NUMBER        NOT NULL
        CONSTRAINT fk_np_case   REFERENCES CASES(Case_ID),
    Person_ID            NUMBER        NOT NULL
        CONSTRAINT fk_np_person REFERENCES PERSONS(Person_ID),
    Nominated_by         VARCHAR2(100),
    Nomination_date      DATE          DEFAULT SYSDATE,
    Role_in_case         VARCHAR2(100),
    Dissemination_status VARCHAR2(30)  DEFAULT 'PENDING'
        CONSTRAINT chk_np_status CHECK (
            Dissemination_status IN ('PENDING','APPROVED','REJECTED','DISSEMINATED')
        )
);

-- ════════════════════════════════════════════════════════════
--  HISTORY TABLES  (store old snapshots before every UPDATE)
-- ════════════════════════════════════════════════════════════
CREATE TABLE CASES_HISTORY (
    History_ID  NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    Case_ID     NUMBER        NOT NULL,
    Title       VARCHAR2(200),
    Description CLOB,
    Date_opened DATE,
    Date_closed DATE,
    Old_status  VARCHAR2(30),
    Changed_at  TIMESTAMP     DEFAULT SYSTIMESTAMP,
    Changed_by  VARCHAR2(100) DEFAULT SYS_CONTEXT('USERENV','SESSION_USER')
);

CREATE TABLE EVIDENCE_HISTORY (
    History_ID          NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    Evidence_ID         NUMBER        NOT NULL,
    Case_ID             NUMBER,
    Old_type            VARCHAR2(50),
    Old_description     VARCHAR2(500),
    Old_collected_by    VARCHAR2(100),
    Old_collection_date DATE,
    Old_status          VARCHAR2(30),
    Changed_at          TIMESTAMP     DEFAULT SYSTIMESTAMP,
    Changed_by          VARCHAR2(100) DEFAULT SYS_CONTEXT('USERENV','SESSION_USER')
);

CREATE TABLE SUSPECTS_HISTORY (
    History_ID       NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    Suspect_ID       NUMBER        NOT NULL,
    Old_threat_level VARCHAR2(20),
    Old_status       VARCHAR2(30),
    Changed_at       TIMESTAMP     DEFAULT SYSTIMESTAMP,
    Changed_by       VARCHAR2(100) DEFAULT SYS_CONTEXT('USERENV','SESSION_USER')
);

-- ════════════════════════════════════════════════════════════
--  INDEXES
-- ════════════════════════════════════════════════════════════
CREATE INDEX idx_ev_case      ON EVIDENCE(Case_ID);
CREATE INDEX idx_clue_case    ON CLUES(Case_ID);
CREATE INDEX idx_clue_ev      ON CLUES(Evidence_ID);
CREATE INDEX idx_csl_case     ON CASESTATUSLOG(Case_ID);
CREATE INDEX idx_eal_ev       ON EVIDENCEAUDITLOG(Evidence_ID);
CREATE INDEX idx_cocl_ev      ON CHAINOFCUSTODYLOG(Evidence_ID);
CREATE INDEX idx_eps_ev       ON EVIDENCEPHYSICALSTATE(Evidence_ID);
CREATE INDEX idx_lar_ev       ON LABANALYSISREQUEST(Evidence_ID);
CREATE INDEX idx_fr_case      ON FORENSIC_RECORD(Case_ID);
CREATE INDEX idx_np_case      ON NOMINATED_PERSON(Case_ID);
CREATE INDEX idx_np_person    ON NOMINATED_PERSON(Person_ID);
CREATE INDEX idx_cases_status ON CASES(Current_status);
CREATE INDEX idx_ev_status    ON EVIDENCE(Status);

COMMIT;

