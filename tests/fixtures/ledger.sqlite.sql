CREATE TABLE invoices (
    id TEXT PRIMARY KEY,
    date TEXT NOT NULL,
    counterparty TEXT NOT NULL,
    amount TEXT NOT NULL,
    currency TEXT NOT NULL,
    reference TEXT NOT NULL
);

CREATE TABLE expenses (
    id TEXT PRIMARY KEY,
    date TEXT NOT NULL,
    counterparty TEXT NOT NULL,
    amount TEXT NOT NULL,
    currency TEXT NOT NULL,
    reference TEXT NOT NULL
);

INSERT INTO invoices (id, date, counterparty, amount, currency, reference) VALUES
    ('INV-001', '2026-01-10', 'Acme Corp', '1250.00', 'USD', 'REF-1001'),
    ('INV-002', '2026-01-12', 'Beta LLC', '499.95', 'USD', ''),
    ('INV-003', '2026-01-15', 'Gamma GmbH', '300.00', 'EUR', 'REF-1003'),
    ('INV-004', '2026-01-18', 'Delta Inc', '-50.00', 'USD', 'REF-1004'),
    ('INV-005', '2026-01-20', 'Epsilon Ltd', '800.00', 'USD', 'REF-1005');

INSERT INTO expenses (id, date, counterparty, amount, currency, reference) VALUES
    ('EXP-001', '2026-01-10', 'Acme Corp', '1250.00', 'USD', 'REF-1001'),
    ('EXP-002', '2026-01-14', 'beta llc', '499.95', 'USD', ''),
    ('EXP-003', '2026-01-15', 'Gamma GmbH', '300.00', 'USD', 'REF-1003'),
    ('EXP-004', '2026-01-18', 'Delta Inc', '-50.00', 'USD', 'REF-1004'),
    ('EXP-006', '2026-01-25', 'Zeta Co', '120.00', 'USD', 'REF-9999');
