"""
seed_demo_data.py
------------------
Fills the database with realistic demo data so every dashboard (Marketing,
Technical, Journal team, and the MD/Admin overview) has something to show:
25 clients spread across every stage of the pipeline, a technical team,
a journal team, payments, work updates, journal targets, and a couple of
open client conversations.

HOW TO USE
  1. Make sure you are in the project folder (same folder as server.py) and
     DATABASE_URL is set (e.g. in .env) to point at your Postgres database.
  2. Run:   python seed_demo_data.py
  3. Start the app as usual:   python server.py
  4. Log in as MD / Admin (or any other role) and browse around.

Safe to re-run: if it finds the demo data was already added, it stops
and tells you, instead of adding everything twice. To get a completely
clean slate first, drop and recreate the tables in your Postgres database
(or just point DATABASE_URL at a fresh database).
"""
import random
from datetime import date, timedelta

import server

MARKER_ID = "CL-9001"  # first demo client ID; used to detect a previous run


def d_ago(n):
    return (date.today() - timedelta(days=n)).isoformat()


def d_ahead(n):
    return (date.today() + timedelta(days=n)).isoformat()


def main():
    server.init_db()
    con = server.db()

    already = con.execute("SELECT id FROM clients WHERE id=?", (MARKER_ID,)).fetchone()
    if already:
        print("Demo data already present (found %s) — nothing to do." % MARKER_ID)
        print("Point DATABASE_URL at a fresh database first if you want to reseed from scratch.")
        con.close()
        return

    # ---------------------------------------------------------------
    # 1) TEAM — technical + journal team members so assignments have
    #    real people to point to, and the Team page isn't empty.
    # ---------------------------------------------------------------
    def add_employee(name, role, team_type="", is_coordinator=False, coordinator_id=None):
        out = server.handle_action("employee_create", {
            "name": name, "role": role, "teamType": team_type,
            "email": name.lower().replace(" ", ".") + "@matiz.demo",
            "isCoordinator": is_coordinator, "coordinatorId": coordinator_id,
            "joiningDate": d_ago(random.randint(60, 700)),
        })
        row = con.execute("SELECT id FROM employees WHERE emp_uid=?", (out["empUid"],)).fetchone()
        return row["id"], name

    programmers = [
        add_employee("Ravi Kumar", "PROGRAMMER", is_coordinator=True),
        add_employee("Divya Shankar", "PROGRAMMER"),
        add_employee("Arun Prakash", "PROGRAMMER"),
        add_employee("Meena Iyer", "PROGRAMMER"),
    ]
    writers = [
        add_employee("Priya Raman", "PAPER_WRITER", is_coordinator=True),
        add_employee("Karthik Subramanian", "PAPER_WRITER"),
        add_employee("Lavanya Krishnan", "PAPER_WRITER"),
        add_employee("Naveen Balaji", "PAPER_WRITER"),
    ]
    journal_team = [
        add_employee("Suresh Babu", "JOURNAL_EMPLOYEE", "PROOFREAD_COORDINATOR"),
        add_employee("Anitha Ramesh", "JOURNAL_EMPLOYEE", "PROOFREADER"),
        add_employee("Vignesh Rajan", "JOURNAL_EMPLOYEE", "FORMAT_COORDINATOR"),
        add_employee("Kavya Narayan", "JOURNAL_EMPLOYEE", "FORMATTER"),
        add_employee("Deepak Menon", "JOURNAL_EMPLOYEE", "SUBMISSION"),
    ]
    add_employee("Sathish Telecaller", "TELECALLER")
    add_employee("Revathi Telecaller", "TELECALLER")

    prog_name = lambda i: programmers[i % len(programmers)][1]
    writer_name = lambda i: writers[i % len(writers)][1]

    print("Added %d technical + journal team members." % (len(programmers) + len(writers) + len(journal_team) + 2))

    # ---------------------------------------------------------------
    # 2) CLIENTS — one per pipeline stage (marketing -> technical ->
    #    journal -> completed), plus a rejected one, plus a few extra
    #    overdue / due-soon / this-month-vs-last-month cases so every
    #    KPI on the MD Admin dashboard has real numbers behind it.
    # ---------------------------------------------------------------
    BDCS = ["Sanjay", "Arjun", "Meera", "Vikram"]
    DOMAINS = ["Machine Learning", "IoT", "Cloud Computing", "Cybersecurity", "Blockchain",
               "NLP", "Computer Vision", "VLSI", "Renewable Energy", "Data Mining",
               "Wireless Networks", "Robotics", "Big Data", "Embedded Systems", "5G Networks"]
    INSTITUTIONS = ["Anna University", "VIT Vellore", "SRM Institute", "PSG Tech",
                     "NIT Trichy", "Amrita University", "Karunya University", "SASTRA University"]

    n = 9001
    pn = 9001

    def next_ids():
        nonlocal n, pn
        cid = "CL-%d" % n
        proj = "PRJ-%d" % pn
        n += 1
        pn += 1
        return cid, proj

    def add_history(cid, stage, actor, note="", days_ago=0):
        con.execute("""INSERT INTO history (client_id, stage, actor, note, created_at)
                       VALUES (?,?,?,?, datetime('now','localtime','-%d days'))""" % days_ago,
                    (cid, stage, actor, note))

    def set_payment(cid, key, amount, days_ago):
        con.execute("""UPDATE payments SET status='paid', amount=?, pay_date=?
                       WHERE client_id=? AND pay_key=?""",
                    (amount, d_ago(days_ago), cid, key))

    def add_client(name, phone, stage, service_key, reg_days_ago, deadline_in_days,
                    bdc=None, domain=None, institution=None, paid_keys=None,
                    programmers_on=None, writers_on=None, journal_name="", journal_status="",
                    demo_days_ago=None, rejected=False, reject_reason="",
                    work_updates=None, has_query=False):
        cid, proj = next_ids()
        conf = server.SERVICES[service_key]
        bdc = bdc or random.choice(BDCS)
        domain = domain or random.choice(DOMAINS)
        institution = institution or random.choice(INSTITUTIONS)
        reg_date = d_ago(reg_days_ago)
        deadline = d_ahead(deadline_in_days)
        total = sum(conf["amounts"].values())

        con.execute("""INSERT INTO clients
            (id, display_id, project_id, name, phone, email, domain, address, notes,
             reg_date, deadline_date, stage, service_key, bdc, designation, institution,
             topic, total_amount, demo_given_date, journal_name, journal_status,
             assigned_programmers, assigned_writers, rejected, reject_reason)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (cid, cid, proj, name, phone, name.lower().replace(" ", ".") + "@demo-client.com",
             domain, "Chennai, Tamil Nadu", "Demo record for dashboard testing.",
             reg_date, deadline, stage, service_key, bdc, "PG Scholar", institution,
             domain + " — " + name.split()[0] + "'s project", total,
             d_ago(demo_days_ago) if demo_days_ago is not None else None,
             journal_name, journal_status,
             ",".join(programmers_on or []), ",".join(writers_on or []),
             1 if rejected else 0, reject_reason))

        for k in server.PAY_KEYS:
            con.execute("INSERT INTO payments (client_id, pay_key) VALUES (?,?)", (cid, k))
        for k in (paid_keys or []):
            if k in conf["amounts"]:
                set_payment(cid, k, conf["amounts"][k], random.randint(1, max(reg_days_ago, 1)))

        add_history(cid, "NEW", "Telecaller (demo)", "Lead registered.", reg_days_ago)
        if stage != "NEW":
            add_history(cid, stage, "System (demo)", "Fast-forwarded for demo data.", max(reg_days_ago - 2, 0))

        for w in (work_updates or []):
            con.execute("""INSERT INTO work_updates (client_id, emp_name, milestone, note, created_at)
                           VALUES (?,?,?,?, datetime('now','localtime','-%d days'))""" % w[2],
                        (cid, w[0], w[1], w[3] if len(w) > 3 else ""))

        if journal_name:
            con.execute("""INSERT INTO journal_targets (client_id, name, status, added_by)
                           VALUES (?,?,?, 'Journal Manager (demo)')""",
                        (cid, journal_name, journal_status or "SUBMITTED"))

        if has_query:
            con.execute("""INSERT INTO messages (client_id, thread_with, sender_type, sender_name, body)
                           VALUES (?,?,?,?,?)""",
                        (cid, "Telecaller", "client", name,
                         "Hi, could you share an update on where my project stands?"))

        return cid

    clients_made = []

    # ---- Marketing pipeline (not yet with the technical team) ----
    clients_made.append(add_client("Satish Kumar R", "9840011001", "NEW", "SCI",
        reg_days_ago=1, deadline_in_days=45, has_query=True))
    clients_made.append(add_client("Divya Prasanna", "9840011002", "TL_REVIEW", "SCOPUS_PAID",
        reg_days_ago=2, deadline_in_days=40, paid_keys=["reg"]))
    clients_made.append(add_client("Mohammed Faizal", "9840011003", "MANAGER_REVIEW", "SCI",
        reg_days_ago=3, deadline_in_days=50, paid_keys=["reg"]))
    clients_made.append(add_client("Keerthana Velu", "9840011004", "ACCOUNT_REVIEW", "SYNOPSIS",
        reg_days_ago=4, deadline_in_days=30, paid_keys=["reg"]))

    # ---- Technical: proposal stage ----
    clients_made.append(add_client("Gokul Anand", "9840011005", "TECH_ASSIGNED", "SCI",
        reg_days_ago=10, deadline_in_days=42, paid_keys=["reg"]))
    clients_made.append(add_client("Swathi Ramachandran", "9840011006", "PROPOSAL_ASSIGNED", "SCI",
        reg_days_ago=12, deadline_in_days=38, paid_keys=["reg"], writers_on=[writer_name(0)],
        work_updates=[(writer_name(0), "PROGRESS_NOTE", 3, "Started drafting the proposal.")]))
    clients_made.append(add_client("Harini Baskar", "9840011007", "PROPOSAL_SUBMITTED", "SCI",
        reg_days_ago=15, deadline_in_days=35, paid_keys=["reg"], writers_on=[writer_name(1)],
        work_updates=[(writer_name(1), "PROGRESS_NOTE", 1, "Proposal submitted for review.")]))
    clients_made.append(add_client("Bala Murugan", "9840011008", "PROPOSAL_VERIFIED", "SCOPUS_PAID",
        reg_days_ago=18, deadline_in_days=33, paid_keys=["reg"], writers_on=[writer_name(2)], has_query=True))

    # ---- Technical: implementation stage ----
    clients_made.append(add_client("Nandhini Selvam", "9840011009", "IMPLEMENTATION_ASSIGNED", "SCI",
        reg_days_ago=25, deadline_in_days=20, paid_keys=["reg", "start"],
        programmers_on=[prog_name(0)],
        work_updates=[(prog_name(0), "PROGRESS_NOTE", 2, "Module 1 of 3 implemented.")]))
    clients_made.append(add_client("Yuvaraj Chandran", "9840011010", "IMPLEMENTATION_COMPLETE", "SCI",
        reg_days_ago=28, deadline_in_days=18, paid_keys=["reg", "start"],
        programmers_on=[prog_name(1)], demo_days_ago=2,
        work_updates=[(prog_name(1), "CODE_DELIVERED", 1, "Implementation complete, ready for client review.")]))
    clients_made.append(add_client("Abinaya Chezhian", "9840011011", "IMPLEMENTATION_CLIENT_REVIEW", "SCOPUS_PAID",
        reg_days_ago=30, deadline_in_days=15, paid_keys=["reg", "start"],
        programmers_on=[prog_name(2)], demo_days_ago=1, has_query=True))

    # ---- Technical: paper writing stage ----
    clients_made.append(add_client("Praveen Dinakaran", "9840011012", "PAPERWRITER_ASSIGNED", "SCI",
        reg_days_ago=35, deadline_in_days=25, paid_keys=["reg", "start", "code"],
        writers_on=[writer_name(3)],
        work_updates=[(writer_name(3), "PROGRESS_NOTE", 4, "Literature review complete.")]))
    clients_made.append(add_client("Sowmiya Rangan", "9840011013", "TECHTL_REVIEW", "SCI",
        reg_days_ago=40, deadline_in_days=22, paid_keys=["reg", "start", "code"],
        writers_on=[writer_name(0)],
        work_updates=[(writer_name(0), "PAPER_DELIVERED", 2, "Draft sent for Technical TL review.")]))
    clients_made.append(add_client("Dinesh Kanagaraj", "9840011014", "WRITING_COMPLETE", "SCOPUS_NO_IMPL",
        reg_days_ago=45, deadline_in_days=12, paid_keys=["reg", "paper"],
        writers_on=[writer_name(1)]))

    # ---- With the client for final approval ----
    clients_made.append(add_client("Roshini Vetriselvan", "9840011015", "CLIENT_REVIEW", "SCI",
        reg_days_ago=50, deadline_in_days=10, paid_keys=["reg", "start", "code", "writing"],
        writers_on=[writer_name(2)], has_query=True))
    clients_made.append(add_client("Ashwin Kaliaperumal", "9840011016", "CLIENT_ACCEPTED", "THESIS_100",
        reg_days_ago=55, deadline_in_days=8, paid_keys=["reg", "paper"]))

    # ---- Journal team stages ----
    clients_made.append(add_client("Preethi Manoharan", "9840011017", "JOURNAL_MANAGER_REVIEW", "SCI",
        reg_days_ago=60, deadline_in_days=20, paid_keys=["reg", "start", "code", "writing"],
        journal_name="IEEE Access", journal_status="SUBMITTED"))
    clients_made.append(add_client("Vishal Ganesan", "9840011018", "PROOFREADING", "SCOPUS_PAID",
        reg_days_ago=65, deadline_in_days=18, paid_keys=["reg", "start", "code"],
        journal_name="Springer Journal of Networks", journal_status="UNDER_REVIEW"))
    clients_made.append(add_client("Janani Sundaravel", "9840011019", "FORMATTING_IN_PROGRESS", "SCI",
        reg_days_ago=70, deadline_in_days=15, paid_keys=["reg", "start", "code", "writing"],
        journal_name="Elsevier Computers & Security", journal_status="REVISION_REQUESTED"))
    clients_made.append(add_client("Rajesh Muthukumar", "9840011020", "SUBMISSION", "SCOPUS_PAID",
        reg_days_ago=75, deadline_in_days=10, paid_keys=["reg", "start", "code"],
        journal_name="Wiley Concurrency & Computation", journal_status="ACCEPTED"))
    clients_made.append(add_client("Anushya Palanisamy", "9840011021", "JOURNAL_SUBMITTED", "SCI",
        reg_days_ago=80, deadline_in_days=5, paid_keys=["reg", "start", "code", "writing"],
        journal_name="Taylor & Francis Applied Sciences", journal_status="UNDER_REVIEW"))

    # ---- Completed ----
    clients_made.append(add_client("Kiruthika Elangovan", "9840011022", "COMPLETED", "SCI",
        reg_days_ago=95, deadline_in_days=-10, paid_keys=["reg", "start", "code", "writing", "paper"],
        journal_name="IEEE Transactions on AI", journal_status="PUBLISHED"))
    clients_made.append(add_client("Manikandan Sivaraj", "9840011023", "COMPLETED", "SCOPUS_NO_IMPL",
        reg_days_ago=110, deadline_in_days=-20, paid_keys=["reg", "paper"],
        journal_name="ACM Computing Surveys", journal_status="PUBLISHED"))

    # ---- Rejected ----
    clients_made.append(add_client("Test Reject Case", "9840011024", "NEW", "SYNOPSIS",
        reg_days_ago=5, deadline_in_days=30, rejected=True,
        reject_reason="Client did not respond after multiple follow-ups."))

    # ---- A couple of extra overdue clients so "Overdue projects" has more than one row ----
    clients_made.append(add_client("Overdue Case One", "9840011025", "PROPOSAL_VERIFIED", "SCI",
        reg_days_ago=60, deadline_in_days=-6, paid_keys=["reg"]))
    clients_made.append(add_client("Overdue Case Two", "9840011026", "TECHTL_REVIEW", "SCOPUS_PAID",
        reg_days_ago=70, deadline_in_days=-2, paid_keys=["reg", "start", "code"]))

    con.commit()
    con.close()

    print("Added %d demo clients (IDs %s .. %s)." % (len(clients_made), clients_made[0], clients_made[-1]))
    print("Covers: new leads, TL/Manager/Accounts review, technical (proposal +")
    print("implementation + paper writing), journal team (proofreading, formatting,")
    print("submission, published), a rejected lead, and overdue deadlines.")
    print("Start the app with:  python server.py")


if __name__ == "__main__":
    main()
