"""G-13: AI-literacy training register for the people who operate the review pipeline.

  python3 scripts/training_register.py show-quiz --role adjudicator
      print the knowledge-check questions for a role (training/quiz.yaml).
  python3 scripts/training_register.py assess --person <github-login> --role adjudicator --answers T1=b,T2=c,...
      grade the answers; on a pass (training/records.yaml pass_mark) append a record.
  python3 scripts/training_register.py add --person <login> --role security --assessor <login> --evidence "TRN-42"
      record an instructor-led session (no quiz score).
  python3 scripts/training_register.py check [--today YYYY-MM-DD]
      valid records per required role, expiries within 30 days; exit 1 when a required role has none.
  python3 scripts/training_register.py status --person <login> --role adjudicator
      exit 0 if that person holds a valid record for the role, else 1.

The register is the evidence governance check G-13 reads; the human-queue sync and calibration use
it to tell trained adjudicators' decisions from the rest.
"""

from __future__ import annotations

import argparse
import datetime as dt
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from mara import training  # noqa: E402

REGISTER = ROOT / "training" / "records.yaml"
QUIZ = ROOT / "training" / "quiz.yaml"


def _today(a: argparse.Namespace) -> dt.date:
    return dt.date.fromisoformat(a.today) if getattr(a, "today", None) else dt.date.today()


def cmd_show_quiz(a: argparse.Namespace) -> int:
    for q in training.questions_for(training.load_quiz(a.quiz), a.role):
        print(f"{q['id']}. {q['question']}")
        for k, v in q["options"].items():
            print(f"   {k}) {v}")
    return 0


def cmd_assess(a: argparse.Namespace) -> int:
    quiz = training.load_quiz(a.quiz)
    answers = dict(kv.split("=", 1) for kv in a.answers.split(",") if "=" in kv)
    score, wrong = training.grade(quiz, a.role, answers)
    reg = training.load_register(a.register)
    print(f"{a.person} / {a.role}: score {score:.2f} (pass mark {reg.pass_mark:.2f})" + (f"; wrong or missing: {', '.join(wrong)}" if wrong else ""))
    if score < reg.pass_mark:
        print("not passed; no record written")
        return 1
    rec = training.add_record(reg, a.person, a.role, _today(a), score=score, assessor="quiz", evidence=a.evidence or "quiz")
    training.save_register(reg, a.register)
    print(f"record written: {rec.person} {rec.role} {rec.curriculum_version} {rec.date} → expires {rec.expires}")
    return 0


def cmd_add(a: argparse.Namespace) -> int:
    reg = training.load_register(a.register)
    rec = training.add_record(reg, a.person, a.role, _today(a), score=None, assessor=a.assessor, evidence=a.evidence)
    training.save_register(reg, a.register)
    print(f"record written: {rec.person} {rec.role} {rec.curriculum_version} {rec.date} → expires {rec.expires} (assessor {rec.assessor})")
    return 0


def cmd_check(a: argparse.Namespace) -> int:
    reg = training.load_register(a.register)
    today = _today(a)
    cov = training.coverage(reg, training.ROLES, today)
    missing = []
    print(f"curriculum {reg.curriculum_version}; {len(reg.records)} record(s), {len(reg.valid(today))} valid on {today}")
    for role, recs in cov.items():
        people = ", ".join(sorted({r.person for r in recs})) or "nobody"
        print(f"  {role}: {len(recs)} valid ({people})")
        if not recs:
            missing.append(role)
    for r in reg.expiring(today):
        print(f"  expiring: {r.person} {r.role} on {r.expires}")
    if missing:
        print(f"no valid record for: {', '.join(missing)}")
        return 1
    return 0


def cmd_status(a: argparse.Namespace) -> int:
    ok = training.is_trained(training.load_register(a.register), a.person, a.role, _today(a))
    print(f"{a.person} / {a.role}: {'trained' if ok else 'NOT trained (no valid record)'}")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--register", type=Path, default=REGISTER)
    ap.add_argument("--quiz", type=Path, default=QUIZ)
    ap.add_argument("--today", help="YYYY-MM-DD (default: today)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("show-quiz")
    s.add_argument("--role", required=True, choices=training.ROLES)
    s = sub.add_parser("assess")
    s.add_argument("--person", required=True)
    s.add_argument("--role", required=True, choices=training.ROLES)
    s.add_argument("--answers", required=True, help="comma-separated id=option, e.g. T1=b,T2=a")
    s.add_argument("--evidence", default="")
    s = sub.add_parser("add")
    s.add_argument("--person", required=True)
    s.add_argument("--role", required=True, choices=training.ROLES)
    s.add_argument("--assessor", required=True)
    s.add_argument("--evidence", required=True)
    sub.add_parser("check")
    s = sub.add_parser("status")
    s.add_argument("--person", required=True)
    s.add_argument("--role", required=True, choices=training.ROLES)
    a = ap.parse_args()
    try:
        return {"show-quiz": cmd_show_quiz, "assess": cmd_assess, "add": cmd_add, "check": cmd_check, "status": cmd_status}[a.cmd](a)
    except (OSError, ValueError, KeyError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
