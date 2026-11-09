"""Data-only reconciliation of the unchanged project runner's complete log."""
import re


def summarize(text, expected):
    marks = list(re.finditer(r'^\[(\d+)/(\d+)\] (test[^\s/]+\.py)\s*$', text, re.M))
    summary = re.search(r'^Isolated unittest discovery: (\d+) files attempted; (\d+) failed\.\s*$', text, re.M)
    rows = []
    for index, mark in enumerate(marks):
        end = marks[index + 1].start() if index + 1 < len(marks) else len(text)
        block = text[mark.end():end]
        errors = re.findall(r'^Unittest child exited with status (-?\d+)\s*$', block, re.M)
        start_errors = re.findall(r'^Could not start unittest child: (.+)$', block, re.M)
        complete = index + 1 < len(marks) or summary is not None
        rows.append({'ordinal': int(mark[1]), 'denominator': int(mark[2]), 'module': mark[3],
                     'blob': expected.get(mark[3]), 'completed': complete,
                     'child_exit_code': int(errors[0]) if errors else 0 if complete and not start_errors else None,
                     'start_errors': start_errors,
                     'skip_summaries': [line for line in block.splitlines()
                                        if re.search(r'OK \(skipped=\d+\)|\b\d+ skipped\b', line)]})
    names = [row['module'] for row in rows]
    complete = bool(summary) and names == sorted(expected) and len(rows) == len(expected)
    complete = complete and all(row['ordinal'] == index and row['denominator'] == len(expected)
                                for index, row in enumerate(rows, 1))
    failures = sum(bool(row['child_exit_code']) or bool(row['start_errors']) for row in rows)
    if summary:
        complete = complete and int(summary[1]) == len(expected) and int(summary[2]) == failures
    return {'complete': complete, 'all_passed': complete and failures == 0,
            'modules_started': len(rows), 'modules_completed': sum(row['completed'] for row in rows),
            'modules_failed': failures, 'module_results': rows}
