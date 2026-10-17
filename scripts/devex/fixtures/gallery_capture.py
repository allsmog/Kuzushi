"""Read visible gallery evidence without depending on optional status chrome."""
import re


POSITION = re.compile(r" rows? (\d+)(?:-(\d+))?/(\d+)(?: · lines (\d+)-(\d+)/(\d+))?\s*")


def is_chrome(line):
    return line.lstrip().startswith(("⛭", "─", "PgUp/PgDn", "NOTICE", "ERROR", "DONE", "kz>", "kuzushi>"))


def window(path, title):
    lines = path.read_text().splitlines()
    assert title in lines[0], (path, lines)
    positions = [(index, POSITION.fullmatch(line)) for index, line in enumerate(lines)]
    index, match = next((item for item in positions if item[1]), (None, None))
    if match is None:
        end = next((index for index in range(1, len(lines)) if is_chrome(lines[index])), len(lines))
        return {"body": lines[1:end], "first": None}
    first, last, total = (int(match[i]) for i in [4, 5, 6]) if match[4] else (
        int(match[1]), int(match[2] or match[1]), int(match[3]))
    end = index + 1 + last - first + 1
    body = lines[index + 1:end]
    assert len(body) == last - first + 1, (path, match[0], body)
    assert end == len(lines) or is_chrome(lines[end]), (path, lines[end:])
    return {"first": first, "last": last, "total": total, "logicalTotal": int(match[3]), "body": body}


def complete_text(captures, title):
    display = {}
    totals = set()
    whole = []
    for path in captures:
        shown = window(path, title)
        if shown["first"] is None:
            whole.append("".join(shown["body"]))
            continue
        totals.add(shown["total"])
        for number, line in enumerate(shown["body"], shown["first"]):
            assert number not in display or display[number] == line, (path, number)
            display[number] = line
    if whole:
        return max(whole, key=len)
    assert len(totals) == 1, totals
    total = totals.pop()
    assert set(display) == set(range(1, total + 1)), (title, sorted(display))
    return "".join(display[number] for number in range(1, total + 1))
