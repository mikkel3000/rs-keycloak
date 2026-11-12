#!/usr/bin/env python3
"""Pass, fail and cannot-run counts for Keycloak's tests/base against rs-keycloak.

Usage: counts.py TESTS_BASE_DIR SUREFIRE_REPORTS_DIR [--json]

A test cannot run against a remote server when it, its class, a parent class
or its server config needs something only a server started by the framework,
or code inside the Keycloak JVM, can give; such tests count as cannot-run
even when they happen to pass. Class-wide needs (server options, provider
jars, TLS, a database connection, Infinispan) cover every test in the class.
Run-on-server and time-offset clients are injected into many classes but used
by few tests, so they cover only the tests whose body, or a helper method of
the class the body calls, uses them. Tests the suite skips count as
cannot-run too. Everything else is a pass or a fail from the surefire reports.
"""
import collections
import json
import pathlib
import re
import sys
import xml.etree.ElementTree as ElementTree

PACKAGE = 'org.keycloak.tests.'

# Checked in order on the class and its parents; the first match names the group.
CLASS_MARKERS = [
    ('database', re.compile(r'@InjectTestDatabase')),
    ('tls', re.compile(r'@InjectCertificates')),
    ('infinispan', re.compile(r'@InjectInfinispanServer|ClusteredKeycloakServer|@InjectLoadBalancer')),
    ('time-offset', re.compile(r'@InjectTimeOffSet\([^)]*offset\s*=\s*[1-9]')),
]
CONFIG_MARKERS = [
    ('providers', re.compile(r'\.dependency\(|\.dependencyCurrentProject\(|\.dependencies\(')),
    ('tls', re.compile(r'\.tls\(|https-key-store|https-certificate')),
    ('infinispan', re.compile(r'cacheConfig|\.cache\(')),
    ('server-options', re.compile(r'\.option\(|\.options\(|\.features\(|\.featuresDisabled\(|\.spiOption\(')),
]
# Injected clients that call into the server only when a test uses them.
FIELD_MARKERS = [
    ('run-on-server', re.compile(r'@Inject(?:RunOnServer|TestClassServer)\b[^;]*?\s(\w+)\s*;', re.S)),
    ('time-offset', re.compile(r'@InjectTimeOffSet\b[^;]*?\s(\w+)\s*;', re.S)),
]
# Classes the remote framework waits on for minutes, for a TLS listener on
# 8443 or an Infinispan container; run.sh leaves them out of the Maven run and
# their tests are counted from the source.
WAIT_MARKER = re.compile(r'@InjectCertificates|@InjectInfinispanServer|ClusteredKeycloakServer|@InjectLoadBalancer')
TEST_METHOD = re.compile(r'@(?:Test|ParameterizedTest|RepeatedTest|TestFactory)\b[^{;]*?\bvoid\s+(\w+)\s*\(', re.S)
# Failing classes whose feature the framework uses to set other tests up. A
# failing test counts as blocked by a class when its own class, parents
# included, uses that feature; the counts overlap. RealmCreateTest counts the
# tests whose managed realm creation itself failed.
BLOCKERS = [
    ('admin.realm.RealmCreateTest', 'RealmSupplier: BadRequestException'),
    ('admin.client.ClientProtocolMapperTest', re.compile(r'@InjectOAuthClient\b')),
    ('admin.ClientTest', re.compile(r'\.clients\(|addClient\(|@InjectClient\b')),
    ('admin.user.UserSearchTest', re.compile(r'\.users\(|addUser\(|@InjectUser\b')),
    ('admin.event.LoginEventsTest', re.compile(r'@InjectEvents\b')),
    ('admin.event.AdminEventTest', re.compile(r'@InjectAdminEvents\b')),
    ('admin.event.EventConfigTest', re.compile(r'@Inject(?:Admin)?Events\b')),
    ('admin.realm.RealmRolesCRUDTest', re.compile(r'\.roles\(|realmRole')),
    ('admin.realm.RealmUpdateTest', re.compile(r'updateWithCleanup')),
    ('oauth.RefreshTokenTest', re.compile(r'@InjectOAuthClient\b')),
]
DECLARATION = re.compile(r'\b(?:class|interface|enum|record)\s+(\w+)')
METHOD = re.compile(r'\b(?:void|[\w<>\[\],.? ]+?)\s+(\w+)\s*\([^)]*\)\s*(?:throws [\w., ]+)?\{')


def block(text, start):
    """The index of the brace closing the block that opens at `start`."""
    depth = 0
    for index in range(start, len(text)):
        if text[index] == '{':
            depth += 1
        elif text[index] == '}':
            depth -= 1
            if depth == 0:
                return index
    return len(text)


def class_bodies(sources):
    """Maps each simple class name to the text of its declaration and body."""
    bodies = {}
    for path in sources:
        text = path.read_text(errors='replace')
        for match in DECLARATION.finditer(text):
            start = text.find('{', match.end())
            if start < 0:
                continue
            # Annotations sit just before the declaration.
            head = text.rfind(';', 0, match.start())
            bodies.setdefault(match.group(1), text[head + 1:block(text, start) + 1])
    return bodies


def methods(body):
    """Maps method names in a class body to their bodies."""
    found = {}
    for match in METHOD.finditer(body):
        end = block(body, match.end() - 1)
        found.setdefault(match.group(1), body[match.end():end])
    return found


def lineage(name, bodies):
    """The class and its parents found in the sources, nearest first."""
    chain = []
    while name in bodies and name not in chain:
        chain.append(name)
        parent = re.search(r'\bclass\s+' + name + r'\b[^{]*?\bextends\s+(\w+)', bodies[name])
        name = parent.group(1) if parent else None
    return chain


def class_group(chain, bodies):
    for name in chain:
        body = bodies[name]
        head = body[:body.find('{')]
        for group, pattern in CLASS_MARKERS:
            if pattern.search(body):
                return group
        for config in re.findall(r'config\s*=\s*(?:\w+\.)*(\w+)\.class', head):
            for config_name in lineage(config, bodies) or [config]:
                for group, pattern in CONFIG_MARKERS:
                    if pattern.search(bodies.get(config_name, '')):
                        return group
    return None


def method_group(chain, method, bodies):
    every = {}
    for name in reversed(chain):
        every.update(methods(bodies[name]))
    body = every.get(method)
    if body is None:
        return None
    for group, pattern in FIELD_MARKERS:
        fields = {field for name in chain for field in pattern.findall(bodies[name])}
        if not fields:
            continue
        use = re.compile(r'\b(?:' + '|'.join(map(re.escape, fields)) + r')\s*\.')
        helpers = {name for name, text in every.items() if use.search(text)}
        if use.search(body) or any(re.search(r'\b' + helper + r'\s*\(', body) for helper in helpers):
            return group
    return None


def cause(element):
    """A short failure cause: the framework supplier that failed, or the exception."""
    text = element.text or ''
    supplier = re.search(r'at org\.keycloak\.testframework\.[\w.]*\.(\w+Supplier)\.', text)
    kind = (element.get('type') or '').rsplit('.', 1)[-1]
    message = element.get('message') or ''
    detail = message.splitlines()[0][:80] if message else ''
    if supplier:
        return f'{supplier.group(1)}: {kind} {detail}'.strip()
    return f'{kind} {detail}'.strip()


def waiting_classes(base, bodies):
    """Test classes in tests/base the remote framework would wait on, by name."""
    found = {}
    root = base / 'src/test/java'
    for path in sorted(root.rglob('*.java')):
        name = path.stem
        body = bodies.get(name, '')
        if re.search(r'\babstract\b[^{;]*\bclass\s+' + name + r'\b', body):
            continue
        if any(WAIT_MARKER.search(bodies[link]) for link in lineage(name, bodies)):
            found['.'.join(path.relative_to(root).with_suffix('').parts)] = path.relative_to(root)
    return found


def main():
    base = pathlib.Path(sys.argv[1])
    bodies = class_bodies(base.parent.glob('*/src/**/*.java'))
    if sys.argv[2:] == ['--exclusions']:
        for path in waiting_classes(base, bodies).values():
            print(path)
        return
    reports = pathlib.Path(sys.argv[2])
    as_json = '--json' in sys.argv[3:]

    areas = collections.defaultdict(collections.Counter)
    groups = collections.defaultdict(collections.Counter)
    causes = collections.Counter()
    class_causes = collections.defaultdict(collections.Counter)
    class_counts = collections.defaultdict(collections.Counter)
    reported = set()
    for report in sorted(reports.glob('TEST-*.xml')):
        suite = ElementTree.parse(report).getroot()
        reported.add(suite.get('name'))
        for case in suite.iter('testcase'):
            classname = case.get('classname') or suite.get('name')
            if not classname.startswith(PACKAGE):
                continue
            short = classname[len(PACKAGE):]
            area = short.split('.')[0]
            chain = lineage(classname.rsplit('.', 1)[-1], bodies)
            method = re.split(r'[(\[]', case.get('name') or '')[0]
            group = class_group(chain, bodies) or method_group(chain, method, bodies)
            problem = next((child for child in case if child.tag in ('failure', 'error')), None)
            if group is None and any(child.tag == 'skipped' for child in case):
                group = 'skipped'
            if group:
                outcome = 'cannot-run'
                groups[group][area] += 1
            elif problem is not None:
                outcome = 'fail'
                reason = cause(problem)
                causes[reason] += 1
                class_causes[short][reason] += 1
            else:
                outcome = 'pass'
            areas[area][outcome] += 1
            class_counts[short][outcome] += 1
    if '--with-excluded' in sys.argv[3:]:
        for classname in waiting_classes(base, bodies):
            if classname in reported:
                continue
            short = classname[len(PACKAGE):]
            area = short.split('.')[0]
            chain = lineage(classname.rsplit('.', 1)[-1], bodies)
            group = class_group(chain, bodies) or 'tls'
            tests = {name for link in chain for name in TEST_METHOD.findall(bodies[link])}
            areas[area]['cannot-run'] += len(tests)
            groups[group][area] += len(tests)
            class_counts[short]['cannot-run'] += len(tests)

    blocked = collections.Counter()
    for short, counts in class_counts.items():
        failed = counts.get('fail', 0)
        if not failed:
            continue
        text = ''.join(bodies[link] for link in lineage(short.rsplit('.', 1)[-1], bodies))
        for blocker, need in BLOCKERS:
            if isinstance(need, str):
                blocked[blocker] += sum(n for reason, n in class_causes[short].items() if reason.startswith(need))
            elif need.search(text):
                blocked[blocker] += failed

    if as_json:
        print(json.dumps({
            'areas': areas, 'groups': groups, 'causes': causes, 'blocked': blocked,
            'classes': class_counts,
            'class_causes': {name: dict(counter) for name, counter in class_causes.items()},
        }, indent=1, sort_keys=True))
        return
    total = collections.Counter()
    print(f'{"area":<16}{"pass":>6}{"fail":>6}{"cannot-run":>12}')
    for area in sorted(areas):
        counts = areas[area]
        total.update(counts)
        print(f'{area:<16}{counts["pass"]:>6}{counts["fail"]:>6}{counts["cannot-run"]:>12}')
    print(f'{"total":<16}{total["pass"]:>6}{total["fail"]:>6}{total["cannot-run"]:>12}')
    print()
    print('cannot-run groups:')
    for group, counter in sorted(groups.items(), key=lambda item: -sum(item[1].values())):
        print(f'  {group:<16}{sum(counter.values()):>6}')
    print()
    print('most common failure causes:')
    for reason, count in causes.most_common(15):
        print(f'  {count:>5}  {reason}')
    print()
    print('failing tests blocked by each setup class (overlapping):')
    for blocker, _ in BLOCKERS:
        state = 'fails' if class_counts[blocker].get('fail') else 'does not fail'
        print(f'  {blocked[blocker]:>5}  {blocker} ({state})')


if __name__ == '__main__':
    main()
