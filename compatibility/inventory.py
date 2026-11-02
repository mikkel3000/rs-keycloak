#!/usr/bin/env python3
"""Extract source-declared JAX-RS methods; never infer resolved public routes."""
import argparse
import hashlib
import json
import pathlib
import re

HTTP = re.compile(r'(?m)^\s*@(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b')
METHOD = re.compile(r'(?m)^\s*(?:(?:public|protected|default|final|static)\s+)*(?:[\w<>?,.\[\]]+\s+)+(\w+)\s*\(')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=pathlib.Path)
    parser.add_argument('--output', required=True, type=pathlib.Path)
    args = parser.parse_args()
    lock = json.loads((pathlib.Path(__file__).parent / 'reference.lock').read_text())
    revision = lock['keycloak']['source_revision']
    rows = []
    for path in sorted(args.source.rglob('*.java')):
        if '/src/main/' not in str(path) or any(part in path.parts for part in ['integration', 'test-framework', 'testsuite', 'examples']):
            continue
        source = path.read_text()
        relative = str(path.relative_to(args.source))
        for match in HTTP.finditer(source):
            following = source[match.end():match.end() + 6000]
            method = METHOD.search(following)
            if not method:
                raise ValueError(f'unparsed HTTP method: {relative}:{source[:match.start()].count(chr(10)) + 1}')
            # Class/subresource prefix resolution and inherited annotations need semantic review.
            declaration = following[:method.end()]
            preceding = source[max(0, match.start() - 2500):match.start()]
            annotation_start = preceding.rfind('\n    @')
            nearby = preceding[annotation_start:] + declaration if annotation_start >= 0 else declaration
            paths = re.findall(r'@Path\(\s*"([^"\n]*)"\s*\)', nearby)
            line = source[:match.start()].count('\n') + 1
            rows.append({'id': f'{relative}:{line}', 'method': match[1], 'java_method': method[1], 'source_path': relative, 'source_line': line, 'source_revision': revision, 'source_sha256': hashlib.sha256(source.encode()).hexdigest(), 'path': None, 'declared_path_fragments': paths, 'route_resolution': 'pending-class-inheritance-subresource-provider-review', 'profile': None, 'lifecycle': 'unclassified', 'request_schema': None, 'response_schema': None, 'permission': None, 'side_effects': [], 'positive_tests': [], 'negative_tests': [], 'concurrency_tests': [], 'implementation_owner': None, 'status': 'planned'})
    args.output.write_text(json.dumps({'source_revision': revision, 'complete': False, 'inventory_kind': 'source-declared-http-methods-not-yet-resolved-public-routes', 'operations': rows}, indent=2) + '\n')
    print(f'{len(rows)} source-declared HTTP methods extracted; public route and lifecycle review pending')


if __name__ == '__main__':
    main()
