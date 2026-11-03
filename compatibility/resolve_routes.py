#!/usr/bin/env python3
"""Resolve JAX-RS class, method, inheritance and typed subresource paths."""
import argparse
import hashlib
import json
import pathlib
import re
import tarfile
import tempfile
from collections import defaultdict
import route_sources

VERBS = {'GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'}


def resolve(classes, revision, source_root):
    simple = defaultdict(list)
    for name in classes:
        simple[name.rsplit('.', 1)[-1]].append(name)

    def typename(value, owner):
        value = re.sub(r'<.*>', '', value).strip()
        if value in classes:
            return value
        for imported in owner['imports']:
            if imported.endswith('.' + value) and imported in classes:
                return imported
        nested = owner['class'] + '.' + value
        if nested in classes:
            return nested
        local = owner['class'].rsplit('.', 1)[0] + '.' + value
        if local in classes:
            return local
        matches = simple.get(value, [])
        return matches[0] if len(matches) == 1 else None

    def literal(expression, owner, stack=()):
        expression = expression.strip()
        if expression.startswith('(') and expression.endswith(')'):
            expression = expression[1:-1].strip()
        if expression in stack:
            return None
        pieces = re.split(r'\s*\+\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', expression)
        if len(pieces) > 1:
            values = [literal(piece, owner, stack) for piece in pieces]
            return ''.join(values) if all(isinstance(value, str) for value in values) else None
        if expression.startswith('"') and expression.endswith('"'):
            try:
                return json.loads(expression)
            except json.JSONDecodeError:
                return None
        if expression in owner['constants']:
            return literal(owner['constants'][expression], owner, stack + (expression,))
        if '.' in expression:
            type_name, constant = expression.rsplit('.', 1)
            target = typename(type_name, owner)
            if target:
                return literal(constant, classes[target], stack + (expression,))
        for base in owner['bases']:
            target = typename(base, owner)
            if target and (target + ':' + expression) not in stack:
                value = literal(expression, classes[target], stack + (target + ':' + expression,))
                if value is not None:
                    return value
        for imported in owner['imports']:
            if imported.endswith('.' + expression):
                target = imported.rsplit('.', 1)[0]
                if target in classes:
                    return literal(expression, classes[target], stack + (owner['class'] + ':' + expression,))
        return None

    effective_cache = {}

    def methods(name, stack=()):
        if name in effective_cache:
            return effective_cache[name]
        if name in stack:
            return {}
        owner = classes[name]
        inherited = {}
        for base in owner['bases']:
            target = typename(base, owner)
            if target:
                inherited.update(methods(target, stack + (name,)))
        for method in owner['methods']:
            key = method['name'], tuple(method['parameters'])
            row = method | {'declaring_class': name}
            parent = inherited.get(key)
            if parent and not (set(method['annotations']) & (VERBS | {'Path', 'Produces', 'Consumes'})):
                row['annotations'] = parent['annotations'] | method['annotations']
                row['annotation_source'] = parent.get('annotation_source', parent['declaring_class'])
            inherited[key] = row
        effective_cache[name] = inherited
        return inherited

    roots = []
    for name, owner in classes.items():
        path = owner['annotations'].get('Path')
        if isinstance(path, str) and not name.startswith('org.keycloak.operator.'):
            roots.append((name, path, [{'kind': 'class-root', 'source': owner['source'], 'class': name}]))

    unresolved = []
    rows = []
    seen = {}

    def targets(name, method, stack=()):
        if method['name'] in stack:
            return set()
        owner = classes[name]
        target = typename(method['return_type'], owner)
        result = {target} if target else set()
        for returned in method['returns']:
            target = name if returned.get('value') == 'this' else typename(returned.get('new', ''), owner)
            if target:
                result.add(target)
            called = returned.get('call')
            if called:
                for candidate in methods(name).values():
                    if candidate['name'] == called:
                        result.update(targets(name, candidate, stack + (method['name'],)))
        return result

    def visit(name, prefix, evidence, stack=()):
        if name in stack:
            unresolved.append({'class': name, 'prefix': prefix, 'reason': 'recursive-subresource-cycle', 'evidence': evidence})
            return
        owner = classes[name]
        for method in methods(name).values():
            annotations = method['annotations']
            verbs = VERBS & set(annotations)
            if not verbs and 'Path' not in annotations:
                continue
            fragment = annotations.get('Path', '')
            original_fragment = fragment
            declaring = classes[method['declaring_class']]
            method_evidence = {'source': declaring['source'], 'line': method['line'], 'method': method['name'], 'declaring_class': method['declaring_class']}
            if isinstance(fragment, dict):
                fragment = literal(fragment.get('expression', ''), declaring)
            if not isinstance(fragment, str):
                unresolved.append({'class': name, 'prefix': prefix, 'reason': 'nonliteral-path-expression', 'expression': original_fragment, 'evidence': evidence + [method_evidence]})
                continue
            path = '/' + '/'.join(part.strip('/') for part in (prefix, fragment) if part.strip('/'))
            chain = evidence + [method_evidence]
            if verbs:
                for verb in sorted(verbs):
                    key = verb, path, method['declaring_class'], method['name'], method['line']
                    if key in seen:
                        binding = evidence[0] if evidence and evidence[0].get('kind') == 'registered-provider-binding' else None
                        if binding and binding not in seen[key]['dispatch_bindings']:
                            seen[key]['dispatch_bindings'].append(binding)
                        continue
                    source_path = declaring['source']
                    row = {'id': f'{verb} {path} [{method["declaring_class"]}#{method["name"]}:{method["line"]}]', 'method': verb, 'path': path, 'java_method': method['name'], 'parameter_types': method['parameters'], 'consumes_annotation': annotations.get('Consumes'), 'produces_annotation': annotations.get('Produces'), 'annotation_source': method.get('annotation_source', method['declaring_class']), 'resource_class': name, 'declaring_class': method['declaring_class'], 'source_path': source_path, 'source_line': method['line'], 'source_revision': revision, 'source_sha256': hashlib.sha256((source_root / source_path).read_bytes()).hexdigest(), 'route_resolution': 'source-resolved-not-runtime-verified', 'route_evidence': chain, 'dispatch_bindings': [evidence[0]] if evidence and evidence[0].get('kind') == 'registered-provider-binding' else [], 'profile': None, 'lifecycle': 'unclassified', 'request_schema': None, 'response_schema': None, 'permission': None, 'side_effects': [], 'positive_tests': [], 'negative_tests': [], 'concurrency_tests': [], 'implementation_owner': None, 'status': 'planned'}
                    rows.append(row)
                    seen[key] = row
            else:
                candidates = targets(name, method)
                if not candidates:
                    unresolved.append({'class': name, 'method': method['name'], 'prefix': path, 'return_type': method['return_type'], 'return_expressions': method['returns'], 'reason': 'runtime-provider-or-nonlocal-factory-return', 'evidence': chain})
                for candidate in sorted(candidates):
                    visit(candidate, path, chain, stack + (name,))

    # Expand only factories explicitly registered in the tagged service descriptors.
    registrations = [
        ('org.keycloak.protocol.oidc.ext.OIDCExtProviderFactory', '/realms/{realm}/protocol/openid-connect/ext/{id}', ['create']),
        ('org.keycloak.protocol.LoginProtocolFactory', '/realms/{realm}/protocol/{id}', ['createProtocolEndpoint']),
        ('org.keycloak.services.resource.RealmResourceProviderFactory', '/realms/{realm}/{id}', ['create', 'getResource']),
        ('org.keycloak.services.resources.admin.ext.AdminRealmResourceProviderFactory', '/admin/realms/{realm}/{id}', ['create', 'getResource']),
        ('org.keycloak.services.clientregistration.ClientRegistrationProviderFactory', '/realms/{realm}/clients-registrations/{id}', ['create']),
        ('org.keycloak.services.resource.AccountResourceProviderFactory', '/realms/{realm}/account', ['create', 'getResource']),
        ('org.keycloak.broker.provider.IdentityProviderFactory', '/realms/{realm}/broker/{provider_alias}/endpoint', ['create', 'callback']),
    ]
    for spi, prefix, stages in registrations:
        for descriptor in sorted(source_root.rglob('META-INF/services/' + spi)):
            if '/src/main/resources/' not in str(descriptor) or any(part in descriptor.parts for part in ['tests', 'testsuite', 'test-framework', 'examples']):
                continue
            for factory in descriptor.read_text().splitlines():
                factory = factory.split('#', 1)[0].strip()
                if factory not in classes:
                    continue
                owner = classes[factory]
                ids = [literal(r['value'], classes[m['declaring_class']]) for m in methods(factory).values() if m['name'] == 'getId' for r in m['returns'] if 'value' in r]
                ids = [value for value in ids if isinstance(value, str)]
                if '{id}' in prefix and len(set(ids)) != 1:
                    unresolved.append({'factory': factory, 'source': str(descriptor.relative_to(source_root)), 'reason': 'registered-provider-id-not-statically-resolved'})
                    continue
                binding = prefix.replace('{id}', ids[0]) if '{id}' in prefix else prefix
                candidates = {factory}
                for stage in stages:
                    next_candidates = set()
                    for candidate in sorted(candidates):
                        selected = [m for m in methods(candidate).values() if m['name'] == stage]
                        for method in selected:
                            next_candidates.update(targets(candidate, method))
                        if stage == 'getResource' and not selected:
                            next_candidates.add(candidate)
                    candidates = next_candidates
                for candidate in sorted(candidates):
                    roots.append((candidate, binding, [{'kind': 'registered-provider-binding', 'spi': spi, 'descriptor': str(descriptor.relative_to(source_root)), 'factory': factory, 'factory_source': owner['source'], 'provider_id': ids[0] if len(set(ids)) == 1 else None, 'dispatch_methods': stages}]))

    for root, prefix, evidence in roots:
        visit(root, prefix, evidence)
    reachable = {(r['declaring_class'], r['java_method'], r['source_line']) for r in rows}
    for name in sorted(classes):
        for method in classes[name]['methods']:
            if set(method['annotations']) & VERBS and (name, method['name'], method['line']) not in reachable:
                unresolved.append({'class': name, 'method': method['name'], 'source': classes[name]['source'], 'line': method['line'], 'reason': 'no-static-root-path-found-runtime-provider-registration-or-unreached-locator'})
    rows.sort(key=lambda row: (row['path'], row['method'], row['declaring_class'], row['source_line']))
    unresolved = [json.loads(value) for value in sorted({json.dumps(entry, sort_keys=True) for entry in unresolved})]
    return {'source_revision': revision, 'complete': False, 'inventory_kind': 'syntax-resolved-http-routes-runtime-profile-permission-review-pending', 'route_variant_count': len(rows), 'unique_method_path_count': len({(row['method'], row['path']) for row in rows}), 'operations': rows, 'unresolved': unresolved}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', required=True, type=pathlib.Path, help='Exact source archive pinned in reference.lock')
    parser.add_argument('--output', required=True, type=pathlib.Path)
    args = parser.parse_args()
    lock = json.loads((pathlib.Path(__file__).parent / 'reference.lock').read_text())
    assert hashlib.sha256(args.archive.read_bytes()).hexdigest() == lock['source_archive']['sha256'], 'source archive digest mismatch'
    with tempfile.TemporaryDirectory(prefix='rs-keycloak-routes-') as directory:
        with tarfile.open(args.archive) as archive:
            archive.extractall(directory, filter='data')
        entries = list(pathlib.Path(directory).iterdir())
        assert len(entries) == 1 and entries[0].is_dir(), 'unexpected source archive layout'
        source_root = entries[0]
        classes = route_sources.parse(source_root)
        inventory = resolve(classes, lock['keycloak']['source_revision'], source_root)
    args.output.write_text(json.dumps(inventory, indent=2) + '\n')
    print(f'{len(inventory["operations"])} source-resolved HTTP routes; {len(inventory["unresolved"])} explicit unresolved source entries; no runtime parity claimed')


if __name__ == '__main__':
    main()
