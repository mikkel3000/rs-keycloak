#!/usr/bin/env python3
"""Read JAX-RS Java syntax with tree-sitter; never load or execute Java code."""
import json
import pathlib
import re
from tree_sitter import Language, Parser
import tree_sitter_java


def walk(node):
    yield node
    for child in node.named_children:
        yield from walk(child)


def text(node):
    return node.text.decode() if node else ''


def annotations(node):
    modifiers = next((n for n in node.named_children if n.type == 'modifiers'), None)
    result = {}
    if modifiers:
        for annotation in modifiers.named_children:
            if annotation.type not in ('annotation', 'marker_annotation'):
                continue
            name = text(annotation.child_by_field_name('name')).rsplit('.', 1)[-1]
            arguments = annotation.child_by_field_name('arguments')
            values = arguments.named_children if arguments else []
            if len(values) == 1 and values[0].type == 'string_literal':
                result[name] = json.loads(text(values[0]))
            else:
                result[name] = {'expression': text(arguments)} if arguments else True
    return result


def parse(root):
    parser = Parser(Language(tree_sitter_java.language()))
    classes = {}
    for path in sorted(root.rglob('*.java')):
        if '/src/main/' not in str(path) or any(part in path.parts for part in ['integration', 'test-framework', 'testsuite', 'examples', 'tests', 'operator']):
            continue
        source = path.read_bytes()
        tree = parser.parse(source)
        if tree.root_node.has_error:
            raise ValueError(f'Java syntax parse failure: {path.relative_to(root)}')
        package = next((re.sub(r'^package\s+|;$', '', text(n)) for n in tree.root_node.named_children if n.type == 'package_declaration'), '')
        imports = [re.sub(r'^import\s+(?:static\s+)?|;$', '', text(n)) for n in tree.root_node.named_children if n.type == 'import_declaration']
        for node in walk(tree.root_node):
            if node.type not in ('class_declaration', 'interface_declaration'):
                continue
            name = text(node.child_by_field_name('name'))
            parents, parent = [], node.parent
            while parent:
                if parent.type in ('class_declaration', 'interface_declaration'):
                    parents.insert(0, text(parent.child_by_field_name('name')))
                parent = parent.parent
            full = '.'.join([package] + parents + [name])
            extends = node.child_by_field_name('superclass')
            interfaces = node.child_by_field_name('interfaces') or next((n for n in node.named_children if n.type == 'extends_interfaces'), None)
            bases = []
            if extends:
                bases += [text(n) for n in extends.named_children]
            if interfaces:
                bases += [text(n) for n in walk(interfaces) if n.type in ('type_identifier', 'scoped_type_identifier') and n.parent.type == 'type_list']
            methods = []
            constants = {}
            body = node.child_by_field_name('body')
            for field in body.named_children:
                if field.type in ('field_declaration', 'constant_declaration'):
                    for variable in field.named_children:
                        if variable.type == 'variable_declarator':
                            constants[text(variable.child_by_field_name('name'))] = text(variable.child_by_field_name('value'))
            for method in body.named_children:
                if method.type != 'method_declaration':
                    continue
                method_body = method.child_by_field_name('body')
                returns = []
                if method_body:
                    for returned in walk(method_body):
                        if returned.type != 'return_statement' or not returned.named_children:
                            continue
                        value = returned.named_children[0]
                        if value.type == 'object_creation_expression':
                            returns.append({'new': text(value.child_by_field_name('type'))})
                        elif value.type == 'method_invocation':
                            returns.append({'call': text(value.child_by_field_name('name'))})
                        elif value.type in ('string_literal', 'identifier', 'field_access', 'this'):
                            returns.append({'value': text(value)})
                parameters = method.child_by_field_name('parameters')
                methods.append({'name': text(method.child_by_field_name('name')), 'return_type': text(method.child_by_field_name('type')), 'annotations': annotations(method), 'parameters': [text(n.child_by_field_name('type')) for n in parameters.named_children], 'line': method.start_point.row + 1, 'returns': returns})
            classes[full] = {'class': full, 'source': str(path.relative_to(root)), 'annotations': annotations(node), 'bases': bases, 'imports': imports, 'constants': constants, 'methods': methods}
    return classes
