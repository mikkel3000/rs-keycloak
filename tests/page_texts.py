"""Reduces a login page to the texts a user reads, so a reference page and
this server's page compare even though their markup differs.

A page becomes its title, its heading (`#kc-page-title`), its labels,
submit buttons and login-actions links as texts in page order, its list
items, its messages (`.kc-feedback-text` or `role` alert or status, outside
field errors), its field errors (`#input-error-<field>`) and its language
choice: the reference's `#login-select-toggle` options or the links of
`#kc-locale`, each as label, selected, login-actions step and kc_locale.
Text inside `aria-hidden` elements is left out, whitespace collapses, and
empty texts are dropped.
"""
import html.parser
import urllib.parse

VOID = {'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'source', 'track', 'wbr'}


def target(href):
    """A link's login-actions step and its kc_locale value."""
    parts = urllib.parse.urlsplit(href)
    path = parts.path.split('/login-actions/', 1)
    step = path[1].split('/', 1)[0] if len(path) == 2 else parts.path.rsplit('/', 1)[-1]
    locale = urllib.parse.parse_qs(parts.query).get('kc_locale', [None])[0]
    return step, locale


class _Reader(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        # Open elements: (tag, attributes, collected text).
        self.stack = []
        self.texts = {'title': None, 'heading': None, 'labels': [], 'buttons': [], 'links': [], 'items': [], 'messages': [], 'errors': {}, 'languages': None}

    def hidden(self):
        return any(attrs.get('aria-hidden') == 'true' for _, attrs, _ in self.stack)

    def inside(self, test):
        return any(test(tag, attrs) for tag, attrs, _ in self.stack)

    def handle_starttag(self, tag, attrs):
        attrs = {name: value or '' for name, value in attrs}
        if tag == 'select' and attrs.get('id') == 'login-select-toggle' or tag == 'nav' and attrs.get('id') == 'kc-locale':
            self.texts['languages'] = {'label': attrs.get('aria-label'), 'options': []}
        if tag == 'input' and attrs.get('type') == 'submit':
            self.add('buttons', attrs.get('value', ''))
        if tag not in VOID:
            self.stack.append((tag, attrs, []))

    def handle_data(self, data):
        if not self.hidden():
            for _, _, collected in self.stack:
                collected.append(data)

    def handle_endtag(self, tag):
        if tag in VOID or not any(open_tag == tag for open_tag, _, _ in self.stack):
            return
        while self.stack:
            open_tag, attrs, collected = self.stack.pop()
            if open_tag == tag:
                self.finish(tag, attrs, ' '.join(''.join(collected).split()))
                return

    def add(self, kind, text):
        text = ' '.join(text.split())
        if text:
            self.texts[kind].append(text)

    def finish(self, tag, attrs, text):
        texts = self.texts
        element_id = attrs.get('id', '')
        field_error = element_id.startswith('input-error-') and not element_id.startswith('input-error-container-')
        in_languages = self.inside(lambda t, a: a.get('id') in ('login-select-toggle', 'kc-locale'))
        in_error = self.inside(lambda t, a: a.get('id', '').startswith('input-error-'))
        if tag == 'title':
            texts['title'] = text
        elif element_id == 'kc-page-title':
            texts['heading'] = text
        elif tag == 'label':
            self.add('labels', text)
        elif tag == 'button' and attrs.get('type', 'submit') == 'submit':
            self.add('buttons', text)
        elif tag in ('option', 'a') and in_languages:
            step, locale = target(attrs.get('value' if tag == 'option' else 'href', ''))
            selected = 'selected' in attrs if tag == 'option' else attrs.get('aria-current') == 'true'
            texts['languages']['options'].append([text, selected, step, locale])
        elif tag == 'a' and '/login-actions/' in attrs.get('href', ''):
            self.add('links', text)
        elif tag == 'li' and not in_languages:
            self.add('items', text)
        if field_error and text:
            texts['errors'][element_id[len('input-error-'):]] = text
        elif not field_error and not in_error and ('kc-feedback-text' in attrs.get('class', '').split() or attrs.get('role') in ('alert', 'status')):
            self.add('messages', text)


def page_texts(body):
    """The texts of an HTML page given as bytes or text."""
    reader = _Reader()
    reader.feed(body.decode() if isinstance(body, bytes) else body)
    reader.close()
    return reader.texts
