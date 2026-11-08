#!/usr/bin/env python3
"""Capture pinned Keycloak's realm localization texts in emails.

Covers FreeMarkerEmailTemplateProvider: a mail's locale is the user's
(session.getContext().resolveLocale(user)), and its subject and bodies
read the email theme's messages with the realm's localization texts of
that locale over them (Theme.getEnhancedMessages), for the
forgot-password, execute-actions and verify-email mails; with
internationalization off, mails are English and read the English texts.
"""
import html
import re

import oauth
from recording import Recording
from smtp_sink import SmtpSink  # noqa: E402

TEXTS = {
    'en': {
        'passwordResetSubject': 'Realm reset EN',
        'passwordResetBody': 'Realm body EN for {2}: {0} within {3}.',
        'passwordResetBodyHtml': '<p>Realm HTML EN for {2}: <a href="{0}">reset</a></p>',
        'executeActionsSubject': 'Realm actions EN',
        'emailVerificationSubject': 'Realm verify EN',
        'requiredAction.UPDATE_PASSWORD': 'Realm password action',
    },
    'de': {'passwordResetSubject': 'Realm Betreff DE'},
}
REALMS = {
    'texts': {'internationalizationEnabled': True, 'supportedLocales': ['en', 'de'], 'defaultLocale': 'en', 'localizationTexts': TEXTS},
    'plain': {'internationalizationEnabled': True, 'supportedLocales': ['en', 'de'], 'defaultLocale': 'en'},
    'no-i18n': {'localizationTexts': TEXTS},
}
LINK = re.compile(r'https?://[^\s"<>]*login-actions/action-token\?[^\s"<>]*')


def summary(mail):
    message = mail['message']
    text = message.get_body(('plain',)).get_content()
    markup = message.get_body(('html',)).get_content()
    words = ' '.join(html.unescape(re.sub(r'<[^>]+>', ' ', markup)).split())
    return {
        'to': mail['to'],
        'subject': str(message['subject']),
        'text': LINK.sub('{link}', text).strip(),
        'html_text': LINK.sub('{link}', words),
        'html_links': len(LINK.findall(markup)),
    }


def run(base, bootstrap_secret, record=False):
    rec =Recording(base, bootstrap_secret, REALMS)
    observations = {}
    with SmtpSink() as sink:
        smtp = {'host': '127.0.0.1', 'port': str(sink.port), 'from': 'noreply@example.invalid'}
        rec.create_realms({key: extra | {'resetPasswordAllowed': True, 'smtpServer': smtp} for key, extra in REALMS.items()})

        def mailed(send):
            before = len(sink.received)
            result = send()
            mails = sink.wait(before + 1, timeout=5)[before:]
            return {'result': result, 'mails': [summary(mail) for mail in mails]}

        def forgot(key, username):
            browser = rec.browser(key)
            page = browser.authorize()
            link = re.search(r'href="([^"]*/login-actions/reset-credentials[^"]*)"', page[2].decode()).group(1)
            form = browser.visit(link)
            return browser.shown(browser.submit(form, {'username': username}))['status']

        try:
            for key in REALMS:
                users = {'en': rec.new_user(key, 'en-user'), 'de': rec.new_user(key, 'de-user', {'attributes': {'locale': ['de']}})}
                for locale, user in users.items():
                    username = locale + '-user'
                    observations[f'reset/{key}/{locale}'] = mailed(lambda: forgot(key, username))
                    observations[f'execute-actions/{key}/{locale}'] = mailed(lambda: rec.admin_call(key, f'/users/{user}/execute-actions-email', 'PUT', ['UPDATE_PASSWORD'])[0])
                    observations[f'verify-email/{key}/{locale}'] = mailed(lambda: rec.admin_call(key, f'/users/{user}/send-verify-email', 'PUT')[0])
            # A text changed after the realm was made is read at sending.
            status = rec.call('PUT', f'/admin/realms/{rec.names["plain"]}/localization/de/passwordResetSubject', {'Authorization': 'Bearer ' + rec.admin, 'Content-Type': 'text/plain'}, 'Neuer Betreff {0}'.encode())[0]
            observations['reset/plain/de/added-text'] = {'put': status} | mailed(lambda: forgot('plain', 'de-user'))
        finally:
            rec.delete_realms()
    return rec.finish(observations, 'email-texts-observations.json', record,
                      'Realm localization texts in the forgot-password, execute-actions and verify-email mails: the user locale, realm texts over the email theme messages for subjects and bodies, a realm without texts, internationalization off, and a text added later.',
                      'The base URL and realm names are replaced with placeholders; mails keep their recipients, subject, text part and the HTML part reduced to its words, with action links as {link}, and the number of links in the HTML part.')


if __name__ == '__main__':
    try:
        oauth.main(run)
    except Exception as error:
        raise SystemExit(f'reference email texts check failed: {error}') from None
