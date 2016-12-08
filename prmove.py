#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright 2016 Matt Martz
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import re
import json
import shutil
import logging
import urllib.parse
import tempfile
import requests

from git import Repo, GitCommandError
from functools import wraps
from flask_github import GitHub
from flask_sslify import SSLify
from flask import (Flask, Markup, session, request, url_for, redirect, flash,
                   render_template, abort)


GITHUB_API_BASE = 'https://api.github.com'

DIFF_GIT_RE = re.compile(r'^(diff --git a/)([^ ]+ b/)([^ ]+)$', re.M)
STAT_RE = re.compile(r'^(\s+)([^ ]+\s+\|\s+\d+\s+[+-]+)$', re.M)
MINUS_PLUS_RE = re.compile(r'^((?:-|\+){3} [ab]/)(.+)$', re.M)


app = Flask('prmove')
app.config.from_envvar('PRMOVE_CONFIG')
github = GitHub(app)
sslify = SSLify(app)

LOG = logging.getLogger('prmove')


class Mover(object):
    def __init__(self, token, username, pr_url, close_original=False):
        self.username = username
        self.token = token
        self.pr_url = pr_url.rstrip('/')
        self.close_original = close_original
        self.upstream_dir = app.config['UPSTREAM_DIR']
        self.upstream_account = None
        self.upstream_branch = None

        self.urlparts = urllib.parse.urlparse(self.pr_url)

        self.branch_name = self.urlparts.path.split('/', 2)[-1]
        self.patch = None

        self.working_dir = tempfile.mkdtemp()

        self.original_pull_request_url = '%s/repos%s' % (
            GITHUB_API_BASE, self.urlparts.path.replace('/pull/', '/pulls/'))

        self.original_pull_request = None

    def check_already_migrated(self):
        params = {
            'access_token': self.token
        }

        url = '%s/repos/%s/ansible/branches/%s' % (GITHUB_API_BASE, self.username, self.branch_name)

        r = requests.get(url, params=params)

        if r.status_code == 404:
            return

        if r.status_code == 200:
            raise Exception('Branch %s already exists. Has this pull request already been migrated?' %
                            self.branch_name)

        r.raise_for_status()

    def get_original_pull_request(self):
        params = {
            'access_token': self.token
        }

        r = requests.get(self.original_pull_request_url, params=params)
        r.raise_for_status()
        self.original_pull_request = r.json()
        self.mergeable_state = self.original_pull_request['mergeable_state']

        return self.original_pull_request

    def validate_pull_request(self):
        original = self.get_original_pull_request()
        if original['user']['login'] != self.username:
            raise Exception('You (%s) are not the PR owner (%s): %s' %
                            (self.username, original['user']['login'],
                             self.pr_url))

    def get_patch(self):
        r = requests.get('%s.patch' % self.pr_url)
        r.raise_for_status()
        self.patch = r.text

        self.patch = DIFF_GIT_RE.sub(
            r'\1lib/ansible/modules/\2lib/ansible/modules/\3',
            self.patch
        )
        self.patch = STAT_RE.sub(r'\1lib/ansible/modules/\2', self.patch)
        self.patch = MINUS_PLUS_RE.sub(r'\1lib/ansible/modules/\2', self.patch)

        with open('%s/patch.patch' % self.working_dir, 'w+') as f:
            f.write(self.patch)

        return self.patch

    def clone_ansible(self):
        clone_dir = '%s/ansible' % self.working_dir
        origin_url = 'https://%s@github.com/%s/ansible.git' % (self.token, self.username)

        shutil.copytree(self.upstream_dir, clone_dir, symlinks=True)

        try:
            clone = Repo(clone_dir)
        except GitCommandError as e:
            raise Exception('Failed to open clone of ansible/ansible repository:',
                            '\n%s\n%s' % (e.stdout, e.stderr)) from e

        try:
            self.upstream_account = urllib.parse.urlparse(list(clone.remote('upstream').urls)[0]).path.split('/')[1]
        except GitCommandError as e:
            raise Exception('Failed to get upstream from ansible/ansible repository:',
                            '\n%s\n%s' % (e.stdout, e.stderr)) from e

        try:
            self.upstream_branch = clone.active_branch.name
        except GitCommandError as e:
            raise Exception('Failed to get active branch from ansible/ansible repository:',
                            '\n%s\n%s' % (e.stdout, e.stderr)) from e

        try:
            clone.create_remote('origin', origin_url)
        except GitCommandError as e:
            raise Exception('Failed to add origin to clone of ansible/ansible repository:'
                            '\n%s\n%s' % (e.stdout, e.stderr)) from e

        try:
            if requests.get(origin_url).status_code != 200:
                raise Exception('You must have a fork of ansible/ansible at: %s' % origin_url)
        except GitCommandError as e:
            raise Exception('Failed to verify origin exists:'
                            '\n%s\n%s' % (e.stdout, e.stderr)) from e

        try:
            clone.git.checkout(b=self.branch_name)
        except GitCommandError as e:
            raise Exception('Failed to create new branch:'
                            '\n%s\n%s' % (e.stdout, e.stderr)) from e

        try:
            clone.git.am('%s/patch.patch' % self.working_dir, '--3way')
        except GitCommandError as e:
            raise Exception('Failed to apply patch:'
                            '\n%s\n%s' % (e.stdout, e.stderr)) from e

        try:
            clone.git.push(['origin', self.branch_name])
        except GitCommandError as e:
            raise Exception('Failed to push new branch for pull request:'
                            '\n%s\n%s' % (e.stdout, e.stderr)) from e

    def create_pull_request(self):
        params = {
            'access_token': self.token
        }

        data = {
            'title': self.original_pull_request['title'],
            'body': self.original_pull_request['body'],
            'head': '%s:%s' % (self.username, self.branch_name),
            'base': self.upstream_branch,
        }

        url = '%s/repos/%s/ansible/pulls' % (GITHUB_API_BASE, self.upstream_account)

        r = requests.post(url, data=json.dumps(data), params=params)
        r.raise_for_status()

        pull = r.json()

        comment = {
            'body': 'Migrated from %s' % self.original_pull_request['html_url']
        }

        r = requests.post(pull['comments_url'], data=json.dumps(comment),
                          params=params)
        r.raise_for_status()

        return pull

    def close_original_pull_request(self):
        if not self.close_original:
            return None

        params = {
            'access_token': self.token
        }

        data = {
            'state': 'closed'
        }

        r = requests.post(self.original_pull_request_url, data=json.dumps(data), params=params)
        r.raise_for_status()

    def __enter__(self):
        return self

    def __exit__(self, ex_type, value, traceback):
        try:
            shutil.rmtree(self.working_dir)
        except OSError:
            LOG.exception('Failure removing working dir: %s' %
                          self.working_dir)


@github.access_token_getter
def token_getter():
    return session.get('token')


def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not session.get('token'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapped


@app.before_first_request
def logger():
    app.logger.addHandler(logging.StreamHandler())
    app.logger.setLevel(logging.INFO)
    app.logger.handlers.extend(logging.getLogger("gunicorn.error").handlers)


@app.errorhandler(500)
def internal_server_error(e):
    app.logger.exception(e)
    return abort(500)


@app.route('/')
def index():
    if session.get('token'):
        return redirect('/move')

    return render_template('index.html')


@app.route('/login')
def login():
    return github.authorize(scope='user:email public_repo')


@app.route('/login/authorized')
@github.authorized_handler
def authorized(oauth_token):
    if oauth_token is None:
        flash('Authorization failed.', 'danger')
        return redirect('index')

    session['token'] = oauth_token
    session.update(github.get('user'))
    return redirect(url_for('move'))


@app.route('/move', methods=['GET', 'POST'])
def move():
    if request.method == 'POST':
        try:
            move_post()
        except MarkupException as e:
            LOG.exception(e)
            flash(Markup(e.markup), 'danger')
        except Exception as e:
            LOG.exception(e)
            flash(e, 'danger')

    return render_template('move.html')


def move_post():
    pr_url = request.form.get('prurl')
    close_original = request.form.get('closeorig')

    with Mover(session['token'], session['login'], pr_url, close_original == '1') as mover:
        mover.check_already_migrated()

        try:
            mover.validate_pull_request()
        except Exception as e:
            raise Exception('Failure validating pull request (%s) for %s: %s' %
                            (pr_url, session['login'], e)) from e

        if mover.mergeable_state == 'dirty':
            raise MarkupException('Please rebase your branch and update your PR before migrating. '
                                  'Tests will fail for your old PR after rebasing. '
                                  'This is expected and can be ignored. '
                                  'For more information please consult the <a href="'
                                  'http://docs.ansible.com/ansible/dev_guide/repomerge.html#move-issues-and-prs-to-new-repo'
                                  '">repo merge</a> documentation. ')

        try:
            mover.get_patch()
        except Exception as e:
            raise Exception('Failure getting patch (%s) for %s: %s' %
                            (pr_url, session['login'], e)) from e

        try:
            mover.clone_ansible()
        except Exception as e:
            raise Exception('Failure handling git repository (%s) for %s: %s' %
                            (pr_url, session['login'], e)) from e

        try:
            pull = mover.create_pull_request()
        except Exception as e:
            raise Exception('Failure creating pull request (%s) for %s: %s' %
                            (pr_url, session['login'], e)) from e

        flash(
            Markup('Your pull request has been migrated to '
                   '<a href="%(html_url)s">%(html_url)s</a>' % pull),
            'success'
        )

        try:
            mover.close_original_pull_request()
        except Exception as e:
            raise Exception('Failure closing original pull request (%s) for %s: %s' %
                            (pr_url, session['login'], e)) from e


class MarkupException(Exception):
    def __init__(self, markup):
        super(MarkupException, self).__init__(markup)
        self.markup = markup


if __name__ == '__main__':
    app.run('0.0.0.0', 5000, debug=True)
