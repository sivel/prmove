#!/usr/bin/env python
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
import urlparse
import tempfile
import requests

from git import Repo, GitCommandError
from functools import wraps
from flask.ext.github import GitHub
from flask import (Flask, session, request, url_for, redirect, flash,
                   render_template, abort)


GITHUB_API_BASE = 'https://api.github.com'

DIFF_GIT_RE = re.compile(r'^(diff --git a/)([^ ]+ b/)([^ ]+)$', re.M)
STAT_RE = re.compile(r'^(\s+)([^ ]+\s+\|\s+\d+\s+[+-]+)$', re.M)
MINUS_PLUS_RE = re.compile(r'^((?:-|\+){3} [ab]/)(.+)$', re.M)


app = Flask('prmove')
app.config.from_envvar('PRMOVE_CONFIG')
github = GitHub(app)

LOG = logging.getLogger('prmove')


class Mover(object):
    def __init__(self, token, username, pr_url, close_original=False):
        self.username = username
        self.token = token
        self.pr_url = pr_url.rstrip('/')
        self.close_original = close_original

        self.urlparts = urlparse.urlparse(self.pr_url)

        self.branch_name = self.urlparts.path.split('/', 2)[-1]
        self.patch = None

        self.working_dir = tempfile.mkdtemp()
        self.clone = None

        self.original_pull_request = None

    def get_original_pull_request(self):
        url = '%s/repos%s' % (GITHUB_API_BASE, self.urlparts.path)
        url = url.replace('/pull/', '/pulls/')

        params = {
            'access_token': self.token
        }

        r = requests.get(url, params=params)
        r.raise_for_status()
        self.original_pull_request = r.json()

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
        origin_url = 'https://%s@github.com/%s/ansible.git' % (self.token,
                                                               self.username)

        try:
            self.clone = Repo.clone_from(
                origin_url,
                '%s/ansible' % self.working_dir
            )
        except GitCommandError as e:
            raise Exception('You must have a fork of ansible/ansible:'
                            '\n%s\n%s' % (e.stdout, e.stderr))

        self.clone.git.remote(
            [
                'add',
                'upstream',
                'git://github.com/ansible/ansible.git'
            ]
        )

        self.clone.git.fetch(all=True)
        self.clone.git.checkout('upstream/devel', b=self.branch_name)
        # self.clone.git.checkout('origin/prmove-test-branch',
        #                         b=self.branch_name)
        self.clone.git.am('%s/patch.patch' % self.working_dir)
        self.clone.git.push(['origin', self.branch_name])

        return self.clone

    def create_pull_request(self):
        params = {
            'access_token': self.token
        }

        data = {
            'title': self.original_pull_request['title'],
            'body': self.original_pull_request['body'],
            'head': '%s:%s' % (self.username, self.branch_name),
            'base': 'devel'
        }

        url = '%s/repos/ansible/ansible/pulls' % GITHUB_API_BASE
        # url = '%s/repos/sivel/ansible/pulls' % GITHUB_API_BASE

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

        number = self.original_pull_request['number']

        url = '%s/repos/ansible/ansible/pulls/%s' % (GITHUB_API_BASE, number)

        r = requests.post(url, data=json.dumps(data), params=params)
        r.raise_for_status()

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        try:
            shutil.rmtree(self.working_dir)
        except:
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
    if request.method == 'GET':
        return render_template('move.html')

    pr_url = request.form.get('prurl')
    close_original = request.form.get('closeorig')

    pull = None
    errors = []
    with Mover(session['token'], session['login'], pr_url,
               close_original == '1') as mover:
        try:
            mover.validate_pull_request()
        except Exception as e:
            LOG.exception('Failure validating pull request (%s): %s' %
                          (pr_url, session['login']))
            errors.append(e)

        try:
            mover.get_patch()
        except Exception as e:
            LOG.exception('Failure getting patch (%s): %s' %
                          (pr_url, session['login']))
            errors.append(e)

        try:
            mover.clone_ansible()
        except Exception as e:
            LOG.exception('Failure handling git repo (%s): %s' %
                          (pr_url, session['login']))
            errors.append(e)

        try:
            pull = mover.create_pull_request()
        except Exception as e:
            LOG.exception('Failure creating pull request (%s): %s' %
                          (pr_url, session['login']))
            errors.append(e)

        try:
            mover.close_original_pull_request()
        except Exception as e:
            LOG.exception('Failure closing orig PR (%s): %s' %
                          (pr_url, session['login']))
            errors.append(e)

    for e in errors:
        flash(e.message, 'danger')

    if pull:
        flash(
            ('Your pull request has been migrated to '
             '<a href="%(html_url)s">%(html_url)s</a>' % pull),
            'success'
        )

if __name__ == '__main__':
    app.run('0.0.0.0', 5000, debug=True)
