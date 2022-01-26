# Copyright 2012 Nebula, Inc.
# Copyright 2013 IBM Corp.
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

import mock
import nova.conf
from nova import objects
from nova.tests.functional.api_sample_tests import test_servers
from oslo_utils.fixture import uuidsentinel

CONF = nova.conf.CONF


class ShelveJsonTest(test_servers.ServersSampleBase):
    # The 'os_compute_api:os-shelve:shelve_offload' policy is admin-only
    ADMIN_API = True
    sample_dir = "os-shelve"

    def setUp(self):
        super(ShelveJsonTest, self).setUp()
        # Don't offload instance, so we can test the offload call.
        CONF.set_override('shelved_offload_time', -1)

    def _test_server_action(self, uuid, template, action):
        response = self._do_post('servers/%s/action' % uuid,
                                 template, {'action': action})
        self.assertEqual(202, response.status_code)
        self.assertEqual("", response.text)

    def test_shelve(self):
        uuid = self._post_server()
        self._test_server_action(uuid, 'os-shelve', 'shelve')

    def test_shelve_offload(self):
        uuid = self._post_server()
        self._test_server_action(uuid, 'os-shelve', 'shelve')
        self._test_server_action(uuid, 'os-shelve-offload', 'shelveOffload')

    def test_unshelve(self):
        uuid = self._post_server()
        self._test_server_action(uuid, 'os-shelve', 'shelve')
        self._test_server_action(uuid, 'os-unshelve', 'unshelve')


class UnshelveJson277Test(test_servers.ServersSampleBase):
    sample_dir = "os-shelve"
    microversion = '2.77'
    scenarios = [('v2_77', {'api_major_version': 'v2.1'})]

    def _test_server_action(self, uuid, template, action, subs=None):
        subs = subs or {}
        subs.update({'action': action})
        response = self._do_post('servers/%s/action' % uuid,
                                 template, subs)
        self.assertEqual(202, response.status_code)
        self.assertEqual("", response.text)

    def test_unshelve_with_az(self):
        uuid = self._post_server()
        self._test_server_action(uuid, 'os-shelve', 'shelve')
        self._test_server_action(uuid, 'os-unshelve', 'unshelve',
                                 subs={"availability_zone": "us-west"})

    def test_unshelve_no_az(self):
        uuid = self._post_server()
        self._test_server_action(uuid, 'os-shelve', 'shelve')
        self._test_server_action(uuid, 'os-unshelve-null', 'unshelve')


class UnshelveJson291Test(test_servers.ServersSampleBase):
    ADMIN_API = True
    sample_dir = "os-shelve"
    microversion = '2.91'
    scenarios = [('v2_91', {'api_major_version': 'v2.1'})]

    def _test_server_action(self, uuid, template, action, subs=None):
        subs = subs or {}
        subs.update({'action': action})
        response = self._do_post('servers/%s/action' % uuid,
                                 template, subs)
        self.assertEqual(202, response.status_code)
        self.assertEqual('', response.text)

    def _test_server_action_invalid(self, uuid, template, action, subs=None):
        subs = subs or {}
        subs.update({'action': action})
        response = self._do_post('servers/%s/action' % uuid,
                                 template, subs)
        self.assertEqual(400, response.status_code)
        self.assertIn(
            'The requested host \\"server01\\" is not found', response.text)

    def test_unshelve_with_az(self):
        uuid = self._post_server()
        self._test_server_action(uuid, 'os-shelve', 'shelve')
        self._test_server_action(uuid, 'os-unshelve', 'unshelve',
                                 subs={"availability_zone": "us-west"})

    def test_unshelve_no_az(self):
        uuid = self._post_server()
        self._test_server_action(uuid, 'os-shelve', 'shelve')
        self._test_server_action(uuid, 'os-unshelve-null', 'unshelve')

    def test_unshelve_with_non_valid_dh(self):
        """Ensure an exception rise if destination_host is invalid and
        a http 400 error
        """
        uuid = self._post_server()
        self._test_server_action(uuid, 'os-shelve', 'shelve')
        self._test_server_action_invalid(uuid, 'os-unshelve-host', 'unshelve',
                                 subs={'destination_host': 'server01'})

    @mock.patch('nova.objects.ComputeNodeList.get_all_by_host')
    def test_unshelve_with_valid_dh(self, compute_node_get_all_by_host):
        """Ensure we can unshelve to a destination_host
        """
        uuid = self._post_server()
        self._test_server_action(uuid, 'os-shelve', 'shelve')
        fake_computes = objects.ComputeNodeList(
            objects=[objects.ComputeNode(host='server01',
                                         uuid=uuidsentinel.host1,
                                         hypervisor_hostname='server01')])
        compute_node_get_all_by_host.return_value = fake_computes
        self._test_server_action(uuid, 'os-unshelve-host', 'unshelve',
                                 subs={'destination_host': 'server01'})


class UnshelveJson291NonAdminTest(test_servers.ServersSampleBase):
    # Use non admin api credentials.
    ADMIN_API = False
    sample_dir = "os-shelve"
    microversion = '2.91'
    scenarios = [('v2_91', {'api_major_version': 'v2.1'})]

    def _test_server_action_invalid(self, uuid, template, action, subs=None):
        subs = subs or {}
        subs.update({'action': action})
        response = self._do_post('servers/%s/action' % uuid,
                                 template, subs)
        self.assertEqual(403, response.status_code)
        self.assertIn(
            "Policy doesn\'t allow os_compute_api:os-shelve:unshelve_to_host" +
            " to be performed.", response.text)

    def _test_server_action(self, uuid, template, action, subs=None):
        subs = subs or {}
        subs.update({'action': action})
        response = self._do_post('servers/%s/action' % uuid,
                                 template, subs)
        self.assertEqual(202, response.status_code)
        self.assertEqual('', response.text)

    def test_unshelve_with_non_valid_dh(self):
        """Ensure an exception rise if user is not admin.
        a http 403 error
        """
        uuid = self._post_server()
        self._test_server_action(uuid, 'os-shelve', 'shelve')
        self._test_server_action_invalid(uuid, 'os-unshelve-host', 'unshelve',
                                 subs={'destination_host': 'server01'})
