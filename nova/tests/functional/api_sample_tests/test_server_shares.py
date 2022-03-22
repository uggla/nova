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

from nova import exception
from nova.tests import fixtures as nova_fixtures
from nova.tests.functional.api_sample_tests import test_servers
from oslo_utils.fixture import uuidsentinel
from unittest import mock


class ServerSharesBase(test_servers.ServersSampleBase):
    sample_dir = 'os-server-shares'
    microversion = '2.92'
    scenarios = [('v2_92', {'api_major_version': 'v2.1'})]

    def setUp(self):
        super(ServerSharesBase, self).setUp()
        self.useFixture(nova_fixtures.ManilaFixture())

    def _get_create_subs(self):
        return {'shareId': 'e8debdc0-447a-4376-a10a-4cd9122d7986',
                'uuid': '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}'
                '-[0-9a-f]{4}-[0-9a-f]{12}',
                }

    def create_server_ok(self,
            requested_flavor={
                'virtiofs': 'required',
                'mem_backing_file': 'required'}
            ):
        flavor = self._create_flavor(extra_spec=requested_flavor)
        server = self._create_server(networks='auto', flavor_id=flavor)
        self._stop_server(server)
        return server['id']

    def create_server_not_stopped(self):
        flavor = self._create_flavor(extra_spec={
            'virtiofs': 'required',
            'mem_backing_file': 'required'})
        server = self._create_server(networks='auto', flavor_id=flavor)
        return server['id']

    def create_server_extra_spec_not_ok(self):
        flavor = self._create_flavor(extra_spec={'fake': 'required'})
        server = self._create_server(networks='auto', flavor_id=flavor)
        self._stop_server(server)
        return server['id']

    @mock.patch('socket.gethostbyname', return_value='192.168.122.152')
    def _post_server_shares(self, mock_resolver):
        """Verify the response status and returns the UUID of the
        newly created server with shares.
        """
        uuid = self.create_server_ok()
        subs = self._get_create_subs()
        response = self._do_post('servers/%s/shares' % uuid,
                                'server-shares-create-req', subs)
        self._verify_response('server-shares-show-resp', subs, response, 201)
        return uuid


class ServerSharesJsonTest(ServerSharesBase):
    def test_server_shares_create(self):
        """Verify we can create a share mapping.
        """
        self._post_server_shares()

    @mock.patch('socket.gethostbyname', return_value='192.168.122.152')
    def test_server_shares_create_with_alternative_flavor(self, mock_resolver):
        """Verify we can create a share mapping with the alternative flavor.
        """
        uuid = self.create_server_ok(requested_flavor=
                {'virtiofs': 'required',
                    'hw:mem_page_size': 'large'}
                )
        subs = self._get_create_subs()
        response = self._do_post('servers/%s/shares' % uuid,
                                'server-shares-create-req', subs)
        self._verify_response('server-shares-show-resp',
                subs, response, 201)
        return uuid

    def test_server_shares_create_fails_if_already_created(self):
        """Verify we cannot create a share mapping already created.
        """
        uuid = self._post_server_shares()
        # Post a second time to simulate a user error.
        subs = self._get_create_subs()
        response = self._do_post('servers/%s/shares' % uuid,
                                'server-shares-create-req', subs)
        self.assertEqual(400, response.status_code)
        self.assertIn('already associated to this server', response.text)

    def test_server_shares_create_fails_instance_not_stopped(self):
        """Verify we cannot create a share if instance is not stopped.
        """
        uuid = self.create_server_not_stopped()
        subs = self._get_create_subs()
        response = self._do_post('servers/%s/shares' % uuid,
                                'server-shares-create-req', subs)
        self.assertEqual(409, response.status_code)
        self.assertIn('while it is in vm_state active', response.text)

    def test_server_shares_create_fails_extra_spec_incorrect(self):
        """Verify we cannot create a share we don't have the
        appropriate extra specs
        """
        uuid = self.create_server_extra_spec_not_ok()
        subs = self._get_create_subs()
        response = self._do_post('servers/%s/shares' % uuid,
                                'server-shares-create-req', subs)
        self.assertEqual(409, response.status_code)
        self.assertIn('missing extra specs', response.text)

    @mock.patch('nova.share.manila.API.get',
            side_effect=exception.ShareNotFound(share_id='fake_uuid')
            )
    def test_server_shares_create_fails_share_not_found(self, _):
        """Verify we can not create a share if the share does not
        exists.
        """
        uuid = self.create_server_ok()
        subs = self._get_create_subs()
        response = self._do_post('servers/%s/shares' % uuid,
                                'server-shares-create-req', subs)
        self.assertEqual(404, response.status_code)
        self.assertIn("Share fake_uuid could not be found", response.text)
        return uuid

    def test_server_shares_index(self):
        """Verify we can list shares.
        """
        uuid = self._post_server_shares()
        subs = self._get_create_subs()
        response = self._do_get('servers/%s/shares' % uuid)
        self._verify_response('server-shares-create-resp',
                subs, response, 200)

    def test_server_shares_index_unknown_uuid(self):
        """Verify we can list shares on an unknown uuid
           If nothing is found in the share_mapping table then an empty
           list is returned.
        """
        response = self._do_get('servers/%s/shares' % uuidsentinel.fake_uuid)
        self.assertEqual(200, response.status_code)
        self.assertEqual('{"shares": []}', response.text)

    def test_server_shares_show(self):
        """Verify we can show a share.
        """
        uuid = self._post_server_shares()
        subs = self._get_create_subs()
        response = self._do_get(
                'servers/%s/shares/%s' % (uuid, subs['shareId']))
        self._verify_response('server-shares-show-resp',
                subs, response, 200)

    @mock.patch('socket.gethostbyname', return_value='192.168.122.152')
    def test_server_shares_delete(self, mock_resolver):
        """Verify we can delete share.
        """
        uuid = self._post_server_shares()
        subs = self._get_create_subs()
        response = self._do_delete(
                'servers/%s/shares/%s' % (uuid, subs['shareId']))
        self.assertEqual(200, response.status_code)

    def test_server_shares_delete_fails_unknown_uuid(self):
        """Verify we have an error if we want to remove an unknown share.
        """
        uuid = self._post_server_shares()
        response = self._do_delete(
                'servers/%s/shares/%s' % (uuid, uuidsentinel.wrong_share_id))
        self.assertEqual(404, response.status_code)

    def test_server_shares_delete_fails_instance_not_stopped(self):
        """Verify we cannot remove a share if the instance is not stopped.
        """
        uuid = self._post_server()
        subs = self._get_create_subs()
        response = self._do_post('servers/%s/shares' % uuid,
                                'server-shares-create-req', subs)
        response = self._do_delete(
                'servers/%s/shares/%s' % (uuid, subs['shareId']))
        self.assertEqual(409, response.status_code)


class ServerSharesJsonAdminTest(ServerSharesBase):
    ADMIN_API = True

    @mock.patch('socket.gethostbyname', return_value='192.168.122.152')
    def _post_server_shares(self, mock_resolver):
        """Verify the response status and returns the UUID of the
        newly created server with shares.
        """
        uuid = self.create_server_ok()
        subs = self._get_create_subs()
        response = self._do_post('servers/%s/shares' % uuid,
                                'server-shares-create-req', subs)
        self._verify_response(
            'server-shares-admin-show-resp', subs, response, 201)
        return uuid

    def test_server_shares_create(self):
        """Verify we can create a share mapping.
        """
        self._post_server_shares()

    def test_server_shares_show(self):
        """Verify we can show a share as admin and thus have more
           information.
        """
        uuid = self._post_server_shares()
        subs = self._get_create_subs()
        response = self._do_get(
                'servers/%s/shares/%s' % (uuid, subs['shareId']))
        self._verify_response('server-shares-admin-show-resp',
                subs, response, 200)
