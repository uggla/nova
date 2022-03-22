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

from nova.api.openstack.compute import server_shares
from nova.compute import vm_states
from nova import context
from nova import objects
from nova import test
from nova.tests.unit.api.openstack import fakes
from nova.tests.unit import fake_instance
from oslo_utils import timeutils

from nova.tests import fixtures as nova_fixtures


UUID = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
NON_EXISTING_UUID = '123'


def return_server(compute_api, context, instance_id, expected_attrs=None):
    return fake_instance.fake_instance_obj(context, vm_state=vm_states.ACTIVE)


def return_invalid_server(compute_api, context, instance_id,
                          expected_attrs=None):
    return fake_instance.fake_instance_obj(context,
                                           vm_state=vm_states.BUILDING)


class ServerSharesTest(test.TestCase):
    wsgi_api_version = '2.92'

    def setUp(self):
        super(ServerSharesTest, self).setUp()
        self.controller = server_shares.ServerSharesController()
        inst_map = objects.InstanceMapping(
            project_id=fakes.FAKE_PROJECT_ID,
            user_id=fakes.FAKE_USER_ID,
            cell_mapping=objects.CellMappingList.get_all(
                context.get_admin_context())[1])
        self.stub_out('nova.objects.InstanceMapping.get_by_instance_uuid',
                      lambda s, c, u: inst_map)
        self.req = fakes.HTTPRequest.blank(
                '/servers/%s/shares' % (UUID),
                use_admin_context=False, version=self.wsgi_api_version)
        self.useFixture(nova_fixtures.ManilaFixture())

    def fake_get_instance(self):
        ctxt = self.req.environ['nova.context']
        return fake_instance.fake_instance_obj(
                ctxt,
                uuid=fakes.FAKE_UUID,
                flavor = objects.Flavor(id=1, name='flavor1',
                    memory_mb=256, vcpus=1,
                    root_gb=1, ephemeral_gb=1,
                    flavorid='1',
                    swap=0, rxtx_factor=1.0,
                    vcpu_weight=1,
                    disabled=False,
                    is_public=True,
                    extra_specs={
                        'virtiofs': 'required',
                        'mem_backing_file': 'required'
                        },
                    projects=[]),
                vm_state=vm_states.STOPPED)

    @mock.patch('nova.db.main.api.share_mapping_get_by_instance_uuid')
    @mock.patch('nova.api.openstack.common.get_instance')
    def test_index(self, mock_get_instance, mock_db_get_shares,):
        NOW = timeutils.utcnow().replace(microsecond=0)
        instance = self.fake_get_instance()
        mock_get_instance.return_value = instance

        fake_db_shares = [
            {
                'created_at': NOW,
                'updated_at': None,
                'deleted_at': None,
                'deleted': False,
                "id": 1,
                "uuid": "33a8e0cb-5f82-409a-b310-89c41f8bf023",
                "instance_uuid": "48c16a1a-183f-4052-9dac-0e4fc1e498ae",
                "share_id": "48c16a1a-183f-4052-9dac-0e4fc1e498ad",
                "status": "active",
                "tag": "foo",
                "export_location": "10.0.0.50:/mnt/foo",
                "share_proto": "NFS",
            },
            {
                'created_at': NOW,
                'updated_at': None,
                'deleted_at': None,
                'deleted': False,
                "id": 2,
                "uuid": "33a8e0cb-5f82-409a-b310-89c41f8bf024",
                "instance_uuid": "48c16a1a-183f-4052-9dac-0e4fc1e498ae",
                "share_id": "e8debdc0-447a-4376-a10a-4cd9122d7986",
                "status": "active",
                "tag": "bar",
                "export_location": "10.0.0.50:/mnt/bar",
                "share_proto": "NFS",
            }
        ]

        fake_shares = {
            "shares": [
                {
                    "shareId": "48c16a1a-183f-4052-9dac-0e4fc1e498ad",
                    "status": "active",
                    "tag": "foo",
                },
                {
                    "shareId": "e8debdc0-447a-4376-a10a-4cd9122d7986",
                    "status": "active",
                    "tag": "bar",
                }
            ]
        }

        mock_db_get_shares.return_value = fake_db_shares
        output = self.controller.index(self.req, instance.uuid)
        mock_db_get_shares.assert_called_once_with(mock.ANY, instance.uuid)
        self.assertEqual(output, fake_shares)

    @mock.patch('socket.gethostbyname', return_value='192.168.122.152')
    @mock.patch('nova.db.main.api.share_mapping_update')
    @mock.patch('nova.api.openstack.common.get_instance')
    def test_create(self,
            mock_get_instance,
            mock_db_update_share,
            mock_resolver):
        NOW = timeutils.utcnow().replace(microsecond=0)
        instance = self.fake_get_instance()

        mock_get_instance.return_value = instance

        fake_db_share = {
            'created_at': NOW,
            'updated_at': None,
            'deleted_at': None,
            'deleted': False,
            "id": 1,
            "uuid": "7ddcf3ae-82d4-4f93-996a-2b6cbcb42c2b",
            "instance_uuid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "share_id": "e8debdc0-447a-4376-a10a-4cd9122d7986",
            "status": "inactive",
            "tag": "e8debdc0-447a-4376-a10a-4cd9122d7986",
            "export_location": "10.0.0.50:/mnt/foo",
            "share_proto": "NFS",
        }

        body = {
            'share': {
                'shareId': 'e8debdc0-447a-4376-a10a-4cd9122d7986'
            }}

        mock_db_update_share.return_value = fake_db_share
        self.controller.create(self.req, instance.uuid, body=body)
        mock_db_update_share.assert_called_once_with(
            mock.ANY,
            mock.ANY,
            instance.uuid,
            fake_db_share['share_id'],
            'inactive',
            fake_db_share['tag'],
            fake_db_share['export_location'],
            fake_db_share['share_proto'],
        )

    @mock.patch('socket.gethostbyname', return_value='192.168.122.152')
    @mock.patch('nova.db.main.api.'
            'share_mapping_delete_by_instance_uuid_and_share_id')
    @mock.patch('nova.db.main.api.'
            'share_mapping_get_by_instance_uuid_and_share_id')
    @mock.patch('nova.api.openstack.common.get_instance')
    def test_delete(self,
            mock_get_instance,
            mock_db_get_shares,
            mock_db_delete_share,
            mock_resolver):
        NOW = timeutils.utcnow().replace(microsecond=0)
        instance = self.fake_get_instance()

        mock_get_instance.return_value = instance

        fake_db_share = {
            'created_at': NOW,
            'updated_at': None,
            'deleted_at': None,
            'deleted': False,
            "id": 1,
            "uuid": "33a8e0cb-5f82-409a-b310-89c41f8bf023",
            "instance_uuid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "share_id": "e8debdc0-447a-4376-a10a-4cd9122d7986",
            "status": "inactive",
            "tag": "e8debdc0-447a-4376-a10a-4cd9122d7986",
            "export_location": "10.0.0.50:/mnt/foo",
            "share_proto": "NFS",
        }

        mock_db_get_shares.return_value = fake_db_share
        self.controller.delete(
                self.req, instance.uuid, fake_db_share['share_id'])
        mock_db_delete_share.assert_called_once_with(
            mock.ANY, instance.uuid,
            fake_db_share['share_id'],
        )
