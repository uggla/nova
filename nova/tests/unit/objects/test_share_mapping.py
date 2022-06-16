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

from copy import deepcopy
import mock
from nova.db.main import api as db
from nova import exception
from nova import objects
from nova.objects import share_mapping as sm
from nova.tests.unit.objects import test_objects
from oslo_utils.fixture import uuidsentinel as uuids
from oslo_utils import timeutils

NOW = timeutils.utcnow().replace(microsecond=0)

fake_share_mapping = {
    'created_at': NOW,
    'updated_at': None,
    # 'deleted_at': None,
    # 'deleted': False,
    'id': 1,
    'uuid': uuids.share_mapping,
    'instance_uuid': uuids.instance,
    'share_id': uuids.share,
    'status': 'inactive',
    'tag': 'fake_tag',
    'export_location': '192.168.122.152:/manila/share',
    'share_proto': 'NFS',
    }

fake_share_mapping_attached = deepcopy(fake_share_mapping)
fake_share_mapping_attached['status'] = 'active'


class _TestShareMapping(object):
    @mock.patch(
        'nova.db.main.api.share_mapping_update',
        return_value=fake_share_mapping)
    def test_save(self, mock_upd):
        share_mapping = objects.ShareMapping(self.context)
        share_mapping.uuid = uuids.share_mapping
        share_mapping.instance_uuid = uuids.instance
        share_mapping.share_id = uuids.share
        share_mapping.status = 'inactive'
        share_mapping.tag = 'fake_tag'
        share_mapping.export_location = '192.168.122.152:/manila/share'
        share_mapping.share_proto = 'NFS'
        share_mapping.save()
        mock_upd.assert_called_once_with(
            self.context,
            uuids.share_mapping,
            uuids.instance,
            uuids.share,
            'inactive',
            'fake_tag',
            '192.168.122.152:/manila/share',
            'NFS'
        )
        self.compare_obj(share_mapping, fake_share_mapping,
                allow_missing=['deleted', 'deleted_at'])

    def test_get_share_host_provider(self):
        share_mapping = objects.ShareMapping(self.context)
        share_mapping.uuid = uuids.share_mapping
        share_mapping.instance_uuid = uuids.instance
        share_mapping.share_id = uuids.share
        share_mapping.status = 'inactive'
        share_mapping.tag = 'fake_tag'
        share_mapping.export_location = '192.168.122.152:/manila/share'
        share_mapping.share_proto = 'NFS'
        share_host_provider = share_mapping.get_share_host_provider()
        self.assertEqual(share_host_provider, '192.168.122.152')

    def test_get_share_host_provider_not_defined(self):
        share_mapping = objects.ShareMapping(self.context)
        share_mapping.uuid = uuids.share_mapping
        share_mapping.instance_uuid = uuids.instance
        share_mapping.share_id = uuids.share
        share_mapping.status = 'inactive'
        share_mapping.tag = 'fake_tag'
        share_mapping.export_location = ''
        share_mapping.share_proto = 'NFS'
        share_host_provider = share_mapping.get_share_host_provider()
        self.assertIsNone(share_host_provider)

    @mock.patch(
        'nova.db.main.api.share_mapping_update',
        return_value=fake_share_mapping_attached)
    def test_attach(self, mock_upd):
        share_mapping = objects.ShareMapping(self.context)
        share_mapping.uuid = uuids.share_mapping
        share_mapping.instance_uuid = uuids.instance
        share_mapping.share_id = uuids.share
        share_mapping.status = 'inactive'
        share_mapping.tag = 'fake_tag'
        share_mapping.export_location = '192.168.122.152:/manila/share'
        share_mapping.share_proto = 'NFS'
        share_mapping.attach('inactive')
        mock_upd.assert_called_once_with(
            self.context,
            uuids.share_mapping,
            uuids.instance,
            uuids.share,
            'inactive',
            'fake_tag',
            '192.168.122.152:/manila/share',
            'NFS'
        )
        self.compare_obj(share_mapping, fake_share_mapping_attached,
                allow_missing=['deleted', 'deleted_at'])

    @mock.patch(
        'nova.db.main.api.share_mapping_update',
        return_value=fake_share_mapping_attached)
    def test_attach_attaching_status(self, mock_upd):
        share_mapping = objects.ShareMapping(self.context)
        share_mapping.uuid = uuids.share_mapping
        share_mapping.instance_uuid = uuids.instance
        share_mapping.share_id = uuids.share
        share_mapping.status = 'inactive'
        share_mapping.tag = 'fake_tag'
        share_mapping.export_location = '192.168.122.152:/manila/share'
        share_mapping.share_proto = 'NFS'
        share_mapping.attach('inactive')
        mock_upd.assert_called_once_with(
            self.context,
            uuids.share_mapping,
            uuids.instance,
            uuids.share,
            'inactive',
            'fake_tag',

            '192.168.122.152:/manila/share',
            'NFS'
        )
        self.compare_obj(share_mapping, fake_share_mapping_attached,
                allow_missing=['deleted', 'deleted_at'])

    @mock.patch(
        'nova.db.main.api.share_mapping_delete_by_instance_uuid_and_share_id')
    def test_detach(self, mock_del):
        share_mapping = objects.ShareMapping(self.context)
        share_mapping.uuid = uuids.share_mapping
        share_mapping.instance_uuid = uuids.instance
        share_mapping.share_id = uuids.share
        share_mapping.status = 'inactive'
        share_mapping.tag = 'fake_tag'
        share_mapping.export_location = '192.168.122.152:/manila/share'
        share_mapping.share_proto = 'NFS'
        share_mapping.detach()
        mock_del.assert_called_once_with(
            self.context, uuids.instance, uuids.share)

    @mock.patch(
        'nova.db.main.api.share_mapping_get_by_instance_uuid_and_share_id',
        return_value=fake_share_mapping)
    def test_get_by_instance_uuid_and_share_id(self, mock_get):
        share_mapping = sm.ShareMapping.get_by_instance_uuid_and_share_id(
                self.context,
                uuids.instance,
                uuids.share)
        mock_get.assert_called_once_with(
            self.context, uuids.instance, uuids.share)
        self.compare_obj(share_mapping, fake_share_mapping,
                allow_missing=['deleted', 'deleted_at'])

    @mock.patch(
        'nova.db.main.api.share_mapping_get_by_instance_uuid_and_share_id',
        return_value=None)
    def test_get_by_instance_uuid_and_share_id_not_found(self, mock_get):
        self.assertRaises(exception.ShareNotFound,
                sm.ShareMapping.get_by_instance_uuid_and_share_id,
                self.context,
                uuids.instance,
                uuids.share)
        mock_get.assert_called_once_with(
            self.context, uuids.instance, uuids.share)


class _TestShareMappingList(object):
    def test_get_by_instance_uuid(self):
        with mock.patch.object(
            db, 'share_mapping_get_by_instance_uuid') as get:
            get.return_value = [fake_share_mapping]
            share_mappings = sm.ShareMappingList.get_by_instance_uuid(
            self.context, uuids.instance)

            self.assertEqual(1, len(share_mappings))
            self.assertIsInstance(share_mappings[0], sm.ShareMapping)

    def test_get_by_share_id(self):
        with mock.patch.object(
            db, 'share_mapping_get_by_share_id') as get:
            get.return_value = [fake_share_mapping]
            share_mappings = sm.ShareMappingList.get_by_share_id(
            self.context, uuids.share)

            self.assertEqual(1, len(share_mappings))
            self.assertIsInstance(share_mappings[0], sm.ShareMapping)


class TestShareMapping(test_objects._LocalTest, _TestShareMapping):
    pass


class TestShareMappingList(test_objects._LocalTest, _TestShareMappingList):
    pass


class TestShareMappingLibvirtNFS(test_objects._LocalTest):
    @mock.patch(
        'nova.virt.libvirt.volume.nfs.LibvirtNFSVolumeDriver')
    @mock.patch(
        'nova.db.main.api.share_mapping_update',
        return_value=fake_share_mapping_attached)
    def test_attach(self, mock_upd, mock_drv):
        share_mapping = objects.ShareMapping(self.context)
        share_mapping.uuid = uuids.share_mapping
        share_mapping.instance_uuid = uuids.instance
        share_mapping.share_id = uuids.share
        share_mapping.status = 'inactive'
        share_mapping.tag = 'fake_tag'
        share_mapping.export_location = '192.168.122.152:/manila/share'
        share_mapping.share_proto = 'NFS'
        # share_mapping_libvirt_nfs = objects.ShareMappingLibvirtNFS(
        #     self.context, 'fake_driver', share_mapping)
        instance = objects.Instance(self.context)
        instance.host = 'fake-host'
        share_mapping_libvirt_nfs = \
            objects.ShareMappingLibvirtNFS.from_share_mapping(
                self.context, instance, share_mapping)
        self.assertEqual(share_mapping_libvirt_nfs.instance, instance)
        self.assertEqual(
            share_mapping_libvirt_nfs.instance_uuid, uuids.instance)
        self.assertEqual(
            share_mapping_libvirt_nfs.share_id, uuids.share)
        self.assertEqual(share_mapping_libvirt_nfs.status, 'inactive')
        self.assertEqual(share_mapping_libvirt_nfs.tag, 'fake_tag')
        self.assertEqual(
            share_mapping_libvirt_nfs.export_location,
            '192.168.122.152:/manila/share')
        self.assertEqual(
            share_mapping_libvirt_nfs.share_proto, 'NFS')

        share_mapping_libvirt_nfs.attach('inactive')
        mock_upd.assert_called_once_with(
            self.context,
            uuids.share_mapping,
            uuids.instance,
            uuids.share,
            'inactive',
            'fake_tag',
            '192.168.122.152:/manila/share',
            'NFS'
        )
