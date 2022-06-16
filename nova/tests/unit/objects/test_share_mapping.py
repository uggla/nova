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
import datetime

from copy import deepcopy
from nova.db.main import api as db
from nova.db.main import models
from nova import exception
from nova import objects
from nova.objects import share_mapping as sm
from nova.tests.unit.objects import test_objects
from oslo_concurrency import processutils
from oslo_utils.fixture import uuidsentinel as uuids

from unittest import mock


fake_share_mapping = {
    'created_at': datetime.datetime(2022, 8, 25, 10, 5, 4),
    'updated_at': None,
    'id': 1,
    'uuid': uuids.share_mapping,
    'instance_uuid': uuids.instance,
    'share_id': uuids.share,
    'status': 'inactive',
    'tag': 'fake_tag',
    'export_location': '192.168.122.152:/manila/share',
    'share_proto': 'NFS',
    }

fake_share_mapping2 = {
    'created_at': datetime.datetime(2022, 8, 26, 10, 5, 4),
    'updated_at': None,
    'id': 2,
    'uuid': uuids.share_mapping2,
    'instance_uuid': uuids.instance,
    'share_id': uuids.share2,
    'status': 'inactive',
    'tag': 'fake_tag2',
    'export_location': '192.168.122.152:/manila/share2',
    'share_proto': 'NFS',
    }

fake_share_mapping_attached = deepcopy(fake_share_mapping)
fake_share_mapping_attached['status'] = 'active'


class _TestShareMapping(object):
    def _compare_obj(self, share_mapping, fake_share_mapping):
        self.compare_obj(
            share_mapping,
            fake_share_mapping,
            allow_missing=['deleted', 'deleted_at'])

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
        self._compare_obj(share_mapping, fake_share_mapping)

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
    def test_create(self, mock_upd):
        share_mapping = objects.ShareMapping(self.context)
        share_mapping.uuid = uuids.share_mapping
        share_mapping.instance_uuid = uuids.instance
        share_mapping.share_id = uuids.share
        share_mapping.status = 'inactive'
        share_mapping.tag = 'fake_tag'
        share_mapping.export_location = '192.168.122.152:/manila/share'
        share_mapping.share_proto = 'NFS'
        share_mapping.create()
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
        self._compare_obj(share_mapping, fake_share_mapping_attached)

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
        share_mapping.attach()
        mock_upd.assert_called_once_with(
            self.context,
            uuids.share_mapping,
            uuids.instance,
            uuids.share,
            'active',
            'fake_tag',

            '192.168.122.152:/manila/share',
            'NFS'
        )
        self._compare_obj(share_mapping, fake_share_mapping_attached)

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

    def test_get_by_instance_uuid_and_share_id(self):

        fake_db_sm = models.ShareMapping()
        fake_db_sm.id = 1
        fake_db_sm.created_at = datetime.datetime(2022, 8, 25, 10, 5, 4)
        fake_db_sm.uuid = fake_share_mapping['uuid']
        fake_db_sm.instance_uuid = fake_share_mapping['instance_uuid']
        fake_db_sm.share_id = fake_share_mapping['share_id']
        fake_db_sm.status = fake_share_mapping['status']
        fake_db_sm.tag = fake_share_mapping['tag']
        fake_db_sm.export_location = fake_share_mapping['export_location']
        fake_db_sm.share_proto = fake_share_mapping['share_proto']

        with mock.patch(
            'nova.db.main.api.share_mapping_get_by_instance_uuid_and_share_id',
            return_value=fake_db_sm
        ) as mock_get:

            share_mapping = sm.ShareMapping.get_by_instance_uuid_and_share_id(
                self.context,
                uuids.instance,
                uuids.share
            )

            mock_get.assert_called_once_with(
                self.context, uuids.instance, uuids.share)

            self._compare_obj(share_mapping, fake_share_mapping)

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
            db, 'share_mapping_get_by_instance_uuid'
        ) as get:
            get.return_value = [fake_share_mapping]
            share_mappings = sm.ShareMappingList.get_by_instance_uuid(
                self.context, uuids.instance
            )

            self.assertIsInstance(share_mappings, sm.ShareMappingList)
            self.assertEqual(1, len(share_mappings))
            self.assertIsInstance(share_mappings[0], sm.ShareMapping)

    def test_get_by_share_id(self):
        with mock.patch.object(db, 'share_mapping_get_by_share_id') as get:
            get.return_value = [fake_share_mapping]
            share_mappings = sm.ShareMappingList.get_by_share_id(
                self.context, uuids.share
            )

            self.assertIsInstance(share_mappings, sm.ShareMappingList)
            self.assertEqual(1, len(share_mappings))
            self.assertIsInstance(share_mappings[0], sm.ShareMapping)

    def _convert_to_driver(self, fake_share_mappings_list):
        instance = objects.Instance(self.context)
        instance.host = 'fake_host'
        with mock.patch.object(
            db, 'share_mapping_get_by_instance_uuid'
        ) as get:
            get.return_value = fake_share_mappings_list
            share_mappings = sm.ShareMappingList.get_by_instance_uuid(
                self.context, uuids.share
            )

        self.assertIsInstance(share_mappings, sm.ShareMappingList)
        self.assertEqual(len(fake_share_mappings_list), len(share_mappings))
        share_mappings_drv = share_mappings.convert_to_driver(
            self.context, instance)
        return share_mappings_drv

    def test_convert_to_driver_two_items(self):
        share_mappings_drv = self._convert_to_driver(
            [fake_share_mapping, fake_share_mapping2])
        self.assertIsInstance(share_mappings_drv, sm.ShareMappingDrvList)
        self.assertEqual(2, len(share_mappings_drv))
        self.assertIsInstance(share_mappings_drv[0], sm.ShareMappingLibvirtNFS)
        self.assertIsInstance(share_mappings_drv[1], sm.ShareMappingLibvirtNFS)
        return share_mappings_drv

    def test_convert_to_driver_no_items(self):
        share_mappings_drv = self._convert_to_driver([])
        self.assertIsInstance(share_mappings_drv, sm.ShareMappingDrvList)
        self.assertEqual(0, len(share_mappings_drv))
        return share_mappings_drv

    def test_mount_all(self):
        share_mappings_drv = self.test_convert_to_driver_two_items()
        with mock.patch('nova.objects.share_mapping.'
                        'ShareMappingLibvirtNFS.attach') as mock_attach:
            share_mappings_drv.mount_all()
            mock_attach.assert_called_with()
            self.assertEqual(mock_attach.call_count, 2)

    def test_mount_umount_empty_list(self):
        share_mappings_drv = self.test_convert_to_driver_no_items()
        with mock.patch('nova.objects.share_mapping.'
                        'ShareMappingLibvirtNFS.attach'):
            share_mappings_drv.mount_all()
            share_mappings_drv.umount_all()

    def test_umount_all(self):
        share_mappings_drv = self.test_convert_to_driver_two_items()
        with mock.patch('nova.objects.share_mapping.'
                        'ShareMappingLibvirtNFS.detach') as mock_detach:
            share_mappings_drv.umount_all()
            mock_detach.assert_called_with()
            self.assertEqual(mock_detach.call_count, 2)


class TestShareMapping(test_objects._LocalTest, _TestShareMapping):
    pass


class TestRemoteShareMapping(test_objects._RemoteTest, _TestShareMapping):
    pass


class TestShareMappingList(test_objects._LocalTest, _TestShareMappingList):
    pass


class TestRemoteShareMappingList(
        test_objects._RemoteTest, _TestShareMappingList):
    pass


class TestShareMappingLibvirtNFS(test_objects._LocalTest):
    def fake_share_mapping(self):
        share_mapping = objects.ShareMapping(self.context)
        share_mapping.uuid = uuids.share_mapping
        share_mapping.instance_uuid = uuids.instance
        share_mapping.share_id = uuids.share
        share_mapping.status = 'inactive'
        share_mapping.tag = 'fake_tag'
        share_mapping.export_location = '192.168.122.152:/manila/share'
        share_mapping.share_proto = 'NFS'
        return share_mapping

    @mock.patch(
        'nova.virt.libvirt.volume.nfs.LibvirtNFSVolumeDriver.connect_volume')
    def test_attach(self, mock_drv):
        share_mapping = self.fake_share_mapping()
        instance = objects.Instance(self.context)
        instance.host = 'fake-host'
        share_mapping_libvirt_nfs = (
            sm.ShareMappingLibvirt.from_share_mapping(
                self.context, instance, share_mapping)
        )

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

        with mock.patch('nova.db.main.api.share_mapping_update') as mock_upd:
            mock_upd.return_value = fake_share_mapping_attached
            share_mapping_libvirt_nfs.attach()
            mock_upd.assert_called_once_with(
                self.context,
                uuids.share_mapping,
                uuids.instance,
                uuids.share,
                'active',
                'fake_tag',
                '192.168.122.152:/manila/share',
                'NFS'
            )
        return (share_mapping_libvirt_nfs)

    @mock.patch(
        'nova.virt.libvirt.volume.nfs.LibvirtNFSVolumeDriver.'
        'disconnect_volume')
    @mock.patch(
        'nova.db.main.api.share_mapping_delete_by_instance_uuid_and_share_id')
    def test_detach(self, mock_del, mock_drv):
        share_mapping_libvirt_nfs = self.test_attach()
        # fake_share_mapping_attached returns an active status.
        # Make sure a first call to detach() will change the status from
        # active to inactive.
        with mock.patch('nova.db.main.api.share_mapping_update') as mock_upd:
            mock_upd.return_value = fake_share_mapping
            share_mapping_libvirt_nfs.detach()
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

            # So the next call to detach() should remove the share_mapping db
            # record.
            share_mapping_libvirt_nfs.detach()
            mock_del.assert_called_once_with(
                self.context,
                uuids.instance,
                uuids.share,
            )

    @mock.patch(
        'nova.virt.libvirt.volume.nfs.LibvirtNFSVolumeDriver.connect_volume',
        side_effect=processutils.ProcessExecutionError(
            stdout='This is stdout',
            stderr='This is stderror',
            exit_code=1,
            cmd="mount")
    )
    @mock.patch(
        'nova.db.main.api.share_mapping_update',
        return_value=fake_share_mapping_attached)
    def test_attach_fails_to_mount_share(self, mock_upd, mock_drv):
        share_mapping = self.fake_share_mapping()
        instance = objects.Instance(self.context)
        instance.host = 'fake-host'
        share_mapping_libvirt_nfs = (
            sm.ShareMappingLibvirt.from_share_mapping(
                self.context, instance, share_mapping)
        )

        exc = self.assertRaises(
            exception.ShareMountError,
            share_mapping_libvirt_nfs.attach
        )

        self.assertIn("Unexpected error while running command", exc.message)
        self.assertIn("mount", exc.message)
        self.assertIn("This is stdout", exc.message)
        self.assertIn("This is stderr", exc.message)

    @mock.patch(
        'nova.virt.libvirt.volume.nfs.LibvirtNFSVolumeDriver.'
        'disconnect_volume',
        side_effect=processutils.ProcessExecutionError(
            stdout='This is stdout',
            stderr='This is stderror',
            exit_code=1,
            cmd="umount")
    )
    @mock.patch(
        'nova.db.main.api.share_mapping_delete_by_instance_uuid_and_share_id')
    def test_detach_fails_to_umount_share(self, mock_del, mock_drv):
        share_mapping_libvirt_nfs = self.test_attach()

        exc = self.assertRaises(
            exception.ShareUmountError,
            share_mapping_libvirt_nfs.detach
        )

        self.assertIn("Unexpected error while running command", exc.message)
        self.assertIn("umount", exc.message)
        self.assertIn("This is stdout", exc.message)
        self.assertIn("This is stderr", exc.message)
