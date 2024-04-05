#    Copyright 2015 Red Hat, Inc.
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

from oslo_serialization import jsonutils
from oslo_utils.fixture import uuidsentinel as uuids
from oslo_versionedobjects import base as ovo_base

from nova import exception
from nova.network import model as network_model
from nova import objects
from nova.objects import migrate_data
from nova import test
from nova.tests.unit.objects import test_objects


class _TestLiveMigrateData(object):
    def test_obj_make_compatible(self):
        props = {
            'serial_listen_addr': '127.0.0.1',
            'serial_listen_ports': [1000, 10001, 10002, 10003],
            'wait_for_vif_plugged': True
        }

        obj = migrate_data.LibvirtLiveMigrateData(**props)
        primitive = obj.obj_to_primitive()
        self.assertIn('serial_listen_ports', primitive['nova_object.data'])
        self.assertIn('wait_for_vif_plugged', primitive['nova_object.data'])
        obj.obj_make_compatible(primitive['nova_object.data'], '1.5')
        self.assertNotIn('wait_for_vif_plugged', primitive['nova_object.data'])
        obj.obj_make_compatible(primitive['nova_object.data'], '1.1')
        self.assertNotIn('serial_listen_ports', primitive['nova_object.data'])


class TestLiveMigrateData(test_objects._LocalTest,
                          _TestLiveMigrateData):
    pass


class TestRemoteLiveMigrateData(test_objects._RemoteTest,
                                _TestLiveMigrateData):
    pass


class _TestLibvirtLiveMigrateData(object):
    def test_bdm_to_disk_info(self):
        obj = migrate_data.LibvirtLiveMigrateBDMInfo(
            serial='foo', bus='scsi', dev='sda', type='disk')
        expected_info = {
            'dev': 'sda',
            'bus': 'scsi',
            'type': 'disk',
        }
        self.assertEqual(expected_info, obj.as_disk_info())
        obj.format = 'raw'
        obj.boot_index = 1
        expected_info['format'] = 'raw'
        expected_info['boot_index'] = '1'
        self.assertEqual(expected_info, obj.as_disk_info())

    def test_numa_migrate_data(self):
        data = lambda x: x['nova_object.data']
        obj = migrate_data.LibvirtLiveMigrateNUMAInfo(
            cpu_pins={'0': set([1])},
            cell_pins={'2': set([3])},
            emulator_pins=set([4]),
            sched_vcpus=set([5]),
            sched_priority=6)
        manifest = ovo_base.obj_tree_get_versions(obj.obj_name())
        primitive = data(obj.obj_to_primitive(target_version='1.0',
                                              version_manifest=manifest))
        self.assertEqual({'0': (1,)}, primitive['cpu_pins'])
        self.assertEqual({'2': (3,)}, primitive['cell_pins'])
        self.assertEqual((4,), primitive['emulator_pins'])
        self.assertEqual((5,), primitive['sched_vcpus'])
        self.assertEqual(6, primitive['sched_priority'])

    def test_obj_make_compatible(self):
        obj = migrate_data.LibvirtLiveMigrateData(
            src_supports_native_luks=True,
            old_vol_attachment_ids={uuids.volume: uuids.attachment},
            supported_perf_events=[],
            serial_listen_addr='127.0.0.1',
            target_connect_addr='127.0.0.1',
            dst_wants_file_backed_memory=False,
            file_backed_memory_discard=False,
            src_supports_numa_live_migration=True,
            dst_supports_numa_live_migration=True,
            dst_numa_info=migrate_data.LibvirtLiveMigrateNUMAInfo(),
            dst_supports_mdev_live_migration=True,
            source_mdev_types={},
            target_mdevs={},
            dst_cpu_shared_set_info=set())
        manifest = ovo_base.obj_tree_get_versions(obj.obj_name())

        data = lambda x: x['nova_object.data']

        primitive = data(obj.obj_to_primitive())
        self.assertIn('file_backed_memory_discard', primitive)
        primitive = data(obj.obj_to_primitive(target_version='1.0',
                                              version_manifest=manifest))
        self.assertNotIn('target_connect_addr', primitive)
        self.assertNotIn('supported_perf_events', primitive)
        self.assertNotIn('old_vol_attachment_ids', primitive)
        self.assertNotIn('src_supports_native_luks', primitive)
        self.assertNotIn('dst_wants_file_backed_memory', primitive)
        primitive = data(obj.obj_to_primitive(target_version='1.1',
                                              version_manifest=manifest))
        self.assertNotIn('serial_listen_ports', primitive)
        primitive = data(obj.obj_to_primitive(target_version='1.2',
                                              version_manifest=manifest))
        self.assertNotIn('supported_perf_events', primitive)
        primitive = data(obj.obj_to_primitive(target_version='1.3',
                                              version_manifest=manifest))
        self.assertNotIn('old_vol_attachment_ids', primitive)
        primitive = data(obj.obj_to_primitive(target_version='1.4',
                                              version_manifest=manifest))
        self.assertNotIn('src_supports_native_luks', primitive)
        primitive = data(obj.obj_to_primitive(target_version='1.6',
                                              version_manifest=manifest))
        self.assertNotIn('dst_wants_file_backed_memory', primitive)
        primitive = data(obj.obj_to_primitive(target_version='1.7',
                                              version_manifest=manifest))
        self.assertNotIn('file_backed_memory_discard', primitive)
        primitive = data(obj.obj_to_primitive(target_version='1.9',
                                              version_manifest=manifest))
        self.assertNotIn('dst_numa_info', primitive)
        self.assertNotIn('src_supports_numa_live_migration', primitive)
        self.assertNotIn('dst_supports_numa_live_migration', primitive)
        primitive = data(obj.obj_to_primitive(target_version='1.10',
                                              version_manifest=manifest))
        self.assertNotIn('dst_supports_mdev_live_migration', primitive)
        self.assertNotIn('source_mdev_types', primitive)
        self.assertNotIn('target_mdevs', primitive)
        primitive = data(obj.obj_to_primitive(target_version='1.11',
                                              version_manifest=manifest))
        self.assertNotIn('dst_cpu_shared_set_info', primitive)

    def test_bdm_obj_make_compatible(self):
        obj = migrate_data.LibvirtLiveMigrateBDMInfo(
            encryption_secret_uuid=uuids.encryption_secret_uuid)
        primitive = obj.obj_to_primitive(target_version='1.0')
        self.assertNotIn(
            'encryption_secret_uuid', primitive['nova_object.data'])

        primitive = obj.obj_to_primitive(target_version='1.1')
        self.assertIn(
            'encryption_secret_uuid', primitive['nova_object.data'])

    def test_vif_migrate_data(self):
        source_vif = network_model.VIF(
            id=uuids.port_id,
            network=network_model.Network(id=uuids.network_id),
            type=network_model.VIF_TYPE_OVS,
            vnic_type=network_model.VNIC_TYPE_NORMAL,
            active=True,
            profile={'migrating_to': 'dest-host'})
        vif_details_dict = {'port_filter': True}
        profile_dict = {'trusted': False}
        vif_data = objects.VIFMigrateData(
            port_id=uuids.port_id,
            vnic_type=network_model.VNIC_TYPE_NORMAL,
            vif_type=network_model.VIF_TYPE_BRIDGE,
            vif_details=vif_details_dict, profile=profile_dict,
            host='dest-host', source_vif=source_vif)
        # Make sure the vif_details and profile fields are converted and
        # stored properly.
        self.assertEqual(
            jsonutils.dumps(vif_details_dict), vif_data.vif_details_json)
        self.assertEqual(
            jsonutils.dumps(profile_dict), vif_data.profile_json)
        self.assertDictEqual(vif_details_dict, vif_data.vif_details)
        self.assertDictEqual(profile_dict, vif_data.profile)
        obj = migrate_data.LibvirtLiveMigrateData(
            file_backed_memory_discard=False)
        obj.vifs = [vif_data]
        manifest = ovo_base.obj_tree_get_versions(obj.obj_name())
        primitive = obj.obj_to_primitive(target_version='1.8',
                                         version_manifest=manifest)
        self.assertIn(
            'file_backed_memory_discard', primitive['nova_object.data'])
        self.assertNotIn('vifs', primitive['nova_object.data'])


class TestLibvirtLiveMigrateData(test_objects._LocalTest,
                                 _TestLibvirtLiveMigrateData):
    pass


class TestRemoteLibvirtLiveMigrateData(test_objects._RemoteTest,
                                       _TestLibvirtLiveMigrateData):
    pass


class _TestHyperVLiveMigrateData(object):
    def test_obj_make_compatible(self):
        obj = migrate_data.HyperVLiveMigrateData(
            is_shared_instance_path=True,
            old_vol_attachment_ids={'yes': 'no'},
            wait_for_vif_plugged=True)

        data = lambda x: x['nova_object.data']

        primitive = data(obj.obj_to_primitive())
        self.assertIn('is_shared_instance_path', primitive)
        primitive = data(obj.obj_to_primitive(target_version='1.0'))
        self.assertNotIn('is_shared_instance_path', primitive)
        primitive = data(obj.obj_to_primitive(target_version='1.1'))
        self.assertNotIn('old_vol_attachment_ids', primitive)
        primitive = data(obj.obj_to_primitive(target_version='1.2'))
        self.assertNotIn('wait_for_vif_plugged', primitive)


class TestHyperVLiveMigrateData(test_objects._LocalTest,
                                _TestHyperVLiveMigrateData):
    pass


class TestRemoteHyperVLiveMigrateData(test_objects._RemoteTest,
                                      _TestHyperVLiveMigrateData):
    pass


class TestVIFMigrateData(test.NoDBTestCase):

    def test_get_dest_vif_source_vif_not_set(self):
        migrate_vif = objects.VIFMigrateData(
            port_id=uuids.port_id, vnic_type=network_model.VNIC_TYPE_NORMAL,
            vif_type=network_model.VIF_TYPE_OVS, vif_details={},
            profile={}, host='fake-dest-host')
        self.assertRaises(
            exception.ObjectActionError, migrate_vif.get_dest_vif)

    def test_get_dest_vif(self):
        source_vif = network_model.VIF(
            id=uuids.port_id, type=network_model.VIF_TYPE_OVS, details={},
            vnic_type=network_model.VNIC_TYPE_DIRECT, profile={'foo': 'bar'},
            ovs_interfaceid=uuids.ovs_interfaceid)
        migrate_vif = objects.VIFMigrateData(
            port_id=uuids.port_id, vnic_type=network_model.VNIC_TYPE_NORMAL,
            vif_type=network_model.VIF_TYPE_BRIDGE, vif_details={'bar': 'baz'},
            profile={}, host='fake-dest-host', source_vif=source_vif)
        dest_vif = migrate_vif.get_dest_vif()
        self.assertEqual(migrate_vif.port_id, dest_vif['id'])
        self.assertEqual(migrate_vif.vnic_type, dest_vif['vnic_type'])
        self.assertEqual(migrate_vif.vif_type, dest_vif['type'])
        self.assertEqual(migrate_vif.vif_details, dest_vif['details'])
        self.assertEqual(migrate_vif.profile, dest_vif['profile'])
        self.assertEqual(uuids.ovs_interfaceid, dest_vif['ovs_interfaceid'])

    def test_create_skeleton_migrate_vifs(self):
        vifs = [
            network_model.VIF(id=uuids.port1),
            network_model.VIF(id=uuids.port2)]
        mig_vifs = migrate_data.VIFMigrateData.create_skeleton_migrate_vifs(
            vifs)
        self.assertEqual(len(vifs), len(mig_vifs))
        self.assertEqual([vif['id'] for vif in vifs],
                         [mig_vif.port_id for mig_vif in mig_vifs])

    def test_supports_os_vif_delegation(self):
        # first try setting on a object without 'profile' defined
        migrate_vif = objects.VIFMigrateData(
            port_id=uuids.port_id, vnic_type=network_model.VNIC_TYPE_NORMAL,
            vif_type=network_model.VIF_TYPE_OVS, vif_details={},
            host='fake-dest-host')
        migrate_vif.supports_os_vif_delegation = True
        self.assertTrue(migrate_vif.supports_os_vif_delegation)
        self.assertEqual(migrate_vif.profile, {'os_vif_delegation': True})

        # now do the same but with profile defined
        migrate_vif = objects.VIFMigrateData(
            port_id=uuids.port_id, vnic_type=network_model.VNIC_TYPE_NORMAL,
            vif_type=network_model.VIF_TYPE_OVS, vif_details={},
            host='fake-dest-host', profile={'interface_name': 'eth0'})
        migrate_vif.supports_os_vif_delegation = True
        self.assertTrue(migrate_vif.supports_os_vif_delegation)
        self.assertEqual(
            migrate_vif.profile,
            {'os_vif_delegation': True, 'interface_name': 'eth0'})
