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

import copy

from oslo_utils.fixture import uuidsentinel as uuids

from nova.compute import utils as compute_utils
from nova.conductor.tasks import cross_cell_migrate
from nova import context as nova_context
from nova import exception
from nova.network import model as network_model
from nova import objects
from nova.objects import base as obj_base
from nova.objects import instance as instance_obj
from nova import test
from nova.tests.unit.db import test_db_api
from nova.tests.unit import fake_block_device
from nova.tests.unit import fake_instance
from nova.tests.unit.objects import test_compute_node
from nova.tests.unit.objects import test_instance_device_metadata
from nova.tests.unit.objects import test_instance_numa_topology
from nova.tests.unit.objects import test_instance_pci_requests
from nova.tests.unit.objects import test_keypair
from nova.tests.unit.objects import test_migration
from nova.tests.unit.objects import test_pci_device
from nova.tests.unit.objects import test_service
from nova.tests.unit.objects import test_vcpu_model


class TargetDBSetupTaskTestCase(
        test.TestCase, test_db_api.ModelsObjectComparatorMixin):

    def setUp(self):
        super(TargetDBSetupTaskTestCase, self).setUp()
        cells = list(self.cell_mappings.values())
        self.source_cell = cells[0]
        self.target_cell = cells[1]
        # Pass is_admin=True because of the funky DB API
        # _check_instance_exists_in_project check when creating instance tags.
        self.source_context = nova_context.RequestContext(
            user_id='fake-user', project_id='fake-project', is_admin=True)
        self.target_context = self.source_context.elevated()  # copy source
        nova_context.set_target_cell(self.source_context, self.source_cell)
        nova_context.set_target_cell(self.target_context, self.target_cell)

    def _create_instance_data(self):
        """Creates an instance record and associated data like BDMs, VIFs,
        migrations, etc in the source cell and returns the Instance object.

        The idea is to create as many things from the
        Instance.INSTANCE_OPTIONAL_ATTRS list as possible.

        :returns: The created Instance and Migration objects
        """
        # Create the nova-compute services record first.
        fake_service = test_service._fake_service()
        fake_service.pop('version', None)  # version field is immutable
        fake_service.pop('id', None)  # cannot create with an id set
        service = objects.Service(self.source_context, **fake_service)
        service.create()
        # Create the compute node using the service.
        fake_compute_node = copy.copy(test_compute_node.fake_compute_node)
        fake_compute_node['host'] = service.host
        fake_compute_node['hypervisor_hostname'] = service.host
        fake_compute_node['stats'] = {}  # the object requires a dict
        fake_compute_node['service_id'] = service.id
        fake_compute_node.pop('id', None)  # cannot create with an id set
        compute_node = objects.ComputeNode(
            self.source_context, **fake_compute_node)
        compute_node.create()

        # Build an Instance object with basic fields set.
        updates = {
            'metadata': {'foo': 'bar'},
            'system_metadata': {'roles': ['member']},
            'host': compute_node.host,
            'node': compute_node.hypervisor_hostname
        }
        inst = fake_instance.fake_instance_obj(self.source_context, **updates)
        delattr(inst, 'id')  # cannot create an instance with an id set
        # Now we have to dirty all of the fields because fake_instance_obj
        # uses Instance._from_db_object to create the Instance object we have
        # but _from_db_object calls obj_reset_changes() which resets all of
        # the fields that were on the object, including the basic stuff like
        # the 'host' field, which means those fields don't get set in the DB.
        # TODO(mriedem): This should live in fake_instance_obj with a
        # make_creatable kwarg.
        for field in inst.obj_fields:
            if field in inst:
                setattr(inst, field, getattr(inst, field))
        # Make sure at least one expected basic field is dirty on the Instance.
        self.assertIn('host', inst.obj_what_changed())
        # Set the optional fields on the instance before creating it.
        inst.pci_requests = objects.InstancePCIRequests(requests=[
            objects.InstancePCIRequest(
                **test_instance_pci_requests.fake_pci_requests[0])])
        inst.numa_topology = objects.InstanceNUMATopology(
            cells=test_instance_numa_topology.fake_obj_numa_topology.cells)
        inst.trusted_certs = objects.TrustedCerts(ids=[uuids.cert])
        inst.vcpu_model = test_vcpu_model.fake_vcpumodel
        inst.keypairs = objects.KeyPairList(objects=[
            objects.KeyPair(**test_keypair.fake_keypair)])
        inst.device_metadata = (
            test_instance_device_metadata.get_fake_obj_device_metadata(
                self.source_context))
        # FIXME(mriedem): db.instance_create does not handle tags
        inst.obj_reset_changes(['tags'])
        inst.create()

        bdm = {
            'instance_uuid': inst.uuid,
            'source_type': 'volume',
            'destination_type': 'volume',
            'volume_id': uuids.volume_id,
            'volume_size': 1,
            'device_name': '/dev/vda',
        }
        bdm = objects.BlockDeviceMapping(
            self.source_context,
            **fake_block_device.FakeDbBlockDeviceDict(bdm_dict=bdm))
        delattr(bdm, 'id')  # cannot create a bdm with an id set
        bdm.obj_reset_changes(['id'])
        bdm.create()

        vif = objects.VirtualInterface(
            self.source_context, address='de:ad:be:ef:ca:fe', uuid=uuids.port,
            instance_uuid=inst.uuid)
        vif.create()

        info_cache = objects.InstanceInfoCache().new(
            self.source_context, inst.uuid)
        info_cache.network_info = network_model.NetworkInfo([
                network_model.VIF(id=vif.uuid, address=vif.address)])
        info_cache.save(update_cells=False)

        objects.TagList.create(self.source_context, inst.uuid, ['test'])

        try:
            raise test.TestingException('test-fault')
        except test.TestingException as fault:
            compute_utils.add_instance_fault_from_exc(
                self.source_context, inst, fault)

        objects.InstanceAction().action_start(
            self.source_context, inst.uuid, 'resize', want_result=False)
        objects.InstanceActionEvent().event_start(
            self.source_context, inst.uuid, 'migrate_server',
            want_result=False)

        # Create a fake migration for the cross-cell resize operation.
        migration = objects.Migration(
            self.source_context,
            **test_migration.fake_db_migration(
                instance_uuid=inst.uuid, cross_cell_move=True,
                migration_type='resize'))
        delattr(migration, 'id')  # cannot create a migration with an id set
        migration.obj_reset_changes(['id'])
        migration.create()

        # Create an old non-resize migration to make sure it is copied to the
        # target cell database properly.
        old_migration = objects.Migration(
            self.source_context,
            **test_migration.fake_db_migration(
                instance_uuid=inst.uuid, migration_type='live-migration',
                status='completed', uuid=uuids.old_migration))
        delattr(old_migration, 'id')  # cannot create a migration with an id
        old_migration.obj_reset_changes(['id'])
        old_migration.create()

        fake_pci_device = copy.copy(test_pci_device.fake_db_dev)
        fake_pci_device['extra_info'] = {}  # the object requires a dict
        fake_pci_device['compute_node_id'] = compute_node.id
        pci_device = objects.PciDevice.create(
            self.source_context, fake_pci_device)
        pci_device.allocate(inst)  # sets the status and instance_uuid fields
        pci_device.save()

        # Return a fresh copy of the instance from the DB with as many joined
        # fields loaded as possible.
        expected_attrs = copy.copy(instance_obj.INSTANCE_OPTIONAL_ATTRS)
        # Cannot load fault from get_by_uuid.
        expected_attrs.remove('fault')
        inst = objects.Instance.get_by_uuid(
            self.source_context, inst.uuid, expected_attrs=expected_attrs)
        return inst, migration

    def _compare_objs(self, obj1, obj2, ignored_keys=None):
        # We can always ignore id since it is not deterministic when records
        # are copied over to the target cell database.
        if ignored_keys is None:
            ignored_keys = []
        if 'id' not in ignored_keys:
            ignored_keys.append('id')
        prim1 = obj1.obj_to_primitive()['nova_object.data']
        prim2 = obj2.obj_to_primitive()['nova_object.data']
        if isinstance(obj1, obj_base.ObjectListBase):
            self.assertEqual(len(obj1), len(obj2))
            prim1 = [o['nova_object.data'] for o in prim1['objects']]
            prim2 = [o['nova_object.data'] for o in prim2['objects']]
            self._assertEqualListsOfObjects(
                prim1, prim2, ignored_keys=ignored_keys)
        else:
            self._assertEqualObjects(prim1, prim2, ignored_keys=ignored_keys)

    def test_execute_and_rollback(self):
        """Happy path test which creates an instance with related records
        in a source cell and then executes TargetDBSetupTask to create those
        same records in a target cell. Runs rollback to make sure the target
        cell instance is deleted.
        """
        source_cell_instance, migration = self._create_instance_data()
        instance_uuid = source_cell_instance.uuid

        task = cross_cell_migrate.TargetDBSetupTask(
            self.source_context, source_cell_instance, migration,
            self.target_context)
        target_cell_instance = task.execute()[0]

        # The instance in the target cell should be hidden.
        self.assertTrue(target_cell_instance.hidden,
                        'Target cell instance should be hidden')
        # Assert that the various records created in _create_instance_data are
        # found in the target cell database. We ignore 'hidden' because the
        # values are explicitly different between source and target DB. The
        # pci_devices/services/tags fields are not set on the target instance
        # during TargetDBSetupTask.execute so we ignore those here and verify
        # them below.
        ignored_keys = ['hidden', 'pci_devices', 'services', 'tags']
        self._compare_objs(source_cell_instance, target_cell_instance,
                           ignored_keys=ignored_keys)

        # Explicitly compare flavor fields to make sure they are created and
        # loaded properly.
        for flavor_field in ('old_', 'new_', ''):
            source_field = getattr(
                source_cell_instance, flavor_field + 'flavor')
            target_field = getattr(
                target_cell_instance, flavor_field + 'flavor')
            # old/new may not be set
            if source_field is None or target_field is None:
                self.assertIsNone(source_field)
                self.assertIsNone(target_field)
            else:
                self._compare_objs(source_field, target_field)

        # Compare PCI requests
        self.assertIsNotNone(target_cell_instance.pci_requests)
        self._compare_objs(source_cell_instance.pci_requests,
                           target_cell_instance.pci_requests)

        # Compare requested instance NUMA topology
        self.assertIsNotNone(target_cell_instance.numa_topology)
        self._compare_objs(source_cell_instance.numa_topology,
                           target_cell_instance.numa_topology)

        # Compare trusted certs
        self.assertIsNotNone(target_cell_instance.trusted_certs)
        self._compare_objs(source_cell_instance.trusted_certs,
                           target_cell_instance.trusted_certs)

        # Compare vcpu_model
        self.assertIsNotNone(target_cell_instance.vcpu_model)
        self._compare_objs(source_cell_instance.vcpu_model,
                           target_cell_instance.vcpu_model)

        # Compare keypairs
        self.assertEqual(1, len(target_cell_instance.keypairs))
        self._compare_objs(source_cell_instance.keypairs,
                           target_cell_instance.keypairs)

        # Compare device_metadata
        self.assertIsNotNone(target_cell_instance.device_metadata)
        self._compare_objs(source_cell_instance.device_metadata,
                           target_cell_instance.device_metadata)

        # Compare BDMs
        target_bdms = target_cell_instance.get_bdms()
        self.assertEqual(1, len(target_bdms))
        self._compare_objs(source_cell_instance.get_bdms(), target_bdms)
        self.assertEqual(source_cell_instance.uuid,
                         target_bdms[0].instance_uuid)

        # Compare VIFs
        source_vifs = objects.VirtualInterfaceList.get_by_instance_uuid(
            self.source_context, instance_uuid)
        target_vifs = objects.VirtualInterfaceList.get_by_instance_uuid(
            self.target_context, instance_uuid)
        self.assertEqual(1, len(target_vifs))
        self._compare_objs(source_vifs, target_vifs)

        # Compare info cache (there should be a single vif in the target)
        self.assertEqual(1, len(target_cell_instance.info_cache.network_info))
        self.assertEqual(target_vifs[0].uuid,
                         target_cell_instance.info_cache.network_info[0]['id'])
        self._compare_objs(source_cell_instance.info_cache,
                           target_cell_instance.info_cache)

        # Compare tags
        self.assertEqual(1, len(target_cell_instance.tags))
        self._compare_objs(source_cell_instance.tags,
                           target_cell_instance.tags)

        # Assert that the fault from the source is not in the target.
        self.assertIsNone(target_cell_instance.fault)

        # Compare instance actions and events
        source_actions = objects.InstanceActionList.get_by_instance_uuid(
            self.source_context, instance_uuid)
        target_actions = objects.InstanceActionList.get_by_instance_uuid(
            self.target_context, instance_uuid)
        self._compare_objs(source_actions, target_actions)

        # The InstanceActionEvent.action_id is per-cell DB so we need to get
        # the events per action and compare them but ignore the action_id.
        source_events = objects.InstanceActionEventList.get_by_action(
            self.source_context, source_actions[0].id)
        target_events = objects.InstanceActionEventList.get_by_action(
            self.target_context, target_actions[0].id)
        self._compare_objs(source_events, target_events,
                           ignored_keys=['action_id'])

        # Compare migrations
        filters = {'instance_uuid': instance_uuid}
        source_migrations = objects.MigrationList.get_by_filters(
            self.source_context, filters)
        target_migrations = objects.MigrationList.get_by_filters(
            self.target_context, filters)
        # There should be two migrations in the target cell.
        self.assertEqual(2, len(target_migrations))
        self._compare_objs(source_migrations, target_migrations)
        # One should be a live-migration type (make sure Migration._from-db_obj
        # did not set the migration_type for us).
        migration_types = [mig.migration_type for mig in target_migrations]
        self.assertIn('resize', migration_types)
        self.assertIn('live-migration', migration_types)

        # pci_devices and services should not have been copied over since they
        # are specific to the compute node in the source cell database
        for field in ('pci_devices', 'services'):
            source_value = getattr(source_cell_instance, field)
            self.assertEqual(
                1, len(source_value),
                'Unexpected number of %s in source cell instance' % field)
            target_value = getattr(target_cell_instance, field)
            self.assertEqual(
                0, len(target_value),
                'Unexpected number of %s in target cell instance' % field)

        # Rollback the task and assert the instance and its related data are
        # gone from the target cell database. Use a modified context to make
        # sure the instance was hard-deleted.
        task.rollback()
        read_deleted_ctxt = self.target_context.elevated(read_deleted='yes')
        self.assertRaises(exception.InstanceNotFound,
                          objects.Instance.get_by_uuid,
                          read_deleted_ctxt, target_cell_instance.uuid)
