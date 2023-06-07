# Copyright 2020 Red Hat, Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import testtools

from nova.api.validation.extra_specs import validators
from nova import exception
from nova import test


class TestValidators(test.NoDBTestCase):

    def test_namespaces(self):
        """Ensure we see at least the in-tree namespaces.

        If we add new namespaces, they should be added to this list.
        """
        namespaces = {
            'accel', 'aggregate_instance_extra_specs', 'capabilities', 'hw',
            'hw_rng', 'hw_video', 'os', 'pci_passthrough', 'quota',
            'resources(?P<group>([a-zA-Z0-9_-]{1,64})?)',
            'trait(?P<group>([a-zA-Z0-9_-]{1,64})?)', 'vmware',
        }
        self.assertTrue(
            namespaces.issubset(validators.NAMESPACES),
            f'{namespaces} is not a subset of {validators.NAMESPACES}',
        )

    def test_spec(self):
        unknown_namespaces = (
            ('hhw:cpu_realtime_mask', '^0'),
            ('w:cpu_realtime_mask', '^0'),
            ('hw_cpu_realtime_mask', '^0'),
            ('foo', 'bar'),
        )
        for key, value in unknown_namespaces:
            validators.validate(key, value)

        known_invalid_namespaces = (
            ('hw:cpu_realtime_maskk', '^0'),
            ('hw:cpu_realtime_mas', '^0'),
            ('hw:foo', 'bar'),
        )
        for key, value in known_invalid_namespaces:
            with testtools.ExpectedException(exception.ValidationError):
                validators.validate(key, value)

    def test_value__str(self):
        valid_specs = (
            # patterns
            ('hw:cpu_realtime_mask', '0'),
            ('hw:cpu_realtime_mask', '^0'),
            ('hw:cpu_realtime_mask', '^0,2-3,1'),
            ('hw:cpu_dedicated_mask', '0-4,^2,6'),
            ('hw:mem_page_size', 'large'),
            ('hw:mem_page_size', '2kbit'),
            ('hw:mem_page_size', '1GB'),
            # enums
            ('hw:cpu_thread_policy', 'prefer'),
            ('hw:emulator_threads_policy', 'isolate'),
            ('hw:pci_numa_affinity_policy', 'legacy'),
            ('hw:pci_numa_affinity_policy', 'required'),
            ('hw:pci_numa_affinity_policy', 'preferred'),
            ('hw:pci_numa_affinity_policy', 'socket'),
            ('hw:cpu_policy', 'mixed'),
            ('hw:viommu_model', 'auto'),
            ('hw:viommu_model', 'intel'),
            ('hw:viommu_model', 'smmuv3'),
            ('hw:viommu_model', 'virtio'),
        )
        for key, value in valid_specs:
            validators.validate(key, value)

        invalid_specs = (
            # patterns
            ('hw:cpu_realtime_mask', 'a'),
            ('hw:cpu_realtime_mask', '^0,2-3,b'),
            ('hw:mem_page_size', 'largest'),
            ('hw:mem_page_size', '2kbits'),
            ('hw:mem_page_size', '1gigabyte'),
            # enums
            ('hw:cpu_thread_policy', 'preferred'),
            ('hw:emulator_threads_policy', 'iisolate'),
            ('hw:pci_numa_affinity_policy', 'lgacy'),
            ('hw:pci_numa_affinity_policy', 'requird'),
            ('hw:pci_numa_affinity_policy', 'prefrred'),
            ('hw:pci_numa_affinity_policy', 'socet'),
            ('hw:viommu_model', 'autt'),
        )
        for key, value in invalid_specs:
            with testtools.ExpectedException(exception.ValidationError):
                validators.validate(key, value)

    def test_value__int(self):
        valid_specs = (
            ('hw:numa_nodes', '1'),
            ('os:monitors', '1'),
            ('os:monitors', '8'),
        )
        for key, value in valid_specs:
            validators.validate(key, value)

        invalid_specs = (
            ('hw:serial_port_count', 'five'),  # NaN
            ('hw:serial_port_count', '!'),  # NaN
            ('hw:numa_nodes', '0'),  # has min
            ('os:monitors', '0'),  # has min
            ('os:monitors', '9'),  # has max
        )
        for key, value in invalid_specs:
            with testtools.ExpectedException(exception.ValidationError):
                validators.validate(key, value)

    def test_value__bool(self):
        valid_specs = (
            ('hw:cpu_realtime', '1'),
            ('hw:cpu_realtime', '0'),
            ('hw:mem_encryption', 'true'),
            ('hw:boot_menu', 'y'),
            ('hw:share_local_fs', 'true'),
            ('hw:share_local_fs', 'yes'),
        )
        for key, value in valid_specs:
            validators.validate(key, value)

        invalid_specs = (
            ('hw:cpu_realtime', '2'),
            ('hw:cpu_realtime', '00'),
            ('hw:mem_encryption', 'tru'),
            ('hw:boot_menu', 'yah'),
            ('hw:share_local_fs', 'tru'),
            ('hw:share_local_fs', 'yah'),
        )
        for key, value in invalid_specs:
            with testtools.ExpectedException(exception.ValidationError):
                validators.validate(key, value)
