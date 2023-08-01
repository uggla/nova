#    Copyright 2011 OpenStack Foundation
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

from requests import Response

import fixtures
import nova.conf
from nova import exception
from nova.share import manila
from nova import test

from openstack import exceptions as sdk_exc
from openstack.shared_file_system.v2.resource_locks import (
    ResourceLock as SdkResourceLock
)
from openstack.shared_file_system.v2.share import (
    Share as SdkShare
)
from openstack.shared_file_system.v2.share_access_rule import (
    ShareAccessRule as SdkAccessRule
)
from openstack.shared_file_system.v2.share_export_locations import (
    ShareExportLocation as SdkExportLocation
)
from openstack.utils import Munch
from unittest import mock

CONF = nova.conf.CONF


def stub_share(share_id):
    share = SdkShare()
    share.id = share_id
    share.size = 1
    share.availability_zone = "nova"
    share.created_at = "2015-09-18T10:25:24.000000"
    share.status = "available"
    share.name = "share_London"
    share.description = "My custom share London"
    share.project_id = "16e1ab15c35a457e9c2b2aa189f544e1"
    share.snapshot_id = None
    share.share_network_id = "713df749-aac0-4a54-af52-10f6c991e80c"
    share.share_protocol = "NFS"
    share.metadata = {
            "project": "my_app",
            "aim": "doc"
        }
    share.share_type = "25747776-08e5-494f-ab40-a64b9d20d8f7"
    share.is_public = True
    share.share_server_id = "e268f4aa-d571-43dd-9ab3-f49ad06ffaef"
    share.host = "manila2@generic1#GENERIC1"

    share.location = Munch(
        {
            "cloud": "envvars",
            "region_name": "RegionOne",
            "zone": "manila-zone-0",
            "project": Munch(
                {
                    "id": "bce4fcc3bd0d4c598f610cb45ec5c5ba",
                    "name": "demo",
                    "domain_id": "default",
                    "domain_name": None,
                }
            ),
        }
    )
    return share


def stub_export_locations():
    export_locations = []
    export_location = SdkExportLocation()
    export_location.id = "b6bd76ce-12a2-42a9-a30a-8a43b503867d"
    export_location.path = (
        "10.0.0.3:/shares/share-e1c2d35e-fe67-4028-ad7a-45f668732b1d"
    )
    export_location.is_preferred = True
    export_location.share_instance_id = (
        "e1c2d35e-fe67-4028-ad7a-45f668732b1d"
    )
    export_location.is_admin = True
    export_location.share_instance_id = "e1c2d35e-fe67-4028-ad7a-45f668732b1d"
    export_location.location = Munch(
        {
            "cloud": "envvars",
            "region_name": "RegionOne",
            "zone": None,
            "project": Munch(
                {
                    "id": "bce4fcc3bd0d4c598f610cb45ec5c5ba",
                    "name": "demo",
                    "domain_id": "default",
                    "domain_name": None,
                }
            ),
        }
    )

    export_locations.append(export_location)
    for item in export_locations:
        yield item


def stub_access_list():
    access_list = []
    access_list.append(stub_access())
    for access in access_list:
        yield access


def stub_access():
    access = SdkAccessRule()
    access.id = "a25b2df3-90bd-4add-afa6-5f0dbbd50452"
    access.access_level = "rw"
    access.access_to = "0.0.0.0/0"
    access.access_type = "ip"
    access.state = "active"
    access.access_key = None
    access.created_at = "2023-07-21T15:20:01.812350"
    access.updated_at = "2023-07-21T15:20:01.812350"
    access.metadata = {}
    access.location = Munch(
        {
            "cloud": "envvars",
            "region_name": "RegionOne",
            "zone": None,
            "project": Munch(
                {
                    "id": "bce4fcc3bd0d4c598f610cb45ec5c5ba",
                    "name": "demo",
                    "domain_id": "default",
                    "domain_name": None,
                }
            ),
        }
    )
    return access


def stub_lock(share_id):
    lock = SdkResourceLock()
    lock.id = "a37b7da7-5d72-49d3-bf3b-aebd64828089"
    lock.project_id = "ded249b25f6f46918fef4e69f427590c"
    lock.resource_type = "share"
    lock.resource_id = share_id
    lock.resource_action = "delete"
    lock.lock_reason = "nova lock"
    lock.created_at = "2023-07-31T09:39:38.441320"
    lock.updated_at = None
    lock.location = Munch(
        {
            "cloud": "envvars",
            "region_name": "RegionOne",
            "zone": None,
            "project": Munch(
                {
                    "id": "bce4fcc3bd0d4c598f610cb45ec5c5ba",
                    "name": "demo",
                    "domain_id": "default",
                    "domain_name": None,
                }
            ),
        }
    )
    return lock


def stub_resource_locks(share_id):
    resource_locks = []
    resource_lock = stub_lock(share_id)
    resource_locks.append(resource_lock)
    for lock in resource_locks:
        yield lock


class BaseManilaTestCase(object):

    def setUp(self):
        super(BaseManilaTestCase, self).setUp()

        self.mock_get_confgrp = self.useFixture(fixtures.MockPatch(
            'nova.utils._get_conf_group')).mock

        self.mock_get_auth_sess = self.useFixture(fixtures.MockPatch(
            'nova.utils._get_auth_and_session')).mock
        self.mock_get_auth_sess.return_value = (None, mock.sentinel.session)

        self.service_type = 'shared-file-system'
        self.mock_connection = self.useFixture(
            fixtures.MockPatch(
                "nova.utils.connection.Connection", side_effect=self.fake_conn
            )
        ).mock

        # We need to stub the CONF global in nova.utils to assert that the
        # Connection constructor picks it up.
        self.mock_conf = self.useFixture(fixtures.MockPatch(
            'nova.utils.CONF')).mock

        self.api = manila.API()

    def fake_conn(self, *args, **kwargs):
        class FakeConnection(object):
            def __init__(self):
                self.shared_file_system = FakeConnectionShareV2Proxy()

        class FakeConnectionShareV2Proxy(object):
            def __init__(self):
                pass

            def get_share(self, share_id):
                if share_id == 'nonexisting':
                    raise sdk_exc.ResourceNotFound
                return stub_share(share_id)

            def export_locations(self, share_id):
                return stub_export_locations()

            def access_rules(self, share_id):
                if share_id == '4567':
                    return []
                return stub_access_list()

            def create_access_rule(self, share_id, **kwargs):
                if share_id == '2345':
                    raise sdk_exc.BadRequestException
                return stub_access()

            def delete_access_rule(self, access_id, share_id, unrestrict):
                res = Response()
                res.status_code = 202
                res.reason = "Internal error"
                if share_id == '2345':
                    res.status_code = 500
                return res

            def get_all_resource_locks(self, resource_id=None):
                if resource_id == '1234':
                    return []
                if resource_id == '2345':
                    return []
                if resource_id == 'nonexisting':
                    return []
                return stub_resource_locks(resource_id)

            def create_resource_lock(
                self, resource_id=None, resource_type=None, lock_reason=None
            ):
                if resource_id == "nonexisting":
                    raise sdk_exc.BadRequestException
                return stub_lock(resource_id)

            def delete_resource_lock(self, share_id):
                pass

        return FakeConnection()

    def create_client(self):
        return manila.manilaclient()

    def test_client(self):
        client = self.create_client()
        self.assertTrue(hasattr(client, 'get_share'))
        self.assertTrue(hasattr(client, 'export_locations'))
        self.assertTrue(hasattr(client, 'access_rules'))
        self.assertTrue(hasattr(client, 'create_access_rule'))
        self.assertTrue(hasattr(client, 'delete_access_rule'))


class ManilaTestCase(BaseManilaTestCase, test.NoDBTestCase):
    def test_get_fails_non_existing_share(self):
        """Tests that we fail if trying to get an
        non existing share.
        """
        self.assertRaises(
            exception.ShareNotFound, self.api.get, "nonexisting"
        )

    def test_get_share(self):
        """Tests that we manage to get a share.
        """
        share = self.api.get('1234')
        self.assertIsInstance(share, manila.Share)
        self.assertEqual('1234', share.id)
        self.assertEqual(1, share.size)
        self.assertEqual('nova', share.availability_zone)
        self.assertEqual('2015-09-18T10:25:24.000000',
                         share.created_at)
        self.assertEqual('available', share.status)
        self.assertEqual('share_London', share.name)
        self.assertEqual('My custom share London',
                         share.description)
        self.assertEqual('16e1ab15c35a457e9c2b2aa189f544e1',
                         share.project_id)
        self.assertIsNone(share.snapshot_id)
        self.assertEqual(
            '713df749-aac0-4a54-af52-10f6c991e80c',
            share.share_network_id)
        self.assertEqual('NFS', share.share_proto)
        self.assertEqual(share.export_location,
                "10.0.0.3:/shares/"
                "share-e1c2d35e-fe67-4028-ad7a-45f668732b1d"
                )
        self.assertEqual({"project": "my_app", "aim": "doc"},
                         share.metadata)
        self.assertEqual(
            '25747776-08e5-494f-ab40-a64b9d20d8f7',
            share.share_type)
        self.assertTrue(share.is_public)

    def test_get_access(self):
        """Tests that we manage to get an access id based on access_type and
        access_to parameters.
        """
        access = self.api.get_access('1234', 'ip', '0.0.0.0/0')

        self.assertEqual('a25b2df3-90bd-4add-afa6-5f0dbbd50452', access.id)
        self.assertEqual('rw', access.access_level)
        self.assertEqual('active', access.state)
        self.assertEqual('ip', access.access_type)
        self.assertEqual('0.0.0.0/0', access.access_to)
        self.assertIsNone(access.access_key)

    def test_get_access_not_existing(self):
        """Tests that we get None if the access id does not exist.
        """
        access = self.api.get_access('1234', 'ip', '192.168.0.1/32')

        self.assertIsNone(access)

    def test_allow_access(self):
        """Tests that we manage to allow access to a share.
        """
        access = self.api.allow('1234', 'ip', '0.0.0.0/0', 'rw')
        self.assertEqual('a25b2df3-90bd-4add-afa6-5f0dbbd50452', access.id)
        self.assertEqual('rw', access.access_level)
        self.assertEqual('active', access.state)
        self.assertEqual('ip', access.access_type)
        self.assertEqual('0.0.0.0/0', access.access_to)
        self.assertIsNone(access.access_key)

    def test_allow_access_fails_already_exists(self):
        """Tests that we have an exception is the share already exists.
        """
        exc = self.assertRaises(
            exception.ShareAccessGrantError,
            self.api.allow,
            '2345',
            'ip',
            '0.0.0.0/0',
            'rw'
        )

        self.assertIn(
            'Share access could not be granted to share',
            exc.message)

    def test_deny_access(self):
        """Tests that we manage to deny access to a share.
        """
        self.api.deny(
            '1234',
            'ip',
            '0.0.0.0/0'
        )

    def test_deny_access_fails_id_missing(self):
        """Tests that we fail if something wrong happens calling deny method.
        """
        exc = self.assertRaises(exception.ShareAccessRemovalError,
                self.api.deny,
                '2345',
                'ip',
                '0.0.0.0/0'
                )

        self.assertIn(
            'Share access could not be removed from',
            exc.message)
        self.assertEqual(
            500,
            exc.code)

    def test_deny_access_fails_access_not_found(self):
        """Tests that we fail if access is missing.
        """
        exc = self.assertRaises(exception.ShareAccessNotFound,
                self.api.deny,
                '4567',
                'ip',
                '0.0.0.0/0'
                )

        self.assertIn(
            'Share access from Manila could not be found',
            exc.message)
        self.assertEqual(
            404,
            exc.code)

    def test_get_lock(self):
        """Tests that we manage to get an lock id based on lock_type and
        lock_to parameters.
        """
        lock = self.api.get_lock('4567')

        self.assertEqual('a37b7da7-5d72-49d3-bf3b-aebd64828089', lock.id)
        self.assertEqual('ded249b25f6f46918fef4e69f427590c', lock.project_id)
        self.assertEqual('share', lock.resource_type)
        self.assertEqual('4567', lock.resource_id)
        self.assertEqual('delete', lock.resource_action)
        self.assertEqual('nova lock', lock.lock_reason)

    def test_get_lock_not_existing(self):
        """Tests that we get None if the lock id does not exist.
        """
        lock = self.api.get_lock('2345')

        self.assertIsNone(lock)

    def test_create_lock(self):
        """Tests that we manage to create a lock to a share.
        """
        lock = self.api.lock('1234')
        self.assertEqual('a37b7da7-5d72-49d3-bf3b-aebd64828089', lock.id)
        self.assertEqual('ded249b25f6f46918fef4e69f427590c', lock.project_id)
        self.assertEqual('share', lock.resource_type)
        self.assertEqual('1234', lock.resource_id)
        self.assertEqual('delete', lock.resource_action)
        self.assertEqual('nova lock', lock.lock_reason)

    def test_create_lock_fails_incorect_resource_id(self):
        """Tests that we have an exception is the share already exists.
        """
        self.assertRaises(
            exception.ShareLockError, self.api.lock, "nonexisting"
        )

    def test_create_lock_fails_already_exists(self):
        """Tests that we have an exception is the lock already exists.
        """
        exc = self.assertRaises(
            exception.ShareLockAlreadyExists,
            self.api.lock,
            '4567',
        )

        self.assertIn("Share lock can not be acquired", exc.message)

    def test_delete_lock(self):
        """Tests that we manage to unlock a share.
        """
        self.api.unlock(
            '4567',
        )

    # def test_delete_lock_fails(self):
    #     """Tests that we fail if something wrong happens calling unlock
    #     method.
    #     """
    #     exc = self.assertRaises(exception.ShareUnlockError,
    #             self.api.unlock,
    #             '1234',
    #             )

    def test_delete_lock_fails_not_found(self):
        """Tests that we fail if lock is missing.
        """
        exc = self.assertRaises(exception.ShareLockNotFound,
                self.api.unlock,
                '1234',
                )

        self.assertIn(
            'Share lock can not be found',
            exc.message)
