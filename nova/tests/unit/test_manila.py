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

from manilaclient import client as manila_client
from manilaclient.v2 import client as manila_client_v2
from requests_mock.contrib import fixture

import nova.conf
from nova import context
from nova import exception
from nova.share import manila
from nova import test

from unittest import mock

CONF = nova.conf.CONF


class BaseManilaTestCase(object):

    def setUp(self):
        super(BaseManilaTestCase, self).setUp()
        manila.reset_globals()
        self.requests = self.useFixture(fixture.Fixture())

        self.context = context.RequestContext('username',
                                              'project_id',
                                              auth_token='token',
                                              service_catalog=self.CATALOG,
                                             )
        self.api = manila.API()

    def flags(self, *args, **kwargs):
        super(BaseManilaTestCase, self).flags(*args, **kwargs)
        manila.reset_globals()

    def create_client(self, microversion=None):
        return manila.manilaclient(self.context, microversion=microversion)

    def test_client_is_v269_by_default(self):
        client = self.create_client()
        self.assertIsInstance(client, manila_client_v2.Client)
        self.assertEqual('2.69', client.api_version.get_string())

    def test_context_with_catalog(self):
        self.assertEqual(self.URL, self.create_client().client.endpoint_url)

    def test_manila_http_retries(self):
        retries = 42
        self.flags(http_retries=retries, group='manila')
        self.assertEqual(retries, self.create_client().client.retries)

    def test_manila_api_insecure(self):
        # The True/False negation is awkward, but better for the client
        # to pass us insecure=True and we check verify_cert == False
        self.flags(insecure=True, group='manila')
        self.assertFalse(
            self.create_client().client.request_options.get('verify'))

    def test_manila_http_timeout(self):
        timeout = 123
        self.flags(timeout=timeout, group='manila')
        self.assertEqual(
            timeout,
            self.create_client().client.request_options.get('timeout'))

    def test_manila_api_cacert_file(self):
        cacert = "/etc/ssl/certs/ca-certificates.crt"
        self.flags(cafile=cacert, group='manila')
        self.assertEqual(
            cacert,
            self.create_client().client.request_options.get('verify'))


class ManilaTestCase(BaseManilaTestCase, test.NoDBTestCase):

    URL = "http://localhost/share/v2"

    CATALOG = [{
        "type": "sharev2",
        "name": "sharev2",
        "endpoints": [{"publicURL": URL}]
    }]

    def stub_share(self, **kwargs):
        share = {
            "links": [
                {
                    "href": "http://172.18.198.54:8786/v2"
                    "/16e1ab15c35a457e9c2b2aa189f544e1/shares"
                    "/011d21e2-fbc3-4e4a-9993-9ea223f73264",
                    "rel": "self"
                },
                {
                    "href": "http://172.18.198.54:8786"
                    "/16e1ab15c35a457e9c2b2aa189f544e1/shares"
                    "/011d21e2-fbc3-4e4a-9993-9ea223f73264",
                    "rel": "bookmark"
                }
            ],
            "availability_zone": "nova",
            "share_network_id": "713df749-aac0-4a54-af52-10f6c991e80c",
            "export_locations": [],
            "share_server_id": "e268f4aa-d571-43dd-9ab3-f49ad06ffaef",
            "share_group_id": None,
            "snapshot_id": None,
            "id": "011d21e2-fbc3-4e4a-9993-9ea223f73264",
            "size": 1,
            "share_type": "25747776-08e5-494f-ab40-a64b9d20d8f7",
            "share_type_name": "default",
            "export_location": None,
            "project_id": "16e1ab15c35a457e9c2b2aa189f544e1",
            "metadata": {
                "project": "my_app",
                "aim": "doc"
            },
            "status": "available",
            "progress": "100%",
            "description": "My custom share London",
            "host": "manila2@generic1#GENERIC1",
            "user_id": "66ffd308757e44b9a8bec381322b0b88",
            "access_rules_status": "active",
            "has_replicas": False,
            "replication_type": None,
            "task_state": None,
            "is_public": True,
            "snapshot_support": True,
            "name": "share_London",
            "created_at": "2015-09-18T10:25:24.000000",
            "share_proto": "NFS",
            "volume_type": "default"
        }
        share.update(kwargs)
        return share

    def stub_export_locations(self):
        export_locations = [
            {
                "path": "10.254.0.3:/shares/"
                "share-e1c2d35e-fe67-4028-ad7a-45f668732b1d",
                "share_instance_id": "e1c2d35e-fe67-4028-ad7a-45f668732b1d",
                "is_admin_only": False,
                "id": "b6bd76ce-12a2-42a9-a30a-8a43b503867d",
                "preferred": False
            },
            {
                "path": "10.0.0.3:/shares/"
                "share-e1c2d35e-fe67-4028-ad7a-45f668732b1d",
                "share_instance_id": "e1c2d35e-fe67-4028-ad7a-45f668732b1d",
                "is_admin_only": True,
                "id": "6921e862-88bc-49a5-a2df-efeed9acd583",
                "preferred": True
            }
        ]
        return export_locations

    def stub_access_list(self):
        access_list = [
            {
                "access_level": "rw",
                "state": "error",
                "id": "507bf114-36f2-4f56-8cf4-857985ca87c1",
                "access_type": "cert",
                "access_to": "example.com",
                "access_key": None
            },
            {
                "access_level": "rw",
                "state": "active",
                "id": "a25b2df3-90bd-4add-afa6-5f0dbbd50452",
                "access_type": "ip",
                "access_to": "0.0.0.0/0",
                "access_key": None
            }
        ]

        return access_list

    def stub_access(self):
        access = {
            "access_level": "rw",
            "state": "active",
            "id": "a25b2df3-90bd-4add-afa6-5f0dbbd50452",
            "access_type": "ip",
            "access_to": "0.0.0.0/0",
            "access_key": None
        }
        return access

    def test_manilaclient_fails_unsupported_microversion(self):
        """Tests that we fail if trying to use an
        unsupported Manila microversion.
        """
        manila_client.api_versions.discover_version = \
            mock.Mock(
                return_value = manila_client.api_versions.APIVersion('2.67')
            )
        self.assertRaises(
            exception.UnsupportedManilaAPIVersion,
            self.create_client,
            '50.0'
        )

    def test_manilaclient_supported_microversion(self):
        """Tests trying to use a supported microversion
        """
        manila_client.api_versions.discover_version = \
            mock.Mock(
                return_value = manila_client.api_versions.APIVersion('2.67'))
        client = self.create_client('2.67')
        self.assertEqual(
            client.api_version,
            manila_client.api_versions.APIVersion('2.67'))

    def test_get_fails_non_existing_share(self):
        """Tests that we fail if trying to get an
        non existing share.
        """
        self.requests.get(self.URL + '/shares/nonexisting',
                          status_code=404)

        self.assertRaises(exception.ShareNotFound, self.api.get, self.context,
                          'nonexisting')

    def test_get_share(self):
        """Tests that we manage to get a share.
        """
        # Mock share
        s = self.stub_share(id='1234')
        self.requests.get(self.URL + '/shares/1234', json={'share': s})
        # Mock export location
        s = self.stub_export_locations()
        self.requests.get(self.URL + '/shares/1234/export_locations',
                json={'export_locations': s})
        share = self.api.get(self.context, '1234')
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
        self.assertEqual('default', share.volume_type)
        self.assertTrue(share.is_public)

    def test_get_fails_share_without_export_location(self):
        """Tests that we fail if the share does not have a share location."""
        # Mock share
        s = self.stub_share(id='1234')
        self.requests.get(self.URL + '/shares/1234', json={'share': s})
        # Mock export location
        self.requests.get(self.URL + '/shares/1234/export_locations',
                json={'export_locations': []})

        self.assertRaises(
            exception.ShareExportLocationNotFound,
            self.api.get,
            self.context,
            '1234'
        )

    def test_get_access(self):
        """Tests that we manage to get an access id based on access_type and
        access_to parameters.
        """
        # Mock the server api version
        manila_client.api_versions.discover_version = (
            mock.Mock(
                return_value = manila_client.api_versions.APIVersion('2.45'))
        )
        # Mock the share
        s = self.stub_share(id='1234')
        self.requests.get(self.URL + '/shares/1234', json={'share': s})
        # Mock the access_list
        s = self.stub_access_list()
        self.requests.get(self.URL + '/share-access-rules?share_id=1234',
                          json={'access_list': s})
        access = self.api.get_access(
            self.context, '1234', 'ip', '0.0.0.0/0', '2.45')

        self.assertEqual('a25b2df3-90bd-4add-afa6-5f0dbbd50452', access.id)
        self.assertEqual('rw', access.access_level)
        self.assertEqual('active', access.state)
        self.assertEqual('ip', access.access_type)
        self.assertEqual('0.0.0.0/0', access.access_to)
        self.assertIsNone(access.access_key)

    def test_get_access_not_existing(self):
        """Tests that we get None if the access id does not exist.
        """
        # Mock the server api version
        manila_client.api_versions.discover_version = (
            mock.Mock(
                return_value = manila_client.api_versions.APIVersion('2.45'))
        )
        # Mock the share
        s = self.stub_share(id='1234')
        self.requests.get(self.URL + '/shares/1234', json={'share': s})
        # Mock the access_list
        s = self.stub_access_list()
        self.requests.get(self.URL + '/share-access-rules?share_id=1234',
                          json={'access_list': s})
        access = self.api.get_access(
            self.context, '1234', 'ip', '192.168.0.1/32', '2.45')

        self.assertIsNone(access)

    def test_allow_access(self):
        """Tests that we manage to allow access to a share.
        """
        # Mock the share
        s = self.stub_share(id='1234')
        self.requests.get(self.URL + '/shares/1234', json={'share': s})
        # Mock the access_list
        s = self.stub_access()
        self.requests.post(self.URL + '/shares/1234/action',
                          json={'access': s})
        self.api.allow(self.context, '1234', 'ip', '0.0.0.0/0', 'rw')

    def test_allow_access_fails_already_exists(self):
        """Tests that we have an exception is the share already exists.
        """
        # Mock the share
        s = self.stub_share(id='1234')
        self.requests.get(self.URL + '/shares/1234', json={'share': s})
        # Mock the access_list
        s = self.stub_access()
        self.requests.post(
            self.URL + '/shares/1234/action',
            status_code=400,
            headers={'x-compute-request-id':
                     'req-0df3171c-82f5-44b2-8c6b-92a1088e6d1d',
                     'Content-Type': 'application/json'},
            json={'badRequest':
                  {'code': 400, 'message':
                   'Share access ip:192.168.0.1/32 exists.'}},
        )

        exc = self.assertRaises(
            exception.ShareAccessGrantError,
            self.api.allow,
            self.context,
            '1234',
            'ip',
            '0.0.0.0/0',
            'rw'
        )

        self.assertIn(
            'Share access could not be granted to share',
            exc.message)
        self.assertIn(
            'HTTP 400',
            exc.message)

    def test_deny_access(self):
        """Tests that we manage to deny access to a share.
        """
        # Mock the share
        s = self.stub_share(id='1234')
        self.requests.get(self.URL + '/shares/1234', json={'share': s})
        # Mock the access_list
        s = self.stub_access_list()
        self.requests.get(self.URL + '/share-access-rules?share_id=1234',
                          json={'access_list': s})
        # Mock deny response
        s = self.stub_access_list()
        self.requests.post(
                self.URL + '/shares/1234/action',
                [
                    {'json': {'access_list': None}, 'status_code': 202}
                ])

        self.api.deny(
            self.context,
            '1234',
            'ip',
            '0.0.0.0/0'
        )

    def test_deny_access_fails_id_missing(self):
        """Tests that we fail if something wrong happens calling deny method.
        """
        s = self.stub_share(id='1234')
        self.requests.get(self.URL + '/shares/1234', json={'share': s})
        # Mock the access_list
        s = self.stub_access_list()
        self.requests.get(self.URL + '/share-access-rules?share_id=1234',
                          json={'access_list': s})
        # Mock deny response
        s = self.stub_access_list()
        self.requests.post(
                self.URL + '/shares/1234/action',
                [
                    {'status_code': 404}
                ])

        exc = self.assertRaises(exception.ShareAccessRemovalError,
                self.api.deny,
                self.context,
                '1234',
                'ip',
                '0.0.0.0/0'
                )

        self.assertIn(
            'Share access could not be removed from',
            exc.message)
        self.assertIn(
            'HTTP 404',
            exc.message)

    def test_deny_access_fails_access_not_found(self):
        """Tests that we fail if access is missing.
        """
        s = self.stub_share(id='1234')
        self.requests.get(self.URL + '/shares/1234', json={'share': s})
        # Mock the access_list
        s = self.stub_access_list()
        self.requests.get(self.URL + '/share-access-rules?share_id=1234',
                          json={'access_list': []})
        # Mock deny response
        s = self.stub_access_list()
        self.requests.post(
                self.URL + '/shares/1234/action',
                [
                    {'status_code': 404}
                ])

        exc = self.assertRaises(exception.ShareAccessNotFound,
                self.api.deny,
                self.context,
                '1234',
                'ip',
                '0.0.0.0/0'
                )

        self.assertIn(
            'Share access from Manila could not be found',
            exc.message)
