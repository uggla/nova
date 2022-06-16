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

import fixtures
from oslo_config import cfg
from oslo_log import log as logging


CONF = cfg.CONF
LOG = logging.getLogger(__name__)


class ManilaFixture(fixtures.Fixture):
    """Fixture that mocks Manila APIs used by nova/share/manila.py"""

    def setUp(self):
        super().setUp()
        self.mock_get = self.useFixture(fixtures.MockPatch(
            'nova.share.manila.API.get',
            side_effect=self.fake_get)).mock
        self.mock_get = self.useFixture(fixtures.MockPatch(
            'nova.share.manila.API.get_access_id',
            side_effect=self.fake_get_access_id)).mock
        self.mock_get = self.useFixture(fixtures.MockPatch(
            'nova.share.manila.API.allow',
            side_effect=self.fake_allow)).mock
        self.mock_get = self.useFixture(fixtures.MockPatch(
            'nova.share.manila.API.deny',
            side_effect=self.fake_deny)).mock

    def fake_get(self, context, share_id):
        d = {}
        d['id'] = share_id
        d['size'] = 1
        d['availability_zone'] = "nova"
        d['created_at'] = "2015-09-18T10:25:24.000000"
        d['status'] = "available"
        d['name'] = "share_London"
        d['description'] = "My custom share London"
        d['project_id'] = "6a6a9c9eee154e9cb8cec487b98d36ab"
        d['snapshot_id'] = None
        d['share_network_id'] = "713df749-aac0-4a54-af52-10f6c991e80c"
        d['share_proto'] = "NFS"
        d['export_location'] = "10.0.0.50:/mnt/foo"
        d['metadata'] = {
            "project": "my_app",
            "aim": "doc"
        }
        d['share_type'] = "25747776-08e5-494f-ab40-a64b9d20d8f7"
        d['volume_type'] = "default"
        d['is_public'] = True
        return d

    def fake_get_access_id(self, context, share_id, access_type, access_to,):
        return None

    def fake_allow(self, context, share_id, access_type, access_to,
            access_level, microversion=None):
        access = {
            "access_level": "rw",
            "state": "active",
            "id": "a25b2df3-90bd-4add-afa6-5f0dbbd50452",
            "access_type": "ip",
            "access_to": "compute",
            "access_key": None
        }
        return access

    def fake_deny(self, context, share_id, access_type, access_to,
            microversion=None):
        pass
