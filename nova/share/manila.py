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

"""
Handles all requests relating to shares + manila.
"""

from dataclasses import dataclass
import functools

from keystoneauth1 import exceptions as keystone_exception
from openstack import exceptions as sdk_exc
from oslo_log import log as logging
from oslo_utils import encodeutils

import nova.conf
from nova import exception
from nova import utils

CONF = nova.conf.CONF
LOG = logging.getLogger(__name__)


def manilaclient():
    """Constructs a manila client object for making API requests.

    :return: An openstack.proxy.Proxy object for the specified service_type.
    :raise: ConfGroupForServiceTypeNotFound If no conf group name could be
            found for the specified service_type.
    :raise: ServiceUnavailable if the service is down
    """

    return utils.get_sdk_adapter('shared-file-system', check_service=True)


@dataclass(frozen=True)
class Share():
    id: str
    size: int
    availability_zone: str | None
    created_at: str
    status: str
    name: str | None
    description: str | None
    project_id: str
    snapshot_id: str | None
    share_network_id: str | None
    share_proto: str
    export_location: str
    metadata: dict
    share_type: str | None
    is_public: bool

    @classmethod
    def from_manila_share(cls, manila_share, export_location):
        return cls(
            id=manila_share.id,
            size=manila_share.size,
            availability_zone=manila_share.availability_zone,
            created_at=manila_share.created_at,
            status=manila_share.status,
            name=manila_share.name,
            description=manila_share.description,
            project_id=manila_share.project_id,
            snapshot_id=manila_share.snapshot_id,
            share_network_id=manila_share.share_network_id,
            share_proto=manila_share.share_protocol,
            export_location=export_location,
            metadata=manila_share.metadata,
            share_type=manila_share.share_type,
            is_public=manila_share.is_public,
        )


@dataclass(frozen=True)
class Access():
    id: str
    access_level: str
    state: str
    access_type: str
    access_to: str
    access_key: str | None

    @classmethod
    def from_manila_access(cls, manila_access):
        return cls(
            id=manila_access.id,
            access_level=manila_access.access_level,
            state=manila_access.state,
            access_type=manila_access.access_type,
            access_to=manila_access.access_to,
            access_key= getattr(manila_access, 'access_key', None)
        )

    @classmethod
    def from_dict(cls, manila_access):
        return cls(
            id=manila_access['id'],
            access_level=manila_access['access_level'],
            state=manila_access['state'],
            access_type=manila_access['access_type'],
            access_to=manila_access['access_to'],
            access_key=manila_access['access_key'],
        )


def translate_sdk_exception(method):
    """Transforms a manila exception but keeps its traceback intact."""
    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        try:
            res = method(self, *args, **kwargs)
        except (sdk_exc.SDKException,
                keystone_exception.ConnectionError) as exc:
            err_msg = encodeutils.exception_to_unicode(exc)
            raise exception.ManilaConnectionFailed(reason=err_msg) from exc
        except (keystone_exception.BadRequest,
                sdk_exc.BadRequestException) as exc:
            err_msg = encodeutils.exception_to_unicode(exc)
            raise exception.InvalidInput(reason=err_msg) from exc
        except (keystone_exception.Forbidden,
                sdk_exc.ForbiddenException) as exc:
            err_msg = encodeutils.exception_to_unicode(exc)
            raise exception.Forbidden(err_msg) from exc
        return res
    return wrapper


def translate_share_exception(method):
    """Transforms the exception for the share but keeps its traceback intact.
    """

    def wrapper(self, share_id, *args, **kwargs):
        try:
            res = method(self, share_id, *args, **kwargs)
        except (keystone_exception.NotFound, sdk_exc.ResourceNotFound) as exc:
            raise exception.ShareNotFound(
                share_id=share_id, reason=exc) from exc
        return res
    return translate_sdk_exception(wrapper)


def translate_allow_exception(method):
    """Transforms the exception for allow but keeps its traceback intact.
    """

    def wrapper(self, share_id, *args, **kwargs):
        try:
            res = method(self, share_id, *args, **kwargs)
        except (sdk_exc.BadRequestException) as exc:
            raise exception.ShareAccessGrantError(
                share_id=share_id, reason=exc) from exc
        return res
    return translate_sdk_exception(wrapper)


def translate_deny_exception(method):
    """Transforms the exception for deny but keeps its traceback intact.
    """

    def wrapper(self, share_id, *args, **kwargs):
        try:
            res = method(self, share_id, *args, **kwargs)
        except (sdk_exc.BadRequestException) as exc:
            raise exception.ShareAccessRemovalError(
                share_id=share_id, reason=exc) from exc
        return res
    return translate_sdk_exception(wrapper)


class API(object):
    """API for interacting with the share manager."""

    @translate_share_exception
    def get(self, share_id):
        """Get the details about a share given its ID.

        :param share_id: the id of the share to get
        :raises: ShareNotFound if the share_id specified is not available.
        :returns: Share object.
        """

        def filter_export_locations(export_locations):
            # Return the preferred path otherwise choose the first one
            paths = []
            for export_location in export_locations:
                if export_location.is_preferred:
                    return export_location.path
                else:
                    paths.append(export_location.path)
            return paths[0]

        client = manilaclient()
        LOG.debug("Get share id:'%s' data from manila", share_id)
        share = client.get_share(share_id)
        export_locations = client.export_locations(share.id)
        export_location = filter_export_locations(export_locations)

        return Share.from_manila_share(share, export_location)

    @translate_share_exception
    def get_access(
        self,
        share_id,
        access_type,
        access_to,
    ):
        """Get share access

        :param share_id: the id of the share to get
        :param access_type: the type of access ("ip", "cert", "user")
        :param access_to: ip:cidr or cert:cn or user:group or user name
        :raises: ShareNotFound if the share_id specified is not available.
        :returns: Access object or None if there is no access granted to this
            share.
        """

        LOG.debug("Get share access id for share id:'%s'",
                  share_id)
        access_list = manilaclient().access_rules(share_id)

        for access in access_list:
            if (
                access.access_type == access_type and
                access.access_to == access_to
            ):
                return Access.from_manila_access(access)
        return None

    @translate_allow_exception
    def allow(
        self,
        share_id,
        access_type,
        access_to,
        access_level,
    ):
        """Allow share access

        :param share_id: the id of the share
        :param access_type: the type of access ("ip", "cert", "user")
        :param access_to: ip:cidr or cert:cn or user:group or user name
        :param access_level: "ro" for read only or "rw" for read/write
        :raises: ShareNotFound if the share_id specified is not available.
        :raises: BadRequest if the share already exists.
        :raises: ShareAccessGrantError if the answer from manila allow API is
            not the one expected.
        """

        def check_manila_access_response(access):
            if not (
                isinstance(access, Access) and
                access.access_type == access_type and
                access.access_to == access_to and
                access.access_level == access_level
            ):
                raise exception.ShareAccessGrantError(share_id=share_id)

        LOG.debug("Allow host access to share id:'%s'",
                  share_id)

        access = manilaclient().create_access_rule(
            share_id,
            access_type=access_type,
            access_to=access_to,
            access_level=access_level,
            restrict_visibility=True,
            restrict_deletion=True,
        )

        access = Access.from_manila_access(access)
        check_manila_access_response(access)
        return access

    @translate_deny_exception
    def deny(
        self,
        share_id,
        access_type,
        access_to,
    ):
        """Deny share access
        :param share_id: the id of the share
        :param access_type: the type of access ("ip", "cert", "user")
        :param access_to: ip:cidr or cert:cn or user:group or user name
        :raises: ShareAccessNotFound if the access_id specified is not
            available.
        :raises: ShareAccessRemovalError if the manila deny API does not
            respond with a status code 202.
        """

        client = manilaclient()

        access = self.get_access(
            share_id,
            access_type,
            access_to,
            )

        if access:
            LOG.debug("Deny host access to share id:'%s'", share_id)
            resp = client.delete_access_rule(access.id, share_id)
            if resp.status_code != 202:
                raise exception.ShareAccessRemovalError(
                    share_id=share_id, reason=resp.reason
                )
        else:
            raise exception.ShareAccessNotFound(share_id=share_id)
