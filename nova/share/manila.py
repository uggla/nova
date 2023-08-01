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


class Share():
    def __init__(self, manila_share, export_location):
        self.id = manila_share.id
        self.size = manila_share.size
        self.availability_zone = manila_share.availability_zone
        self.created_at = manila_share.created_at
        self.status = manila_share.status
        self.name = manila_share.name
        self.description = manila_share.description
        self.project_id = manila_share.project_id
        self.snapshot_id = manila_share.snapshot_id
        self.share_network_id = manila_share.share_network_id
        self.share_proto = manila_share.share_protocol
        self.export_location = export_location
        self.metadata = manila_share.metadata
        self.share_type = manila_share.share_type
        self.is_public = manila_share.is_public


def from_manila_share(manila_share, export_location):
    return Share(manila_share, export_location)


class Access():

    def __init__(self, manila_access):
        if isinstance(manila_access, dict):
            self.id = manila_access['id']
            self.access_level = manila_access['access_level']
            self.state = manila_access['state']
            self.access_type = manila_access['access_type']
            self.access_to = manila_access['access_to']
            self.access_key = manila_access['access_key']
        else:
            self.id = manila_access.id
            self.access_level = manila_access.access_level
            self.state = manila_access.state
            self.access_type = manila_access.access_type
            self.access_to = manila_access.access_to
            self.access_key = getattr(manila_access, 'access_key', None)


def from_manila_access(manila_access):
    return Access(manila_access)


class Lock():

    def __init__(self, manila_lock):
        self.id = manila_lock.id
        self.project_id = manila_lock.project_id
        self.resource_type = manila_lock.resource_type
        self.resource_id = manila_lock.resource_id
        self.resource_action = manila_lock.resource_action
        self.lock_reason = manila_lock.lock_reason


def from_manila_lock(manila_lock):
    return Lock(manila_lock)


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


def translate_lock_exception(method):
    """Transforms the exception for lock but keeps its traceback intact.
    """

    def wrapper(self, share_id, *args, **kwargs):
        try:
            res = method(self, share_id, *args, **kwargs)
        except (sdk_exc.BadRequestException) as exc:
            raise exception.ShareLockError(
                share_id=share_id, reason=exc) from exc
        return res
    return translate_sdk_exception(wrapper)


def translate_unlock_exception(method):
    """Transforms the exception for unlock but keeps its traceback intact.
    """

    def wrapper(self, share_id, *args, **kwargs):
        try:
            res = method(self, share_id, *args, **kwargs)
        except (sdk_exc.BadRequestException) as exc:
            raise exception.ShareUnlockError(
                share_id=share_id, reason=exc) from exc
        return res
    return translate_sdk_exception(wrapper)


class API(object):
    """API for interacting with the share manager."""

    @translate_share_exception
    def get(self, share_id):
        """Get the details about a share given it's ID.

        :param share_id: the id of the share to get
        :raises: ShareNotFound if the share_id specified is not available.
        :returns: Share object.
        """

        def filter_export_locations(export_locations):
            # Return the prefered path otherwise choose the first one
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

        return from_manila_share(share, export_location)

    @translate_share_exception
    def get_access(self, share_id, access_type, access_to):
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
                return from_manila_access(access)
        return None

    @translate_allow_exception
    def allow(self, share_id, access_type, access_to, access_level):
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

        def check_manila_access_response():
            check = False
            if (
                isinstance(access, Access) and
                access.access_type == access_type and
                access.access_to == access_to and
                access.access_level == access_level
            ):
                check = True
            return check

        LOG.debug("Allow host access to share id:'%s'",
                  share_id)

        access = from_manila_access(
            manilaclient().create_access_rule(
                share_id,
                access_type=access_type,
                access_to=access_to,
                access_level=access_level,
                restrict_visibility=True,
                restrict_deletion=True
            )
        )

        if not check_manila_access_response():
            raise exception.ShareAccessGrantError(share_id=share_id)

        return access

    @translate_deny_exception
    def deny(self, share_id, access_type, access_to):
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
            resp = client.delete_access_rule(
                access.id, share_id, unrestrict=True
            )
            if resp.status_code != 202:
                raise exception.ShareAccessRemovalError(
                    share_id=share_id, reason=resp.reason
                )
        else:
            raise exception.ShareAccessNotFound(share_id=share_id)

    def get_lock(self, share_id):
        """Get share lock

        :param share_id: the id of the share to get
        :returns: lock object or None if there is no lock granted to this
            share.
        """

        LOG.debug("Get share lock id for share id:'%s'",
                  share_id)
        lock_list = []
        lock_generator = manilaclient().get_all_resource_locks(
            resource_id=share_id
        )

        for lock in lock_generator:
            if (
                lock.resource_type == 'share' and
                lock.lock_reason == 'nova lock'
            ):
                lock_list.append(lock)

        if lock_list:
            # Ensure that a share is only locked once by Nova
            assert len(lock_list) == 1
            return from_manila_lock(lock_list[0])
        return None

    @translate_lock_exception
    def lock(self, share_id,):
        """Lock share
        :param share_id: the id of the share
        :raises: ShareLockError if the manila lock API does not
            respond with a status code 202.
        :raises: ShareLockAlreadyExists if the lock is already present.
        """

        lock = self.get_lock(share_id)

        if not lock:
            LOG.debug("Lock share id:'%s'", share_id)
            lock = from_manila_lock(
                manilaclient().create_resource_lock(
                    resource_id=share_id,
                    resource_type="share",
                    lock_reason="nova lock",
                )
            )
            return lock
        raise exception.ShareLockAlreadyExists(share_id=share_id)

    @translate_unlock_exception
    def unlock(self, share_id,):
        """Unlock share
        :param share_id: the id of the share
        :raises: ShareLockNotFound if the access_id specified is not
            available.
        :raises: ShareUnlockError if the manila unlock API does not
            respond with a status code 202.
        """

        lock = self.get_lock(share_id)

        if not lock:
            raise exception.ShareLockNotFound(share_id=share_id)

        LOG.debug("Unlock share id:'%s'", share_id)
        resp = manilaclient().delete_resource_lock(lock.id)

        return resp
