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
from keystoneauth1 import loading as ks_loading
from manilaclient import client as manila_client
from manilaclient import exceptions as manila_exception
from oslo_log import log as logging
from oslo_utils import encodeutils

import nova.conf
from nova import exception
from nova.i18n import _
from nova import service_auth


CONF = nova.conf.CONF

LOG = logging.getLogger(__name__)

_ADMIN_AUTH = None
_SESSION = None


def reset_globals():
    """Testing method to reset globals.
    """
    global _ADMIN_AUTH
    global _SESSION

    _ADMIN_AUTH = None
    _SESSION = None


def _load_auth_plugin(conf):
    auth_plugin = ks_loading.load_auth_from_conf_options(
        conf, nova.conf.manila.manila_group.name)

    if auth_plugin:
        return auth_plugin

    if conf.manila.auth_type is None:
        LOG.error('The [manila] section of your nova configuration file '
                  'must be configured for authentication with the '
                  'share service endpoint.')
    err_msg = _('Unknown auth type: %s') % conf.manila.auth_type
    raise manila_exception.Unauthorized(401, message=err_msg)


def _load_session():
    global _SESSION

    if not _SESSION:
        _SESSION = ks_loading.load_session_from_conf_options(
            CONF, nova.conf.manila.manila_group.name)


def _get_auth(context):
    global _ADMIN_AUTH
    # NOTE(lixipeng): Auth token is none when call
    # manila API from compute periodic tasks, context
    # from them generated from 'context.get_admin_context'
    # which only set is_admin=True but is without token.
    # So add load_auth_plugin when this condition appear.
    if context.is_admin and not context.auth_token:
        if not _ADMIN_AUTH:
            _ADMIN_AUTH = _load_auth_plugin(CONF)
        return _ADMIN_AUTH
    else:
        return service_auth.get_auth_plugin(context)


def _get_manilaclient_parameters(context):
    _load_session()

    auth = _get_auth(context)

    url = None

    service_type, service_name, interface = CONF.manila.catalog_info.split(':')

    service_parameters = {'service_type': service_type,
                          'interface': interface,
                          'region_name': CONF.manila.os_region_name}
    # Only include the service_name if it's provided.
    if service_name:
        service_parameters['service_name'] = service_name

    if CONF.manila.endpoint_template:
        url = CONF.manila.endpoint_template % context.to_dict()
    else:
        url = _SESSION.get_endpoint(auth, **service_parameters)

    return auth, service_parameters, url


def manilaclient(context, microversion=None, skip_version_check=False,
                 check_only=False):
    """Constructs a manila client object for making API requests.

    :param context: The nova request context for auth.
    :param microversion: Optional microversion to check against the client.
        This implies that Manila v2 is required for any calls that require a
        microversion. If the microversion is not available, this method will
        raise an UnsupportedManilaAPIVersion exception.
    :param skip_version_check: If True and a specific microversion is
        requested, the version discovery check is skipped and the microversion
        is used directly. This should only be used if a previous check for the
        same microversion was successful.
    :param check_only: If True, don't build the actual client; just do the
        setup and version checking.
    :raises: UnsupportedManilaAPIVersion if a version requested is not
        supported.
    :returns: A manilaclient.client.Client wrapper, unless check_only is False.
    """

    auth, service_parameters, url = _get_manilaclient_parameters(context)

    # Version 1 is deprecated so use the version 2.
    # The current release (Yoga) of client and server uses 2.69.
    # So we try to use that version as a minimum.
    # Check if version 2.69 is supported by client.
    version = manila_client.api_versions.APIVersion('2.69')

    if not manila_client.api_versions.check_version_supported(version):
        raise exception.UnsupportedManilaAPIVersion(version=version)

    # Start a version 2.69 client to check version available on server.
    client = manila_client.Client(
        version,
        session=_SESSION,
        auth=auth,
        retries=CONF.manila.http_retries,
        insecure=CONF.manila.insecure,
        timeout=CONF.manila.timeout,
        cacert=CONF.manila.cafile,
        global_request_id=context.global_id,
        **service_parameters
    )

    # Check to see a specific microversion is requested and if so, can it
    # be handled by the backing server.
    if microversion is not None:
        if skip_version_check:
            version = manila_client.api_versions.APIVersion(microversion)
        else:
            microversion = manila_client.api_versions.APIVersion(microversion)
            srv_version = (
                manila_client.api_versions.discover_version(client, version)
            )
            if microversion != srv_version:
                raise exception.UnsupportedManilaAPIVersion(version=version)
            version = srv_version

    if check_only:
        return

    return manila_client.Client(
        version,
        session=_SESSION,
        auth=auth,
        retries=CONF.manila.http_retries,
        insecure=CONF.manila.insecure,
        timeout=CONF.manila.timeout,
        cacert=CONF.manila.cafile,
        global_request_id=context.global_id,
        **service_parameters
    )


class Share():
    @classmethod
    def from_manila_share(cls, manila_share, export_location):
        share = cls()
        share.id = manila_share.id
        share.size = manila_share.size
        share.availability_zone = manila_share.availability_zone
        share.created_at = manila_share.created_at
        share.status = manila_share.status
        share.name = manila_share.name
        share.description = manila_share.description
        share.project_id = manila_share.project_id
        share.snapshot_id = manila_share.snapshot_id
        share.share_network_id = manila_share.share_network_id
        share.share_proto = manila_share.share_proto
        share.export_location = export_location
        share.metadata = manila_share.metadata
        share.share_type = manila_share.share_type
        share.volume_type = manila_share.volume_type
        share.is_public = manila_share.is_public
        return share


class Access():
    @classmethod
    def from_manila_access(cls, manila_access):
        access = cls()
        if isinstance(manila_access, dict):
            access.id = manila_access['id']
            access.access_level = manila_access['access_level']
            access.state = manila_access['state']
            access.access_type = manila_access['access_type']
            access.access_to = manila_access['access_to']
            access.access_key = manila_access['access_key']
        else:
            access.id = manila_access.id
            access.access_level = manila_access.access_level
            access.state = manila_access.state
            access.access_type = manila_access.access_type
            access.access_to = manila_access.access_to
            access.access_key = getattr(manila_access, 'access_key', None)
        return access


def translate_manila_exception(method):
    """Transforms a manila exception but keeps its traceback intact."""
    @functools.wraps(method)
    def wrapper(self, ctx, *args, **kwargs):
        try:
            res = method(self, ctx, *args, **kwargs)
        except (manila_exception.ConnectionError,
                keystone_exception.ConnectionError) as exc:
            err_msg = encodeutils.exception_to_unicode(exc)
            raise exception.ManilaConnectionFailed(reason=err_msg) from exc
        except (keystone_exception.BadRequest,
                manila_exception.BadRequest) as exc:
            err_msg = encodeutils.exception_to_unicode(exc)
            raise exception.InvalidInput(reason=err_msg) from exc
        except (keystone_exception.Forbidden,
                manila_exception.Forbidden) as exc:
            err_msg = encodeutils.exception_to_unicode(exc)
            raise exception.Forbidden(err_msg) from exc
        return res
    return wrapper


def translate_share_exception(method):
    """Transforms the exception for the share but keeps its traceback intact.
    """

    def wrapper(self, ctx, share_id, *args, **kwargs):
        try:
            res = method(self, ctx, share_id, *args, **kwargs)
        except (keystone_exception.NotFound, manila_exception.NotFound) as exc:
            raise exception.ShareNotFound(
                share_id=share_id, reason=exc) from exc
        return res
    return translate_manila_exception(wrapper)


def translate_allow_exception(method):
    """Transforms the exception for allow but keeps its traceback intact.
    """

    def wrapper(self, ctx, share_id, *args, **kwargs):
        try:
            res = method(self, ctx, share_id, *args, **kwargs)
        except (manila_exception.ClientException) as exc:
            raise exception.ShareAccessGrantError(
                share_id=share_id, reason=exc) from exc
        return res
    return translate_manila_exception(wrapper)


def translate_deny_exception(method):
    """Transforms the exception for deny but keeps its traceback intact.
    """

    def wrapper(self, ctx, share_id, *args, **kwargs):
        try:
            res = method(self, ctx, share_id, *args, **kwargs)
        except (manila_exception.ClientException) as exc:
            raise exception.ShareAccessRemovalError(
                share_id=share_id, reason=exc) from exc
        return res
    return translate_manila_exception(wrapper)


class API(object):
    """API for interacting with the share manager."""

    @translate_share_exception
    def get(self, context, share_id, microversion=None):
        """Get the details about a share given it's ID.

        :param context: the nova request context
        :param share_id: the id of the share to get
        :param microversion: optional string microversion value
        :raises: UnsupportedManilaAPIVersion if the specified microversion is
        :raises: ShareNotFound if the share_id specified is not available.
        :returns: Share object.
        """

        def filter_export_locations(export_locations):
            # Return the prefered path otherwise choose the first one
            for export_location in export_locations:
                if export_location.preferred:
                    return export_location.path
            return export_locations[0].path

        client = manilaclient(context, microversion=microversion)
        LOG.debug("Get share id:'%s' data from manila", share_id)
        share = client.shares.get(share_id)
        export_locations = client.share_export_locations.list(share_id)
        if export_locations:
            export_location = filter_export_locations(export_locations)
        else:
            raise exception.ShareExportLocationNotFound(share_id=share_id)

        return Share.from_manila_share(share, export_location)

    @translate_share_exception
    def get_access(
        self,
        context,
        share_id,
        access_type,
        access_to,
        microversion=None
    ):
        """Get share access

        :param context: the nova request context
        :param share_id: the id of the share to get
        :param access_type: the type of access ("ip", "cert", "user")
        :param access_to: ip:cidr or cert:cn or user:group or user name
        :param microversion: optional string microversion value
        :raises: UnsupportedManilaAPIVersion if the specified microversion is
        :raises: ShareNotFound if the share_id specified is not available.
        :returns: Access object or None if there is no access granted to this
            share.
        """

        LOG.debug("Get share access id for share id:'%s'",
                  share_id)
        access_list = manilaclient(
            context,
            microversion=microversion
        ).share_access_rules.access_list(share_id)

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
        context,
        share_id,
        access_type,
        access_to,
        access_level,
        microversion=None
    ):
        """Allow share access

        :param context: the nova request context
        :param share_id: the id of the share
        :param access_type: the type of access ("ip", "cert", "user")
        :param access_to: ip:cidr or cert:cn or user:group or user name
        :param access_level: "ro" for read only or "rw" for read/write
        :param microversion: optional string microversion value
        :raises: UnsupportedManilaAPIVersion if the specified microversion is
            not supported
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

        share = manilaclient(
            context,
            microversion=microversion).shares.get(share_id)

        LOG.debug("Allow host access to share id:'%s'",
                  share_id)

        # A dict is return from the manila API not an object so we need to
        # convert it to an Access object.
        access = Access.from_manila_access(
            share.allow(
                access_type=access_type,
                access=access_to,
                access_level=access_level
            )
        )

        if not check_manila_access_response():
            raise exception.ShareAccessGrantError(share_id=share_id)

    @translate_deny_exception
    def deny(
        self,
        context,
        share_id,
        access_type,
        access_to,
        microversion=None
    ):
        """Deny share access
        :param context: the nova request context
        :param share_id: the id of the share
        :param access_type: the type of access ("ip", "cert", "user")
        :param access_to: ip:cidr or cert:cn or user:group or user name
        :param microversion: optional string microversion value
        :raises: UnsupportedManilaAPIVersion if the specified microversion is
        :raises: ShareAccessNotFound if the access_id specified is not
            available.
        :raises: ShareAccessRemovalError if the manila deny API does not
            respond with a status code 202.
        """

        share = manilaclient(
            context,
            microversion=microversion).shares.get(share_id)

        access = self.get_access(
            context,
            share_id,
            access_type,
            access_to,
            microversion=microversion)

        if access:
            LOG.debug("Deny host access to share id:'%s'",
                      share_id)
            # A tuple is returned by client with HTTP response as first
            # element.
            (resp, _) = share.deny(access.id)
            if resp.status_code != 202:
                raise exception.ShareAccessRemovalError(share_id=share_id)
        else:
            raise exception.ShareAccessNotFound(share_id=share_id)
