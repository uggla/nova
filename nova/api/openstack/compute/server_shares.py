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

import socket
import webob

from oslo_utils import uuidutils

from nova.api.openstack import common
from nova.api.openstack.compute.schemas import server_shares as schema
from nova.api.openstack.compute.views import server_shares
from nova.api.openstack import wsgi
from nova.api import validation
from nova.compute import api as compute
from nova.compute import utils
from nova.compute import vm_states
from nova import context as nova_context
from nova import exception
from nova import objects
from nova.objects import fields
from nova.objects import share_mapping as sm
from nova.policies import server_shares as ss_policies
from nova.share import manila
from nova.virt import hardware as hw


def _get_instance_mapping(context, server_id):
    try:
        return objects.InstanceMapping.get_by_instance_uuid(context,
                                                            server_id)
    except exception.InstanceMappingNotFound as e:
        raise webob.exc.HTTPNotFound(explanation=e.format_message())


class ServerSharesController(wsgi.Controller):
    _view_builder_class = server_shares.ViewBuilder

    def __init__(self):
        super(ServerSharesController, self).__init__()
        self.compute_api = compute.API()
        self.manila = manila.API()

    def _get_instance_from_server_uuid(self, context, server_id):
        instance = common.get_instance(self.compute_api, context, server_id)
        return instance

    def _get_instance_host_ip(self, context, server_id):
        instance = self._get_instance_from_server_uuid(context, server_id)
        return socket.gethostbyname(instance.host)

    def _check_instance_in_valid_state(self, context, server_id, action):
        instance = self._get_instance_from_server_uuid(context, server_id)
        if (
            instance.vm_state not in vm_states.STOPPED and
            instance.vm_state not in vm_states.ERROR
        ):
            exc = exception.InstanceInvalidState(attr='vm_state',
                                                 instance_uuid=instance.uuid,
                                                 state=instance.vm_state,
                                                 method=action)
            common.raise_http_conflict_for_instance_invalid_state(exc, action,
                                                                  server_id)
        return instance

    @wsgi.Controller.api_version("2.92")
    @wsgi.response(200)
    @wsgi.expected_errors((400, 401, 403, 404, 409))
    def index(self, req, server_id):
        context = req.environ["nova.context"]
        # Get instance mapping to query the required cell database
        im = _get_instance_mapping(context, server_id)
        context.can(ss_policies.POLICY_ROOT % 'index',
                    target={'project_id': im.project_id})

        with nova_context.target_cell(context, im.cell_mapping) as cctxt:
            try:
                instance = self._get_instance_from_server_uuid(
                    cctxt, server_id
                )
                hw.check_shares_supported(cctxt, instance)

                db_shares = sm.ShareMappingList.get_by_instance_uuid(
                        cctxt, server_id
                )

            except (exception.ForbiddenSharesNotSupported) as e:
                raise webob.exc.HTTPForbidden(explanation=e.format_message())
            except (exception.ForbiddenSharesNotConfiguredCorrectly) as e:
                raise webob.exc.HTTPConflict(explanation=e.format_message())

        return self._view_builder._list_view(db_shares)

    @wsgi.Controller.api_version("2.92")
    @wsgi.response(201)
    @wsgi.expected_errors((400, 401, 403, 404, 409))
    @validation.schema(schema.create, min_version='2.92')
    def create(self, req, server_id, body):
        def sm_exists(context, server_id, share_id):
            try:
                db_share = sm.ShareMapping.get_by_instance_uuid_and_share_id(
                    context,
                    server_id,
                    share_id
                )
                if db_share:
                    return True
            except (exception.ShareNotFound):
                return False

        context = req.environ["nova.context"]
        # Get instance mapping to query the required cell database
        im = _get_instance_mapping(context, server_id)
        context.can(
            ss_policies.POLICY_ROOT % 'create',
            target={'project_id': im.project_id}
        )

        share_dict = body['share']
        share_id = share_dict.get('shareId')
        share_tag = share_dict.get('tag')
        with nova_context.target_cell(context, im.cell_mapping) as cctxt:
            instance = self._check_instance_in_valid_state(
                cctxt,
                server_id,
                "create share"
            )

            try:
                hw.check_shares_supported(cctxt, instance)
                # Check if this share mapping already exists in the database.
                # Prevent user error, requesting an already associated share.
                if sm_exists(cctxt, server_id, share_id):
                    raise exception.ShareMappingAlreadyExists(
                        share_id=share_id)

                manila_share_data = self.manila.get(cctxt, share_id)

                db_share = sm.ShareMapping(cctxt)
                db_share.uuid = uuidutils.generate_uuid()
                db_share.instance_uuid = server_id
                db_share.share_id = manila_share_data.id
                db_share.status = 'inactive'
                if share_tag:
                    db_share.tag = share_tag
                else:
                    db_share.tag = manila_share_data.id
                db_share.export_location = manila_share_data.export_location
                db_share.share_proto = manila_share_data.share_proto

                access = self.manila.get_access(
                    cctxt,
                    db_share.share_id,
                    'ip',
                    self._get_instance_host_ip(cctxt, server_id)
                )

                if not access:
                    self.manila.allow(
                        cctxt,
                        db_share.share_id,
                        'ip',
                        self._get_instance_host_ip(cctxt, server_id),
                        'rw'
                )

                utils.notify_about_share_attach_detach(
                    cctxt,
                    instance,
                    instance.host,
                    action=fields.NotificationAction.SHARE_ATTACH,
                    phase=fields.NotificationPhase.START,
                    share_id=db_share.share_id
                )

                db_share.create()

                utils.notify_about_share_attach_detach(
                    cctxt,
                    instance,
                    instance.host,
                    action=fields.NotificationAction.SHARE_ATTACH,
                    phase=fields.NotificationPhase.END,
                    share_id=db_share.share_id
                )
                view = self._view_builder._show_view(cctxt, db_share)

            except (exception.ShareNotFound) as e:
                raise webob.exc.HTTPNotFound(explanation=e.format_message())
            except (exception.UnsupportedManilaAPIVersion) as e:
                raise webob.exc.HTTPBadRequest(explanation=e.format_message())
            except (exception.ShareMappingAlreadyExists) as e:
                raise webob.exc.HTTPBadRequest(explanation=e.format_message())
            except (exception.ForbiddenSharesNotSupported) as e:
                raise webob.exc.HTTPForbidden(explanation=e.format_message())
            except (exception.ForbiddenSharesNotConfiguredCorrectly) as e:
                raise webob.exc.HTTPConflict(explanation=e.format_message())

        return view

    @wsgi.Controller.api_version("2.92")
    @wsgi.response(200)
    @wsgi.expected_errors((400, 401, 403, 404, 409))
    def show(self, req, server_id, id):
        context = req.environ["nova.context"]
        # Get instance mapping to query the required cell database
        im = _get_instance_mapping(context, server_id)
        context.can(
            ss_policies.POLICY_ROOT % 'show',
            target={'project_id': im.project_id}
        )

        with nova_context.target_cell(context, im.cell_mapping) as cctxt:
            try:
                instance = self._get_instance_from_server_uuid(
                    cctxt, server_id
                )
                hw.check_shares_supported(cctxt, instance)
                share = sm.ShareMapping.get_by_instance_uuid_and_share_id(
                    cctxt,
                    server_id,
                    id
                )

                view = self._view_builder._show_view(cctxt, share)

            except (exception.ShareNotFound) as e:
                raise webob.exc.HTTPNotFound(explanation=e.format_message())
            except (exception.ForbiddenSharesNotSupported) as e:
                raise webob.exc.HTTPForbidden(explanation=e.format_message())
            except (exception.ForbiddenSharesNotConfiguredCorrectly) as e:
                raise webob.exc.HTTPConflict(explanation=e.format_message())

        return view

    @wsgi.Controller.api_version("2.92")
    @wsgi.response(200)
    @wsgi.expected_errors((400, 401, 403, 404, 409))
    def delete(self, req, server_id, id):
        context = req.environ["nova.context"]
        # Get instance mapping to query the required cell database
        im = _get_instance_mapping(context, server_id)
        context.can(
            ss_policies.POLICY_ROOT % 'delete',
            target={'project_id': im.project_id}
        )

        with nova_context.target_cell(context, im.cell_mapping) as cctxt:
            instance = self._check_instance_in_valid_state(
                cctxt,
                server_id,
                "delete share"
            )
            try:
                hw.check_shares_supported(cctxt, instance)
                share = (
                    sm.ShareMapping.get_by_instance_uuid_and_share_id(
                    cctxt,
                    server_id,
                    id)
                )

                # Check if this share is used by other VMs
                # If yes, then we should not deny this access
                if len(sm.ShareMappingList.get_by_share_id(
                        cctxt, share.share_id)) < 2:
                    self.manila.deny(
                        cctxt,
                        share.share_id,
                        'ip',
                        self._get_instance_host_ip(cctxt, server_id)
                    )

                utils.notify_about_share_attach_detach(
                    cctxt,
                    instance,
                    instance.host,
                    action=fields.NotificationAction.SHARE_DETACH,
                    phase=fields.NotificationPhase.START,
                    share_id=share.share_id
                )

                share.detach()

                utils.notify_about_share_attach_detach(
                    cctxt,
                    instance,
                    instance.host,
                    action=fields.NotificationAction.SHARE_DETACH,
                    phase=fields.NotificationPhase.END,
                    share_id=share.share_id
                )

            except (exception.ShareNotFound) as e:
                raise webob.exc.HTTPNotFound(explanation=e.format_message())
            except (exception.UnsupportedManilaAPIVersion) as e:
                raise webob.exc.HTTPBadRequest(explanation=e.format_message())
            except (exception.ForbiddenSharesNotSupported) as e:
                raise webob.exc.HTTPForbidden(explanation=e.format_message())
            except (exception.ForbiddenSharesNotConfiguredCorrectly) as e:
                raise webob.exc.HTTPConflict(explanation=e.format_message())
