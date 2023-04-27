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

    def _check_instance_in_valid_state(self, context, server_id, action):
        instance = self._get_instance_from_server_uuid(context, server_id)
        if (
            (action == "create share" and
             instance.vm_state not in vm_states.STOPPED) or
            (action == "delete share" and
             instance.vm_state not in vm_states.STOPPED and
             instance.vm_state not in vm_states.ERROR)
        ):
            exc = exception.InstanceInvalidState(attr='vm_state',
                                                 instance_uuid=instance.uuid,
                                                 state=instance.vm_state,
                                                 method=action)
            common.raise_http_conflict_for_instance_invalid_state(exc, action,
                                                                  server_id)
        return instance

    @wsgi.Controller.api_version("2.96")
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

                db_shares = objects.ShareMappingList.get_by_instance_uuid(
                        cctxt, server_id
                )

            except (exception.ForbiddenSharesNotSupported) as e:
                raise webob.exc.HTTPForbidden(explanation=e.format_message())
            except (exception.ForbiddenSharesNotConfiguredCorrectly) as e:
                raise webob.exc.HTTPConflict(explanation=e.format_message())

        return self._view_builder._list_view(db_shares)

    @wsgi.Controller.api_version("2.96")
    @wsgi.response(201)
    @wsgi.expected_errors((400, 401, 403, 404, 409, 500))
    @validation.schema(schema.create, min_version='2.96')
    def create(self, req, server_id, body):
        def sm_exists():
            try:
                db_share = (
                    objects.ShareMapping.get_by_instance_uuid_and_share_id(
                        context, server_id, share_id
                    )
                )
                if db_share:
                    return True
            except exception.ShareNotFound:
                return False

        def notify(phase, exception=None):
            try:
                share_mapping
                share_id = share_mapping.share_id
            except NameError:
                share_id = None

            utils.notify_about_share_attach_detach(
                cctxt,
                instance,
                instance.host,
                action=fields.NotificationAction.SHARE_ATTACH,
                phase=phase,
                share_id=share_id,
                exception=exception
            )

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
                if sm_exists():
                    raise exception.ShareMappingAlreadyExists(
                        share_id=share_id)

                manila_share_data = self.manila.get(cctxt, share_id)

                share_mapping = objects.ShareMapping(cctxt)
                share_mapping.uuid = uuidutils.generate_uuid()
                share_mapping.instance_uuid = server_id
                share_mapping.share_id = manila_share_data.id
                share_mapping.status = fields.ShareMappingStatus.INACTIVE
                if share_tag:
                    share_mapping.tag = share_tag
                else:
                    share_mapping.tag = manila_share_data.id
                share_mapping.export_location = (
                    manila_share_data.export_location)
                share_mapping.share_proto = manila_share_data.share_proto

                notify(fields.NotificationPhase.START)

                share_mapping.create()
                self.compute_api.mount_share(cctxt, instance, share_mapping)

                notify(fields.NotificationPhase.END)

                view = self._view_builder._show_view(cctxt, share_mapping)

            except (exception.ShareNotFound) as e:
                notify(fields.NotificationPhase.ERROR, e)
                notify(fields.NotificationPhase.END)
                raise webob.exc.HTTPNotFound(explanation=e.format_message())
            except (exception.ShareMountError) as e:
                notify(fields.NotificationPhase.ERROR, e)
                notify(fields.NotificationPhase.END)
                raise webob.exc.HTTPInternalServerError(
                    explanation=e.filter_format_message())
            except (exception.UnsupportedManilaAPIVersion) as e:
                notify(fields.NotificationPhase.ERROR, e)
                notify(fields.NotificationPhase.END)
                raise webob.exc.HTTPBadRequest(explanation=e.format_message())
            except (exception.ShareMappingAlreadyExists) as e:
                notify(fields.NotificationPhase.ERROR, e)
                notify(fields.NotificationPhase.END)
                raise webob.exc.HTTPBadRequest(explanation=e.format_message())
            except (exception.ForbiddenSharesNotSupported) as e:
                notify(fields.NotificationPhase.ERROR, e)
                notify(fields.NotificationPhase.END)
                raise webob.exc.HTTPForbidden(explanation=e.format_message())
            except (exception.ForbiddenSharesNotConfiguredCorrectly) as e:
                notify(fields.NotificationPhase.ERROR, e)
                notify(fields.NotificationPhase.END)
                raise webob.exc.HTTPConflict(explanation=e.format_message())

        return view

    @wsgi.Controller.api_version("2.96")
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
                share = objects.ShareMapping.get_by_instance_uuid_and_share_id(
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

    @wsgi.Controller.api_version("2.96")
    @wsgi.response(200)
    @wsgi.expected_errors((400, 401, 403, 404, 409, 500))
    def delete(self, req, server_id, id):
        def notify(phase, exception=None):
            try:
                share_mapping
                share_id = share_mapping.share_id
            except NameError:
                share_id = None

            utils.notify_about_share_attach_detach(
                cctxt,
                instance,
                instance.host,
                action=fields.NotificationAction.SHARE_DETACH,
                phase=phase,
                share_id=share_id,
                exception=exception
            )
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
                share_mapping = (
                    objects.ShareMapping.get_by_instance_uuid_and_share_id(
                        cctxt, server_id, id
                    )
                )

                notify(fields.NotificationPhase.START)

                self.compute_api.umount_share(cctxt, instance, share_mapping)

                share_mapping.delete()

                notify(fields.NotificationPhase.END)

            except (exception.ShareNotFound) as e:
                notify(fields.NotificationPhase.ERROR, e)
                notify(fields.NotificationPhase.END)
                raise webob.exc.HTTPNotFound(explanation=e.format_message())
            except (exception.ShareUmountError) as e:
                notify(fields.NotificationPhase.ERROR, e)
                notify(fields.NotificationPhase.END)
                raise webob.exc.HTTPInternalServerError(
                    explanation=e.filter_format_message())
            except (exception.UnsupportedManilaAPIVersion) as e:
                notify(fields.NotificationPhase.ERROR, e)
                notify(fields.NotificationPhase.END)
                raise webob.exc.HTTPBadRequest(explanation=e.format_message())
            except (exception.ForbiddenSharesNotSupported) as e:
                notify(fields.NotificationPhase.ERROR, e)
                notify(fields.NotificationPhase.END)
                raise webob.exc.HTTPForbidden(explanation=e.format_message())
            except (exception.ForbiddenSharesNotConfiguredCorrectly) as e:
                notify(fields.NotificationPhase.ERROR, e)
                notify(fields.NotificationPhase.END)
                raise webob.exc.HTTPConflict(explanation=e.format_message())
