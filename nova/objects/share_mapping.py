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

from abc import ABCMeta
from abc import abstractmethod
import importlib
import logging
from nova.db.main import api as db
from nova.db.main import models
from nova import exception
from nova.objects import base
from nova.objects import fields
from oslo_concurrency import processutils

LOG = logging.getLogger(__name__)


@base.NovaObjectRegistry.register
class ShareMapping(base.NovaPersistentObject, base.NovaObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    fields = {
        'id': fields.IntegerField(read_only=True),
        'uuid': fields.UUIDField(nullable=False),
        'instance_uuid': fields.UUIDField(nullable=False),
        'share_id': fields.UUIDField(nullable=False),
        'status': fields.ShareMappingStatusField(),
        'tag': fields.StringField(nullable=False),
        'export_location': fields.StringField(nullable=False),
        'share_proto': fields.ShareMappingProtoField()
    }

    @staticmethod
    def _from_db_object(context, share_mapping, db_share_mapping):
        for field in share_mapping.fields:
            # TODO(rribaud): Try to refactor object to remove next line
            # Next line is a dirty hack
            if not (field == 'deleted' or field == 'deleted_at'):
                setattr(share_mapping, field, db_share_mapping[field])
        share_mapping._context = context
        share_mapping.obj_reset_changes()
        return share_mapping

    @base.remotable
    def save(self):
        db_share_mapping = db.share_mapping_update(
            self._context, self.uuid, self.instance_uuid, self.share_id,
            self.status, self.tag, self.export_location, self.share_proto)
        self._from_db_object(self._context, self, db_share_mapping)

    def attach(self, status):
        if status == 'inactive':
            LOG.info(
            "Share '%s' about to be attached to instance '%s'.",
                self.share_id, self.instance_uuid)

        elif status == 'active':
            LOG.info(
            "Associate share '%s' to instance '%s'.",
                self.share_id, self.instance_uuid)

        self._change_status(status)

    @base.remotable
    def _change_status(self, status):
        db_share_mapping = db.share_mapping_update(
            self._context, self.uuid, self.instance_uuid, self.share_id,
            status, self.tag, self.export_location, self.share_proto)
        self._from_db_object(self._context, self, db_share_mapping)

    def detach(self, force=False):
        if force:
            LOG.info(
            "Force removal share '%s' from instance '%s'.",
                self.share_id, self.instance_uuid)
            self._detach()
        elif self.status == 'active':
            LOG.info(
            "Share '%s' about to be detached from instance '%s'.",
                self.share_id, self.instance_uuid)
            self._change_status('inactive')
        else:
            LOG.info(
            "Dissociate share '%s' from instance '%s'.",
                self.share_id, self.instance_uuid)
            self._detach()

    @base.remotable
    def _detach(self):
        db.share_mapping_delete_by_instance_uuid_and_share_id(
        self._context, self.instance_uuid, self.share_id)

    @base.remotable_classmethod
    def get_by_instance_uuid_and_share_id(
            cls, context, instance_uuid, share_id):
        share_mapping = ShareMapping(context)
        db_share_mapping = db.share_mapping_get_by_instance_uuid_and_share_id(
            context, instance_uuid, share_id)
        if not db_share_mapping:
            raise exception.ShareNotFound(share_id=share_id)
        # This query should return only one element as a share can be
        # associated only one time to an instance.
        # The REST API prevent the user to create duplicate share mapping by
        # raising an exception.ShareMappingAlreadyExists.
        assert isinstance(db_share_mapping, models.ShareMapping)
        return ShareMapping._from_db_object(
                context,
                share_mapping,
                db_share_mapping)

    def get_share_host_provider(self):
        if not self.export_location:
            return None
        if self.share_proto == 'NFS':
            rhost, rpath = self.export_location.strip().split(':')
        else:
            raise NotImplementedError()
        return rhost


@base.NovaObjectRegistry.register
class ShareMappingList(base.ObjectListBase, base.NovaObject):
    # Version 1.0: Initial version
    VERSION = '1.0'
    fields = {
        'objects': fields.ListOfObjectsField('ShareMapping'),
    }

    @base.remotable_classmethod
    def get_by_instance_uuid(cls, context, instance_uuid):
        db_share_mappings = db.share_mapping_get_by_instance_uuid(
            context, instance_uuid)
        return base.obj_make_list(
            context, cls(context), ShareMapping, db_share_mappings)

    @base.remotable_classmethod
    def get_by_share_id(cls, context, share_id):
        db_share_mappings = db.share_mapping_get_by_share_id(
            context, share_id)
        return base.obj_make_list(
            context, cls(context), ShareMapping, db_share_mappings)


class ShareMappingLibvirtFactory(metaclass=ABCMeta):
    @abstractmethod
    def build(self, context, instance, share_mapping):
        pass


class ShareMappingLibvirtNFSBuilder(ShareMappingLibvirtFactory):
    def build(self, context, instance, share_mapping):
        sm = ShareMappingLibvirtNFS()
        sm.convert(
            context,
            instance,
            share_mapping
        )
        return sm


class ShareMappingLibvirt(ShareMapping, metaclass=ABCMeta):
    @classmethod
    def from_share_mapping(cls, context, instance, share_mapping):
        if share_mapping.share_proto == 'NFS':
            return ShareMappingLibvirtNFSBuilder().build(
                    context,
                    instance,
                    share_mapping)
        else:
            raise exception.ShareProtocolUnknown(
                    share_proto=share_mapping.share_proto)


    def convert(self, context, instance, share_mapping):
        self.context = context
        self.instance = instance
        self.uuid = share_mapping.uuid
        self.instance_uuid = share_mapping.instance_uuid
        self.share_id = share_mapping.share_id
        self.status = share_mapping.status
        self.tag = share_mapping.tag
        self.export_location = share_mapping.export_location
        self.share_proto = share_mapping.share_proto
        # Dynamically import the appropriate module and call the
        # required driver class based on share protocol.
        # e.g. for NFS, call the following class:
        # nova.virt.libvirt.volume.nfs.LibvirtNFSVolumeDriver
        module_object = importlib.import_module(
            'nova.virt.libvirt.volume.' +
            share_mapping.share_proto.lower())
        class_object = getattr(
            module_object, 'Libvirt' +
            share_mapping.share_proto +
            'VolumeDriver')
        self.libvirt_driver = class_object(instance.host)


@base.NovaObjectRegistry.register
class ShareMappingLibvirtNFS(ShareMappingLibvirt):
    def _get_connection_info(self):
        connection_info = {'data': {'export': self.export_location,
                                    'name': self.share_id}}
        return connection_info

    def get_mount_path(self):
        mount_path = self.libvirt_driver._get_mount_path(
                self._get_connection_info())
        return mount_path

    def attach(self, status):
        try:
            self.libvirt_driver.connect_volume(
                    self._get_connection_info(), self.instance)
        except processutils.ProcessExecutionError:
            self._change_status('error')
            raise exception.ShareMountError(share_id=self.share_id)

        super().attach(status)

    def detach(self, force=False):
        try:
            self.libvirt_driver.disconnect_volume(
                    self._get_connection_info(), self.instance)
        except processutils.ProcessExecutionError:
            self._change_status('error')
            raise exception.ShareUmountError(share_id=self.share_id)

        super().detach(force)


class ShareMappingLibvirtCephFS(ShareMappingLibvirt):
    def attach(self, status):
        raise NotImplementedError()

    def detach(self, force=False):
        raise NotImplementedError()
