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

from keystoneauth1 import loading as ks_loading
from oslo_config import cfg

from nova.conf import utils as confutils

DEFAULT_SERVICE_TYPE = 'shared-file-system'

manila_group = cfg.OptGroup(
    'manila',
    title='Manila Options',
    help="Configuration options for the share service")

manila_opts = [
    cfg.StrOpt('catalog_info',
            default='sharev2::publicURL',
            regex=r'^\w+:\w*:.*$',
            help="""
Info to match when looking for manila in the service catalog.

The ``<service_name>`` is optional and omitted by default since it should
not be necessary in most deployments.

Possible values:

* Format is separated values of the form:
  <service_type>:<service_name>:<endpoint_type>

Related options:

* endpoint_template - Setting this option will override catalog_info
"""),
    cfg.StrOpt('endpoint_template',
               help="""
If this option is set then it will override service catalog lookup with
this template for manila endpoint

Possible values:

* URL for manila endpoint API
  e.g. http://localhost:8776/v3/%(project_id)s

Related options:

* catalog_info - If endpoint_template is not set, catalog_info will be used.
"""),
    cfg.StrOpt('os_region_name',
               help="""
Region name of this node. This is used when picking the URL in the service
catalog.

Possible values:

* Any string representing region name
"""),
    cfg.IntOpt('http_retries',
               default=3,
               min=0,
               help="""
Number of times manilaclient should retry on any failed http call.
0 means connection is attempted only once. Setting it to any positive integer
means that on failure connection is retried that many times e.g. setting it
to 3 means total attempts to connect will be 4.

Possible values:

* Any integer value. 0 means connection is attempted only once
"""),
    cfg.IntOpt('action_timeout',
               default=30,
               help="""
Maximum amount of time that a function or method should wait for a response
from the Manila service before timing out.

Possible values:

* A positive integer or 0 (default value is 60).
"""),
    cfg.BoolOpt('debug',
        default=False,
        help="""
Enable DEBUG logging with manilaclient independently of the rest
of Nova.
"""),
]


def register_opts(conf):
    conf.register_group(manila_group)
    conf.register_opts(manila_opts, group=manila_group)
    ks_loading.register_session_conf_options(conf,
                                             manila_group.name)
    ks_loading.register_auth_conf_options(conf, manila_group.name)

    confutils.register_ksa_opts(conf, manila_group, DEFAULT_SERVICE_TYPE)


def list_opts():
    return {
        manila_group.name: (
            manila_opts +
            ks_loading.get_session_conf_options() +
            ks_loading.get_auth_common_conf_options() +
            ks_loading.get_auth_plugin_conf_options('v3password'))
    }
