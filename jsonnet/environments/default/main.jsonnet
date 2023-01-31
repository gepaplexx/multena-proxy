local k = import 'github.com/grafana/jsonnet-libs/ksonnet-util/kausal.libsonnet';
{
    local deployment = k.apps.v1.deployment,
    local container = k.core.v1.container,
    local securityContext = k.core.v1.securityContext,
    local port = k.core.v1.containerPort,
    local service = k.core.v1.service,
    local sa = k.core.v1.serviceAccount,
    local rbac = k.rbac.v1.clusterRoleBinding,

  config+:: {
    namespace: 'grrr',
    ns_proxy: {
        name: 'ns-proxy',
        port: 8080,
        keycloak_client_secret: 'secret',
        keycloak_cert_url: 'https://sso.apps.play.gepaplexx.com/realms/internal/protocol/openid-connect/certs',
        admin_group: 'Gepaplexx',
        token_exhange: 'false',
        bypass_url: 'https://thanos-querier.openshift-monitoring.svc.cluster.local:9091',
    },
    prom_label_proxy:{
        name: 'prom-label-proxy',
        upstream_url: 'https://thanos-querier.openshift-monitoring.svc.cluster.local:9091',
        label: 'namespace',
        port: 9095,
    }
  },

  ns_proxy: {
      deployment: deployment.new(
        name=$.config.ns_proxy.name,
        replicas=1,
        containers=[
          container.new($.config.ns_proxy.name, 'ghcr.io/lucostus/namespace-proxy:uff-v0.0.1')
          + container.withPorts([port.new('http', $.config.ns_proxy.port)])
          + container.withEnvMap({
            'UPSTREAM_URL': "http://"+$.prom_label_proxy.service.metadata.name+"."+$.config.namespace+".svc.cluster.local:"+$.config.prom_label_proxy.port,
            'CLIENT_SECRET': $.config.ns_proxy.keycloak_client_secret,
            'DEV': "false",
            'UPSTREAM_BYPASS_URL': $.config.ns_proxy.bypass_url,
            'TOKEN_EXCHANGE': $.config.ns_proxy.token_exhange,
            'KEYCLOAK_CERT_URL': $.config.ns_proxy.keycloak_cert_url,
            'ADMIN_GROUP': $.config.ns_proxy.admin_group,
          })
//          + securityContext.capabilities.withAdd("SYS_PTRACE")
        ],
      ),
      service:
        k.util.serviceFor($.ns_proxy.deployment)
        + service.mixin.spec.withType('ClusterIP'),

      service_account:
        sa.new($.config.ns_proxy.name)
        + sa.withAutomountServiceAccountToken(true),

      role_bindings: [
      rbac.new($.config.ns_proxy.name+"-cluster-monitoring-view")
      + rbac.bindRole({
                          metadata: {name: 'cluster-monitoring-view'},
                          kind: 'ClusterRole',
                          apiVersion: 'rbac.authorization.k8s.io/v1',
                        })
      + rbac.withSubjects({kind: 'ServiceAccount', name: $.config.ns_proxy.name, namespace: $.config.namespace}),
      rbac.new($.config.ns_proxy.name+"-role-binding-access")
            + rbac.bindRole({
                                metadata: {name: 'system:openshift:controller:default-rolebindings-controller'},
                                kind: 'ClusterRole',
                                apiVersion: 'rbac.authorization.k8s.io/v1',
                              })
            + rbac.withSubjects({kind: 'ServiceAccount', name: $.config.ns_proxy.name, namespace: $.config.namespace})
      ]
    },

  prom_label_proxy: {
        deployment: deployment.new(name=$.config.prom_label_proxy.name, replicas=1, containers=[
        container.new("prom-label-proxy", "ghcr.io/lucostus/prom-label-proxy:multi-value-regex-v0.0.4")
        + container.withPorts([port.new('http', 9095)])
        + container.withArgsMixin([
        '--insecure-listen-address=0.0.0.0:9095',
        '--upstream='+ $.config.prom_label_proxy.upstream_url,
        '--label='+ $.config.prom_label_proxy.label,
        '--enable-label-apis',
        '--error-on-replace'
        ])])
        + deployment.configVolumeMount('openshift-service-ca', '/etc/ssl/certs/'),
        service:
                k.util.serviceFor($.prom_label_proxy.deployment)
                + service.mixin.spec.withType('ClusterIP'),
  },
}