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
    namespace: 'ocpc-35740',
    tenant_label: 'tenant',
    upstream: 'https://thanos-query.ocpc-35740.svc.cluster.local:8480',
    log_level: 'info',
    ns_proxy: {
        name: 'multena-proxy',
        port: 8080,
        keycloak_client_secret: 'TO-BE-SET',
        keycloak_cert_url: 'https://user.apa.at/auth/realms/apa/protocol/openid-connect/certs',
        token_exchange_url: '',
        admin_group: 'IT-Betrieb',
        token_exhange: 'false',
        provider: 'mysql',
    },
    prom_label_proxy:{
        name: 'prom-label-proxy',
        port: 9095,
    }
  },

  ns_proxy: {
      deployment: deployment.new(
        name=$.config.ns_proxy.name,
        replicas=1,
        containers=[
          container.new($.config.ns_proxy.name, 'ghcr.io/lucostus/namespace-proxy:sha-2d87a7b')
          + container.withPorts([port.new('http', $.config.ns_proxy.port)])
          + container.withEnvMap({
            'UPSTREAM_URL': "http://localhost:9095",
            'CLIENT_SECRET': $.config.ns_proxy.keycloak_client_secret,
            'DEV': "false",
            'PROVIDER': $.config.ns_proxy.provider,
            'LOG_LEVEL': $.config.log_level,
            'TENANT_LABEL': $.config.tenant_label,
            'UPSTREAM_BYPASS_URL': $.config.upstream,
            'TOKEN_EXCHANGE': $.config.ns_proxy.token_exhange,
            'TOKEN_EXCHANGE_URL': $.config.ns_proxy.token_exchange_url,
            'KEYCLOAK_CERT_URL': $.config.ns_proxy.keycloak_cert_url,
            'ADMIN_GROUP': $.config.ns_proxy.admin_group,
          }),
          container.new("prom-label-proxy", "ghcr.io/lucostus/prom-label-proxy:multi-value-regex-v0.0.4")
                  + container.withPorts([port.new('http', 9095)])
                  + container.withArgsMixin([
                  '--insecure-listen-address=0.0.0.0:9095',
                  '--upstream='+ $.config.upstream,
                  '--label=' + $.config.tenant_label,
                  '--query-param=' + $.config.tenant_label,
                  '--enable-label-apis',
                  '--error-on-replace'
                  ])
        ],
      )
      + deployment.configVolumeMount('openshift-service-ca', '/etc/ssl/certs/', {}, {configMap: {name: "openshift-service-ca.crt"}}),

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
}