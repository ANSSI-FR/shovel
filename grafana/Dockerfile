FROM grafana/grafana-oss:10.1.2
ENV GF_ANALYTICS_CHECK_FOR_PLUGIN_UPDATES=false
ENV GF_ANALYTICS_CHECK_FOR_UPDATES=false
ENV GF_ANALYTICS_REPORTING_ENABLED=false
ENV GF_AUTH_ANONYMOUS_ENABLED=true
ENV GF_AUTH_ANONYMOUS_HIDE_VERSION=true
ENV GF_INSTALL_PLUGINS=frser-sqlite-datasource
ENV GF_DASHBOARDS_DEFAULT_HOME_DASHBOARD_PATH=/var/lib/grafana/dashboards/home.json
COPY ./provisioning /etc/grafana/provisioning
COPY ./dashboards /var/lib/grafana/dashboards
