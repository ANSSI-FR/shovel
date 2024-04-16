# Copyright (C) 2024  ANSSI
# SPDX-License-Identifier: CC0-1.0
FROM grafana/grafana-oss:10.1.2
ENV GF_ANALYTICS_CHECK_FOR_PLUGIN_UPDATES=false \
    GF_ANALYTICS_CHECK_FOR_UPDATES=false \
    GF_ANALYTICS_REPORTING_ENABLED=false \
    GF_AUTH_ANONYMOUS_ENABLED=true \
    GF_AUTH_ANONYMOUS_HIDE_VERSION=true \
    GF_INSTALL_PLUGINS=frser-sqlite-datasource \
    GF_DASHBOARDS_DEFAULT_HOME_DASHBOARD_PATH=/var/lib/grafana/dashboards/home.json
COPY ./provisioning /etc/grafana/provisioning
COPY ./dashboards /var/lib/grafana/dashboards
