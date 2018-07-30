apt-get update
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
apt-get -y install apt-transport-https software-properties-common dirmngr curl ethtool

echo "deb https://artifacts.elastic.co/packages/6.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-6.x.list
apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys EEA14886
add-apt-repository -y ppa:webupd8team/java

apt-get update
apt-get -y install oracle-java8-installer apache2
apt-get -y install elasticsearch logstash kibana

setcap cap_net_bind_service=+epi /usr/lib/jvm/java-8-oracle/jre/bin/java

/usr/share/logstash/bin/logstash-plugin install logstash-input-syslog
/usr/share/logstash/bin/logstash-plugin install logstash-output-syslog

cat <<EOT >> /etc/logstash/conf.d/10-ftics-input.conf
input {
  syslog {
    port => 514
    codec => plain
    syslog_field => "syslog"
  }
}
EOT

cat <<EOT >> /etc/logstash/conf.d/50-filter-fticks.conf
filter{
  mutate{
    remove_tag => [ "_grokparsefailure_sysloginput" ]
  }
  grok{
    match => [ "message", "(<%{POSINT:priority1}>%{SYSLOGTIMESTAMP:timestamp1} %{GREEDYDATA:hostname1})?<%{POSINT:priority}>%{SYSLOGTIMESTAMP:timestamp} %{GREEDYDATA:hostname} (%{GREEDYDATA:appname} )?\[%{GREEDYDATA:process}\](\:)? %{GREEDYDATA:syslog_message}" ]
  }
  if "_grokparsefailure" in [tags] {
    mutate{
      remove_tag => [ "_grokparsefailure" ]
      add_tag => [ "not_ftick" ]
    }
  }
  grok{
    match => [ "syslog_message", "(%{GREEDYDATA:bean} )?F-TICKS/%{GREEDYDATA:federation}/%{GREEDYDATA:version}[#]TS=%{GREEDYDATA:TS}[#]RP=%{GREEDYDATA:RP}[#]AP=%{GREEDYDATA:AP}[#]PN=%{GREEDYDATA:PN}([#]CSI=%{GREEDYDATA:CSI})?([#]AM=%{GREEDYDATA:AM})?([#]RESULT=%{GREEDYDATA:RESULT})?[#]" ]
  }
  if "_grokparsefailure" in [tags] {
    mutate{
      remove_tag => [ "_grokparsefailure" ]
    }
    grok{
      match => [ "syslog_message", "(%{GREEDYDATA:bean} )?F-TICKS/%{GREEDYDATA:federation}/%{GREEDYDATA:version}[#]RESULT=%{GREEDYDATA:RESULT}([#]CSI=%{GREEDYDATA:CSI})?[#]AP=%{GREEDYDATA:AP}[#]RP=%{GREEDYDATA:RP}[#]PN=%{GREEDYDATA:PN}[#]TS=%{GREEDYDATA:TS}[#]" ]
    }
  }
  grok {
     match => [ "RP", "(%{URIPROTO:RP_uri_proto}://(?:%{USER:RP_user}(?::[^@]*)?@)?)?(?:%{URIHOST:RP_uri_domain})?(?:%{URIPATHPARAM:RP_uri_param})?" ]
  }
  grok {
     match => [ "AP", "(%{URIPROTO:AP_uri_proto}://(?:%{USER:AP_user}(?::[^@]*)?@)?)?(?:%{URIHOST:AP_uri_domain})?(?:%{URIPATHPARAM:AP_uri_param})?" ]
  }
  geoip {
     source => "AP_uri_domain"
     target => "AP_geoip"
  }
  geoip {
     source => "RP_uri_domain"
     target => "RP_geoip"
  }
}
EOT

cat <<EOT >> /etc/logstash/conf.d/90-fticks-output.conf
output {
  if "metrics" not in [tags] {
    file {
      path => "/var/log/logstash/fticks.out"
      codec => line { format => "%{message}"}
    }
    elasticsearch {
      id => "fticks"
      hosts => [ "localhost:9200" ]
      index => "fticks"
      template_name => "fticks_template"
#      template => "/etc/logstash/templates.d/fticks.json"
      document_type => "default"
#      template_overwrite => true
    }
    if [host] != "90.147.166.156" {
      syslog {
        host => "90.147.166.156"
        message => "%{syslog_message}"
        codec => "plain"
        port => 514
      }
    }
  }
  if "metrics" in [tags] {
    elasticsearch {
      id => "metrics"
      hosts => [ "localhost:9200" ]
      index => "metrics"
    }
  }
}
EOT

systemctl start elasticsearch

sleep 5

cat <<EOT > /etc/elasticsearch/fticks.template
{
    "index_patterns": [
      "fticks*"
    ],
    "settings": {
      "index": {
        "refresh_interval": "5s"
      }
    },
    "mappings": {
      "default": {
        "properties": {
          "RP_geoip": {
            "dynamic": true,
            "properties": {
              "ip": {
                "type": "ip"
              },
              "location": {
                "type": "geo_point"
              },
              "latitude": {
                "type": "half_float"
              },
              "longitude": {
                "type": "half_float"
              }
            }
          },
          "AP_geoip": {
            "dynamic": true,
            "properties": {
              "ip": {
                "type": "ip"
              },
              "location": {
                "type": "geo_point"
              },
              "latitude": {
                "type": "half_float"
              },
              "longitude": {
                "type": "half_float"
              }
            }
          },
          "AP_uri_domain": {
            "type": "text",
            "fielddata": true
          },
          "RP_uri_domain": {
            "type": "text",
            "fielddata": true
          }
        }
      }
    }
}
EOT
curl -X PUT -H 'Content-Type: application/json' http://localhost:9200/_template/fticks_template -d '@/etc/elasticsearch/fticks.template'

cat <<EOT > /etc/elasticsearch/fticks.index
{
    "mappings": {
      "default": {
        "dynamic_templates": [
          {
            "message_field": {
              "path_match": "message",
              "match_mapping_type": "string",
              "mapping": {
                "norms": false,
                "type": "text"
              }
            }
          },
          {
            "string_fields": {
              "match": "*",
              "match_mapping_type": "string",
              "mapping": {
                "fields": {
                  "keyword": {
                    "ignore_above": 256,
                    "type": "keyword"
                  }
                },
                "norms": false,
                "type": "text"
              }
            }
          }
        ],
        "properties": {
          "@timestamp": {
            "type": "date"
          },
          "@version": {
            "type": "keyword"
          },
          "AP": {
            "type": "text",
            "norms": false,
            "fields": {
              "keyword": {
                "type": "keyword",
                "ignore_above": 256
              }
            }
          },
          "AP_geoip": {
            "dynamic": "true",
            "properties": {
              "city_name": {
                "type": "text",
                "norms": false,
                "fields": {
                  "keyword": {
                    "type": "keyword",
                    "ignore_above": 256
                  }
                }
              },
              "continent_code": {
                "type": "text",
                "norms": false,
                "fields": {
                  "keyword": {
                    "type": "keyword",
                    "ignore_above": 256
                  }
                }
              },
              "country_code2": {
                "type": "text",
                "norms": false,
                "fields": {
                  "keyword": {
                    "type": "keyword",
                    "ignore_above": 256
                  }
                }
              },
              "country_code3": {
                "type": "text",
                "norms": false,
                "fields": {
                  "keyword": {
                    "type": "keyword",
                    "ignore_above": 256
                  }
                }
              },
              "country_name": {
                "type": "text",
                "norms": false,
                "fields": {
                  "keyword": {
                    "type": "keyword",
                    "ignore_above": 256
                  }
                }
              },
              "ip": {
                "type": "ip"
              },
              "latitude": {
                "type": "half_float"
              },
              "location": {
                "type": "geo_point"
              },
              "longitude": {
                "type": "half_float"
              },
              "postal_code": {
                "type": "text",
                "norms": false,
                "fields": {
                  "keyword": {
                    "type": "keyword",
                    "ignore_above": 256
                  }
                }
              },
              "region_code": {
                "type": "text",
                "norms": false,
                "fields": {
                  "keyword": {
                    "type": "keyword",
                    "ignore_above": 256
                  }
                }
              },
              "region_name": {
                "type": "text",
                "norms": false,
                "fields": {
                  "keyword": {
                    "type": "keyword",
                    "ignore_above": 256
                  }
                }
              },
              "timezone": {
                "type": "text",
                "norms": false,
                "fields": {
                  "keyword": {
                    "type": "keyword",
                    "ignore_above": 256
                  }
                }
              }
            }
          },
          "AP_uri_domain": {
            "type": "text",
            "norms": false,
            "fields": {
              "keyword": {
                "type": "keyword",
                "ignore_above": 256
              }
            }
          },
          "AP_uri_param": {
            "type": "text",
            "norms": false,
            "fields": {
              "keyword": {
                "type": "keyword",
                "ignore_above": 256
              }
            }
          },
          "AP_uri_proto": {
            "type": "text",
            "norms": false,
            "fields": {
              "keyword": {
                "type": "keyword",
                "ignore_above": 256
              }
            }
          },
          "PN": {
            "type": "text",
            "norms": false,
            "fields": {
              "keyword": {
                "type": "keyword",
                "ignore_above": 256
              }
            }
          },
          "RESULT": {
            "type": "text",
            "norms": false,
            "fields": {
              "keyword": {
                "type": "keyword",
                "ignore_above": 256
              }
            }
          },
          "RP": {
            "type": "text",
            "norms": false,
            "fields": {
              "keyword": {
                "type": "keyword",
                "ignore_above": 256
              }
            }
          },
          "RP_geoip": {
            "dynamic": "true",
            "properties": {
              "city_name": {
                "type": "text",
                "norms": false,
                "fields": {
                  "keyword": {
                    "type": "keyword",
                    "ignore_above": 256
                  }
                }
              },
              "continent_code": {
                "type": "text",
                "norms": false,
                "fields": {
                  "keyword": {
                    "type": "keyword",
                    "ignore_above": 256
                  }
                }
              },
              "country_code2": {
                "type": "text",
                "norms": false,
                "fields": {
                  "keyword": {
                    "type": "keyword",
                    "ignore_above": 256
                  }
                }
              },
              "country_code3": {
                "type": "text",
                "norms": false,
                "fields": {
                  "keyword": {
                    "type": "keyword",
                    "ignore_above": 256
                  }
                }
              },
              "country_name": {
                "type": "text",
                "norms": false,
                "fields": {
                  "keyword": {
                    "type": "keyword",
                    "ignore_above": 256
                  }
                }
              },
              "dma_code": {
                "type": "long"
              },
              "ip": {
                "type": "ip"
              },
              "latitude": {
                "type": "half_float"
              },
              "location": {
                "type": "geo_point"
              },
              "longitude": {
                "type": "half_float"
              },
              "postal_code": {
                "type": "text",
                "norms": false,
                "fields": {
                  "keyword": {
                    "type": "keyword",
                    "ignore_above": 256
                  }
                }
              },
              "region_code": {
                "type": "text",
                "norms": false,
                "fields": {
                  "keyword": {
                    "type": "keyword",
                    "ignore_above": 256
                  }
                }
              },
              "region_name": {
                "type": "text",
                "norms": false,
                "fields": {
                  "keyword": {
                    "type": "keyword",
                    "ignore_above": 256
                  }
                }
              },
              "timezone": {
                "type": "text",
                "norms": false,
                "fields": {
                  "keyword": {
                    "type": "keyword",
                    "ignore_above": 256
                  }
                }
              }
            }
          },
          "RP_uri_domain": {
            "type": "text",
            "norms": false,
            "fields": {
              "keyword": {
                "type": "keyword",
                "ignore_above": 256
              }
            }
          },
          "RP_uri_param": {
            "type": "text",
            "norms": false,
            "fields": {
              "keyword": {
                "type": "keyword",
                "ignore_above": 256
              }
            }
          },
          "RP_uri_proto": {
            "type": "text",
            "norms": false,
            "fields": {
              "keyword": {
                "type": "keyword",
                "ignore_above": 256
              }
            }
          },
          "TS": {
            "type": "text",
            "norms": false,
            "fields": {
              "keyword": {
                "type": "keyword",
                "ignore_above": 256
              }
            }
          },
          "bean": {
            "type": "text",
            "norms": false,
            "fields": {
              "keyword": {
                "type": "keyword",
                "ignore_above": 256
              }
            }
          },
          "facility": {
            "type": "long"
          },
          "facility_label": {
            "type": "text",
            "norms": false,
            "fields": {
              "keyword": {
                "type": "keyword",
                "ignore_above": 256
              }
            }
          },
          "federation": {
            "type": "text",
            "norms": false,
            "fields": {
              "keyword": {
                "type": "keyword",
                "ignore_above": 256
              }
            }
          },
          "host": {
            "type": "text",
            "norms": false,
            "fields": {
              "keyword": {
                "type": "keyword",
                "ignore_above": 256
              }
            }
          },
          "hostname": {
            "type": "text",
            "norms": false,
            "fields": {
              "keyword": {
                "type": "keyword",
                "ignore_above": 256
              }
            }
          },
          "hostname1": {
            "type": "text",
            "norms": false,
            "fields": {
              "keyword": {
                "type": "keyword",
                "ignore_above": 256
              }
            }
          },
          "logsource": {
            "type": "text",
            "norms": false,
            "fields": {
              "keyword": {
                "type": "keyword",
                "ignore_above": 256
              }
            }
          },
          "message": {
            "type": "text",
            "norms": false
          },
          "port": {
            "type": "text",
            "norms": false,
            "fields": {
              "keyword": {
                "type": "keyword",
                "ignore_above": 256
              }
            }
          },
          "priority": {
            "type": "long"
          },
          "priority1": {
            "type": "text",
            "norms": false,
            "fields": {
              "keyword": {
                "type": "keyword",
                "ignore_above": 256
              }
            }
          },
          "process": {
            "type": "text",
            "norms": false,
            "fields": {
              "keyword": {
                "type": "keyword",
                "ignore_above": 256
              }
            }
          },
          "severity": {
            "type": "long"
          },
          "severity_label": {
            "type": "text",
            "norms": false,
            "fields": {
              "keyword": {
                "type": "keyword",
                "ignore_above": 256
              }
            }
          },
          "syslog_message": {
            "type": "text",
            "norms": false,
            "fields": {
              "keyword": {
                "type": "keyword",
                "ignore_above": 256
              }
            }
          },
          "tags": {
            "type": "text",
            "norms": false,
            "fields": {
              "keyword": {
                "type": "keyword",
                "ignore_above": 256
              }
            }
          },
          "timestamp": {
            "type": "text",
            "norms": false,
            "fields": {
              "keyword": {
                "type": "keyword",
                "ignore_above": 256
              }
            }
          },
          "timestamp1": {
            "type": "text",
            "norms": false,
            "fields": {
              "keyword": {
                "type": "keyword",
                "ignore_above": 256
              }
            }
          },
          "version": {
            "type": "text",
            "norms": false,
            "fields": {
              "keyword": {
                "type": "keyword",
                "ignore_above": 256
              }
            }
          }
        }
      }
    },
    "settings": {
      "index": {
        "refresh_interval": "5s",
        "number_of_shards": "5",
        "number_of_replicas": "1"
      }
    }
}
EOT
curl -X PUT -H 'Content-Type: application/json' http://localhost:9200/fticks -d '@/etc/elasticsearch/fticks.index'

htpasswd -b -c "/etc/apache2/passwd" geant jra3t1
a2enmod proxy_http

cat <<EOT > /etc/apache2/sites-available/fticks.conf
<VirtualHost *:80>
        #ServerName www.example.com
        ServerAdmin webmaster@localhost

        ProxyPass / http://localhost:5601/
        ProxyPassReverse / http://localhost:5601/

        <Location "/">
                AuthType Basic
                AuthName "Restricted Files"
                # (Following line optional)
                AuthBasicProvider file
                AuthUserFile "/etc/apache2/passwd"
                Require user geant
        </Location>

        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
EOT

cat <<EOT >/etc/apache2/sites-available/elasticsearch.conf
<VirtualHost *:9201>
        RewriteEngine On
        RewriteCond %{REQUEST_METHOD} !^(GET|POST|HEAD)
        RewriteRule .* - [R=405,L]
        ProxyPass / http://localhost:9200/
        ProxyPassReverse / http://localhost:9200/
</VirtualHost>
EOT

a2dissite 000-default.conf
a2ensite fticks.conf
a2ensite elasticsearch.conf
a2enmod proxy_http
a2enmod rewrite

cat <<EOT >>/etc/kibana/kibana.yml
elasticsearch.url: "http://localhost:9201"
EOT

cat <<EOT >>/etc/apache2/ports.conf
Listen 9201
EOT

ethtool --offload  eth0  rx off  tx off
ethtool -K eth0 gso off

systemctl enable logstash kibana elasticsearch apache2
systemctl restart logstash kibana elasticsearch apache2

curl -f -XPOST -H "Content-Type: application/json" -H "kbn-xsrf: anything" \
  "http://geant:jra3t1@localhost/api/saved_objects/index-pattern/fticks*" \
  -d"{\"attributes\":{\"title\":\"fticks*\",\"timeFieldName\":\"@timestamp\"}}"

curl -XPOST -H "Content-Type: application/json" -H "kbn-xsrf: anything" \
  "http://geant:jra3t1@localhost/api/kibana/settings/defaultIndex" \
  -d"{\"value\":\"fticks*\"}"

