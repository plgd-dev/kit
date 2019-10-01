[![Build Status](https://travis-ci.com/go-ocf/kit.svg?branch=master)](https://travis-ci.com/go-ocf/kit)
[![codecov](https://codecov.io/gh/go-ocf/kit/branch/master/graph/badge.svg)](https://codecov.io/gh/go-ocf/kit)
[![Go Report](https://goreportcard.com/badge/github.com/go-ocf/kit)](https://goreportcard.com/report/github.com/go-ocf/kit)
[![Gitter](https://badges.gitter.im/ocfcloud/Lobby.svg)](https://gitter.im/ocfcloud/Lobby?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)

# kit

## Configuration
### CQRS/eventbus/Kafka
| Option | ENV variable | Type | Description | Default |
| ------ | --------- | ----------- | ------- | ------- |
| `-` | `BOOTSTRAP_SERVERS` | string | tbd | `"localhost:9092"` |



### CQRS/eventbus/NATS
| Option | ENV variable | Type | Description | Default |
| ------ | --------- | ----------- | ------- | ------- |
| `-` | `URL` | string | tbd | `"nats://localhost:4222"` |

### CQRS/eventstore/MongoDB
| Option | ENV variable | Type | Description | Default |
| ------ | --------- | ----------- | ------- | ------- |
| `-` | `URI` | string | tbd | `"mongodb://localhost:27017"` |
| `-` | `DATABASE` | string | tbd | `"eventstore"` |
| `-` | `BATCH_SIZE` | int | tbd | `16` |
| `-` | `MAX_POOL_SIZE` | int | tbd | `16` |
| `-` | `MAX_CONN_IDLE_TIME` | string | tbd | `"240s"` |

### security/TLS
| Option | ENV variable | Type | Description | Default |
| ------ | --------- | ----------- | ------- | ------- |
| `-` | `CA_POOL` | string | tbd | `""` |
| `-` | `CERTIFICATE` | string | tbd | `""` |
| `-` | `CERTIFICATE_KEY` | string | tbd | `""` |

### security/ACME
| Option | ENV variable | Type | Description | Default |
| ------ | --------- | ----------- | ------- | ------- |
| `-` | `CA_POOL` | string | tbd | `""` |
| `-` | `DIRECTORY_URL` | string | tbd | `""` |
| `-` | `DOMAINS` | string | tbd | `""` |
| `-` | `REGISTRATION_EMAIL` | string | tbd | `""` |
| `-` | `TICK_FREQUENCY` | string | tbd | `""` |

### net/GRPC
| Option | ENV variable | Type | Description | Default |
| ------ | --------- | ----------- | ------- | ------- |
| `-` | `ADDRESS` | string | tbd | `"0.0.0.0:9100"` |

### net/CoAP

### log
| Option | ENV variable | Type | Description | Default |
| ------ | --------- | ----------- | ------- | ------- |
| `-` | `ENABLE_DEBUG` | bool | tbd | `false` |

