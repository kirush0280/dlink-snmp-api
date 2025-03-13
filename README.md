# Dlink-SNMP-API
(проверено только на DES-3526)

API для управления коммутаторами D-Link через SNMP. Этот инструмент позволяет получать информацию о коммутаторе, управлять VLAN на портах, а также получать данные о интерфейсах коммутатора.

## Установка

1. Убедитесь, что у вас установлен PHP.
2. Склонируйте репозиторий:
   ```bash
   git clone https://github.com/ваш-репозиторий/dlink-snmp-api.git
   cd dlink-snmp-api
   mkdir logs
   установите права на папку с логами
   ```

## Использование

### Командная строка

```bash
php snmp_api.php <ip> <action> [ports] [vlan] [tagged]
```

### Действия (Actions)

#### Получение информации о коммутаторе

```bash
php snmp_api.php <ip> info
```

Пример:
```bash
php snmp_api.php 10.2.0.65 info
```

#### Получение информации о VLAN на портах

```bash
php snmp_api.php <ip> get <ports>
```

Пример:
```bash
php snmp_api.php 10.2.0.65 get 1-4
```

#### Добавление портов в VLAN

```bash
php snmp_api.php <ip> add <ports> <vlan> [tagged]
```

Пример:
```bash
php snmp_api.php 10.2.0.65 add 1-4 100
```

#### Удаление портов из VLAN

```bash
php snmp_api.php <ip> remove <ports> <vlan>
```

Пример:
```bash
php snmp_api.php 10.2.0.65 remove 1-4 100
```

#### Получение информации об интерфейсах коммутатора

```bash
php snmp_api.php <ip> interfaces
```

Пример:
```bash
php snmp_api.php 10.2.0.65 interfaces
```

#### Получение документации по API

```bash
php snmp_api.php help
```

### HTTP API

Вы также можете использовать API через HTTP запросы.

#### Примеры запросов

- **Получение информации о коммутаторе:**
  ```bash
  curl -X POST -H "Content-Type: application/json" -d '{"ip":"10.2.0.65","action":"info"}' http://localhost:8000/snmp_api.php


### REST API

http://localhost:8000/snmp_api.php

![image](https://github.com/user-attachments/assets/fafaf35f-e63c-4e6c-bdca-787db7cddf82)

