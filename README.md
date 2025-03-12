# dlink-snmp-api
Управление коммутаторами Dlink через SNMP

Использование: php snmp_api.php <ip> <action> [ports] [vlan] [tagged]
Для получения полной документации используйте: php snmp_api.php help
alex@Mac-mini-alex dlink % php snmp_api.php help
description: API для управления коммутаторами D-Link через SNMP
version: 1.0.0
endpoints:
  info:
    description: Получение информации о коммутаторе
    usage:
      cli: php snmp_api.php <ip> info
      http:
        method: POST
        endpoint: /
        body:
          ip: string (IP-адрес коммутатора)
          action: info
      get:
        url: /snmp_api.php/info?ip=<ip>
        example: /snmp_api.php/info?ip=10.2.0.65
    returns:
      name: Имя коммутатора
      model: Модель коммутатора
      port_count: Количество портов
      max_bytes: Размер маски в байтах
    examples:
      cli: php snmp_api.php 10.2.0.65 info
      curl: curl -X POST -H "Content-Type: application/json" -d '{"ip":"10.2.0.65","action":"info"}' http://localhost:8000/snmp_api.php
      browser: http://localhost:8000/snmp_api.php/info?ip=10.2.0.65
  get:
    description: Получение информации о VLAN на портах
    usage:
      cli: php snmp_api.php <ip> get <ports>
      http:
        method: POST
        endpoint: /
        body:
          ip: string (IP-адрес коммутатора)
          action: get
          ports: string (номера портов, например: "1-4" или "1,2,3,4")
      get:
        url: /snmp_api.php/get?ip=<ip>&ports=<ports>
        example: /snmp_api.php/get?ip=10.2.0.65&ports=1-4
    returns: Список VLAN для каждого порта с указанием типа (tagged/untagged)
    examples:
      cli: php snmp_api.php 10.2.0.65 get 1-4
      curl: curl -X POST -H "Content-Type: application/json" -d '{"ip":"10.2.0.65","action":"get","ports":"1-4"}' http://localhost:8000/snmp_api.php
      browser: http://localhost:8000/snmp_api.php/get?ip=10.2.0.65&ports=1-4
  add:
    description: Добавление портов в VLAN
    usage:
      cli: php snmp_api.php <ip> add <ports> <vlan> [tagged]
      http:
        method: POST
        endpoint: /
        body:
          ip: string (IP-адрес коммутатора)
          action: add
          ports: string (номера портов)
          vlan: integer (номер VLAN)
          tagged: boolean (опционально, по умолчанию false)
      get:
        url: /snmp_api.php/add?ip=<ip>&ports=<ports>&vlan=<vlan>&tagged=<tagged>
        example: /snmp_api.php/add?ip=10.2.0.65&ports=1-4&vlan=100&tagged=0
    notes: Параметр tagged определяет тип добавления порта в VLAN (true - tagged, false - untagged)
    examples:
      cli: php snmp_api.php 10.2.0.65 add 1-4 100
      curl: curl -X POST -H "Content-Type: application/json" -d '{"ip":"10.2.0.65","action":"add","ports":"1-4","vlan":100,"tagged":false}' http://localhost:8000/snmp_api.php
      browser: http://localhost:8000/snmp_api.php/add?ip=10.2.0.65&ports=1-4&vlan=100&tagged=0
  remove:
    description: Удаление портов из VLAN
    usage:
      cli: php snmp_api.php <ip> remove <ports> <vlan>
      http:
        method: POST
        endpoint: /
        body:
          ip: string (IP-адрес коммутатора)
          action: remove
          ports: string (номера портов)
          vlan: integer (номер VLAN)
      get:
        url: /snmp_api.php/remove?ip=<ip>&ports=<ports>&vlan=<vlan>
        example: /snmp_api.php/remove?ip=10.2.0.65&ports=1-4&vlan=100
    examples:
      cli: php snmp_api.php 10.2.0.65 remove 1-4 100
      curl: curl -X POST -H "Content-Type: application/json" -d '{"ip":"10.2.0.65","action":"remove","ports":"1-4","vlan":100}' http://localhost:8000/snmp_api.php
      browser: http://localhost:8000/snmp_api.php/remove?ip=10.2.0.65&ports=1-4&vlan=100
  interfaces:
    description: Получение информации об интерфейсах коммутатора
    usage:
      cli: php snmp_api.php <ip> interfaces
      http:
        method: POST
        endpoint: /
        body:
          ip: string (IP-адрес коммутатора)
          action: interfaces
      get:
        url: /snmp_api.php/interfaces?ip=<ip>
        example: /snmp_api.php/interfaces?ip=10.2.0.65
    returns:
      Физические порты: Список физических портов с их статусом и скоростью
      VLAN интерфейсы: Список VLAN интерфейсов
      Системные интерфейсы: Список системных интерфейсов
    examples:
      cli: php snmp_api.php 10.2.0.65 interfaces
      curl: curl -X POST -H "Content-Type: application/json" -d '{"ip":"10.2.0.65","action":"interfaces"}' http://localhost:8000/snmp_api.php
      browser: http://localhost:8000/snmp_api.php/interfaces?ip=10.2.0.65
  help:
    description: Получение документации по API
    usage:
      cli: php snmp_api.php help
      http:
        method: POST
        endpoint: /
        body:
          action: help
      get:
        url: /snmp_api.php/help
        example: /snmp_api.php/help
    returns: Полная документация по API
    examples:
      cli: php snmp_api.php help
      curl: curl -X POST -H "Content-Type: application/json" -d '{"action":"help"}' http://localhost:8000/snmp_api.php
      browser: http://localhost:8000/snmp_api.php/help
