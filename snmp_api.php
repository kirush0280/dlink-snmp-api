<?php
require 'config.php';

class DlinkSNMP {
    private $ip;
    private $readOnlyCommunity;
    private $readWriteCommunity;
    private $portCount;
    private $maxBytes;

    public function __construct($ip) {
        $config = include 'config.php';
        $this->ip = $ip;
        $this->readOnlyCommunity = $config['snmp']['read_only_community'];
        $this->readWriteCommunity = $config['snmp']['read_write_community'];
        
        // Пропускаем проверку для вызова help
        if ($ip !== 'localhost') {
            try {
                // Проверяем read-only community
                echo "DEBUG: Проверка read-only community...\n";
                $this->checkSnmpCommunity($this->readOnlyCommunity, 'read-only');
                echo "DEBUG: Read-only community работает корректно\n";
                
                // Проверяем read-write community
                echo "DEBUG: Проверка read-write community...\n";
                $this->checkSnmpCommunity($this->readWriteCommunity, 'read-write');
                echo "DEBUG: Read-write community работает корректно\n";
                
                // Определяем количество портов при инициализации
                $this->portCount = $this->getPortCount();
                // Вычисляем количество байт для маски на основе количества портов
                $this->maxBytes = ceil($this->portCount / 8);
            } catch (Exception $e) {
                throw new Exception("Ошибка инициализации SNMP: " . $e->getMessage());
            }
        }
    }

    // Получение количества портов коммутатора
    private function getPortCount() {
        try {
            // Получаем общее количество интерфейсов
            $ifNumber = snmp2_get($this->ip, $this->readOnlyCommunity, '.1.3.6.1.2.1.2.1.0');
            if ($ifNumber === false) {
                throw new Exception("Не удалось получить количество портов");
            }

            // Преобразуем строку вида "INTEGER: 28" в число
            if (preg_match('/INTEGER: (\d+)/', $ifNumber, $matches)) {
                $totalPorts = (int)$matches[1];
                // Обычно первые два интерфейса - системные
                return $totalPorts - 2;
            }
            
            // Если не удалось определить, используем безопасное значение по умолчанию
            return 24;
        } catch (Exception $e) {
            // В случае ошибки используем безопасное значение по умолчанию
            return 24;
        }
    }

    // Создание маски портов с учетом реального количества портов
    private function createPortMask($portsStr) {
        $mask = array_fill(0, $this->maxBytes, '00');
        
        // Разбираем строку портов (например: "1-4" или "1,2,3,4" или "1-3,5")
        $parts = explode(',', $portsStr);
        foreach ($parts as $part) {
            if (strpos($part, '-') !== false) {
                list($start, $end) = explode('-', $part);
                if ($end > $this->portCount) {
                    throw new Exception("Порт {$end} выходит за пределы количества портов коммутатора ({$this->portCount})");
                }
                $ports = range($start, $end);
            } else {
                if ($part > $this->portCount) {
                    throw new Exception("Порт $part выходит за пределы количества портов коммутатора ({$this->portCount})");
                }
                $ports = [$part];
            }
            
            foreach ($ports as $port) {
                $byteIndex = floor(($port - 1) / 8);
                $bitInByte = 7 - (($port - 1) % 8);
                
                if ($byteIndex < $this->maxBytes) {
                    $currentByte = hexdec($mask[$byteIndex]);
                    $mask[$byteIndex] = sprintf("%02X", $currentByte | (1 << $bitInByte));
                }
            }
        }
        
        return $mask;
    }

    // Получение маски VLAN
    private function getVlanMask($vlanId, $type = 'tagged') {
        $oid = $type === 'tagged' ? 
            ".1.3.6.1.2.1.17.7.1.4.3.1.2.$vlanId" : 
            ".1.3.6.1.2.1.17.7.1.4.3.1.4.$vlanId";
            
        $result = snmp2_get($this->ip, $this->readOnlyCommunity, $oid);
        if ($result === false) {
            return null;
        }

        if (preg_match('/Hex-STRING: (.+)$/', $result, $matches)) {
            $hexMask = preg_replace('/\s+/', '', $matches[1]);
            return str_split($hexMask, 2);
        }
        return null;
    }

    // Проверка существования VLAN
    private function checkVlanExists($vlanId) {
        return $this->getVlanMask($vlanId) !== null;
    }

    // Получение информации о VLAN для порта
    public function getPortVlan($portsStr) {
        $result = [];
        $parts = explode(',', $portsStr);
        
        foreach ($parts as $part) {
            if (strpos($part, '-') !== false) {
                list($start, $end) = explode('-', $part);
                $ports = range($start, $end);
            } else {
                $ports = [$part];
            }

            foreach ($ports as $port) {
                $portInfo = [];
                $portInfo["port"] = $port;
                $portInfo["vlans"] = [];

                // Получаем список всех VLAN
                $vlanList = $this->getExistingVlans();
                
                foreach ($vlanList as $vlanId) {
                    $taggedMask = $this->getVlanMask($vlanId, 'tagged');
                    $untaggedMask = $this->getVlanMask($vlanId, 'untagged');
                    
                    if (!$taggedMask || !$untaggedMask) continue;

                    $byteIndex = floor(($port - 1) / 8);
                    $bitInByte = 7 - (($port - 1) % 8);
                    $bitMask = 1 << $bitInByte;

                    if ($byteIndex < count($untaggedMask)) {
                        if (hexdec($untaggedMask[$byteIndex]) & $bitMask) {
                            $portInfo["vlans"][] = [
                                "vlan" => $vlanId,
                                "type" => "untagged"
                            ];
                            continue;
                        }
                    }

                    if ($byteIndex < count($taggedMask)) {
                        if (hexdec($taggedMask[$byteIndex]) & $bitMask) {
                            $portInfo["vlans"][] = [
                                "vlan" => $vlanId,
                                "type" => "tagged"
                            ];
                        }
                    }
                }

                $result[] = $portInfo;
            }
        }

        return $result;
    }

    // Получение списка существующих VLAN
    private function getExistingVlans() {
        $vlans = [];
        $result = snmp2_real_walk($this->ip, $this->readOnlyCommunity, ".1.3.6.1.2.1.17.7.1.4.3.1.1");
        
        if (is_array($result)) {
            foreach ($result as $oid => $value) {
                if (preg_match('/\.(\d+)$/', $oid, $matches)) {
                    $vlans[] = $matches[1];
                }
            }
        }
        
        return $vlans;
    }

    // Добавление портов в VLAN
    public function addPortsToVlan($portsStr, $vlanId, $tagged = false) {
        if (!$this->checkVlanExists($vlanId)) {
            throw new Exception("VLAN $vlanId не существует");
        }

        // Получаем текущие маски
        $currentTaggedMask = $this->getVlanMask($vlanId, 'tagged');
        $currentUntaggedMask = $this->getVlanMask($vlanId, 'untagged');
        
        // Создаем маску для новых портов
        $newPortsMask = $this->createPortMask($portsStr);
        
        if ($tagged) {
            // Для tagged портов объединяем текущую маску с новой
            $taggedValues = array_map(function($current, $new) {
                return sprintf("%02X", hexdec($current) | hexdec($new));
            }, $currentTaggedMask, $newPortsMask);
            
            $taggedValue = implode(" ", $taggedValues);
            $result = snmp2_set($this->ip, $this->readWriteCommunity, 
                              ".1.3.6.1.2.1.17.7.1.4.3.1.2.$vlanId", 
                              'x', $taggedValue);
            
            if ($result === false) {
                throw new Exception("Ошибка добавления портов в tagged VLAN");
            }
        } else {
            // Для untagged портов
            $taggedValues = array_map(function($current, $new) {
                return sprintf("%02X", hexdec($current) | hexdec($new));
            }, $currentTaggedMask, $newPortsMask);
            
            $untaggedValues = array_map(function($current, $new) {
                return sprintf("%02X", hexdec($current) | hexdec($new));
            }, $currentUntaggedMask, $newPortsMask);
            
            // Устанавливаем tagged конфигурацию
            $result = snmp2_set($this->ip, $this->readWriteCommunity,
                              ".1.3.6.1.2.1.17.7.1.4.3.1.2.$vlanId",
                              'x', implode(" ", $taggedValues));
            
            if ($result === false) {
                throw new Exception("Ошибка добавления портов в VLAN");
            }
            
            // Устанавливаем untagged конфигурацию
            $result = snmp2_set($this->ip, $this->readWriteCommunity,
                              ".1.3.6.1.2.1.17.7.1.4.3.1.4.$vlanId",
                              'x', implode(" ", $untaggedValues));
            
            if ($result === false) {
                throw new Exception("Ошибка установки портов как untagged");
            }
        }
        
        return true;
    }

    // Удаление портов из VLAN
    public function removePortsFromVlan($portsStr, $vlanId) {
        if (!$this->checkVlanExists($vlanId)) {
            throw new Exception("VLAN $vlanId не существует");
        }

        // Получаем текущие маски
        $taggedMask = $this->getVlanMask($vlanId, 'tagged');
        $untaggedMask = $this->getVlanMask($vlanId, 'untagged');
        
        // Создаем маску для портов
        $portMask = $this->createPortMask($portsStr);
        
        // Инвертируем маску портов
        $invertedMask = array_map(function($byte) {
            return sprintf("%02X", hexdec($byte) ^ 0xFF);
        }, $portMask);
        
        // Очищаем untagged конфигурацию
        $untaggedValues = array_map(function($current, $inverted) {
            return sprintf("%02X", hexdec($current) & hexdec($inverted));
        }, $untaggedMask, $invertedMask);
        
        $result = snmp2_set($this->ip, $this->readWriteCommunity,
                          ".1.3.6.1.2.1.17.7.1.4.3.1.4.$vlanId",
                          'x', implode(" ", $untaggedValues));
        
        if ($result === false) {
            throw new Exception("Ошибка удаления портов из VLAN (untagged)");
        }
        
        // Очищаем tagged конфигурацию
        $taggedValues = array_map(function($current, $inverted) {
            return sprintf("%02X", hexdec($current) & hexdec($inverted));
        }, $taggedMask, $invertedMask);
        
        $result = snmp2_set($this->ip, $this->readWriteCommunity,
                          ".1.3.6.1.2.1.17.7.1.4.3.1.2.$vlanId",
                          'x', implode(" ", $taggedValues));
        
        if ($result === false) {
            throw new Exception("Ошибка удаления портов из VLAN (tagged)");
        }
        
        return true;
    }

    // Добавляем метод для получения информации о коммутаторе
    public function getSwitchInfo() {
        $info = [
            'port_count' => $this->portCount,
            'max_bytes' => $this->maxBytes
        ];
        
        try {
            // Получаем информацию о модели
            $sysDescr = snmp2_get($this->ip, $this->readOnlyCommunity, '.1.3.6.1.2.1.1.1.0');
            if ($sysDescr !== false && preg_match('/STRING: "(.*)"/', $sysDescr, $matches)) {
                $info['model'] = $matches[1];
            }
            
            // Получаем имя коммутатора
            $sysName = snmp2_get($this->ip, $this->readOnlyCommunity, '.1.3.6.1.2.1.1.5.0');
            if ($sysName !== false && preg_match('/STRING: "(.*)"/', $sysName, $matches)) {
                $info['name'] = $matches[1];
            }
        } catch (Exception $e) {
            // Игнорируем ошибки при получении дополнительной информации
        }
        
        return $info;
    }

    // Получение информации об интерфейсах
    public function getInterfaces() {
        $interfaces = [];
        
        try {
            echo "DEBUG: Начинаем получение информации об интерфейсах\n";
            
            // Получаем описания интерфейсов
            echo "DEBUG: Пытаемся получить описания интерфейсов...\n";
            $ifDescr = snmp2_walk($this->ip, $this->readOnlyCommunity, '.1.3.6.1.2.1.2.2.1.2');
            if ($ifDescr === false) {
                echo "DEBUG: Ошибка получения описаний интерфейсов\n";
                throw new Exception("Ошибка получения описаний интерфейсов");
            }
            echo "DEBUG: Получено описаний интерфейсов: " . count($ifDescr) . "\n";
            
            // Получаем статус интерфейсов
            echo "\nDEBUG: Пытаемся получить статус интерфейсов...\n";
            $ifOperStatus = snmp2_walk($this->ip, $this->readOnlyCommunity, '.1.3.6.1.2.1.2.2.1.8');
            if ($ifOperStatus === false) {
                echo "DEBUG: Ошибка получения статуса интерфейсов\n";
                throw new Exception("Ошибка получения статуса интерфейсов");
            }
            echo "DEBUG: Получено статусов интерфейсов: " . count($ifOperStatus) . "\n";
            
            // Получаем скорость интерфейсов
            echo "\nDEBUG: Пытаемся получить скорость интерфейсов...\n";
            $ifSpeed = snmp2_walk($this->ip, $this->readOnlyCommunity, '.1.3.6.1.2.1.2.2.1.5');
            if ($ifSpeed === false) {
                echo "DEBUG: Ошибка получения скорости интерфейсов\n";
                throw new Exception("Ошибка получения скорости интерфейсов");
            }
            echo "DEBUG: Получено скоростей интерфейсов: " . count($ifSpeed) . "\n";
            
            // Получаем MAC-адреса интерфейсов
            echo "\nDEBUG: Пытаемся получить MAC-адреса интерфейсов...\n";
            $ifPhysAddress = snmp2_walk($this->ip, $this->readOnlyCommunity, '.1.3.6.1.2.1.2.2.1.6');
            if ($ifPhysAddress === false) {
                echo "DEBUG: Ошибка получения MAC-адресов интерфейсов\n";
                throw new Exception("Ошибка получения MAC-адресов интерфейсов");
            }
            echo "DEBUG: Получено MAC-адресов интерфейсов: " . count($ifPhysAddress) . "\n";
            
            echo "\nDEBUG: Начинаем обработку полученных данных...\n";
            
            // Обрабатываем каждый интерфейс
            for ($i = 0; $i < count($ifDescr); $i++) {
                echo "\nDEBUG: Обработка интерфейса с индексом: " . ($i + 1) . "\n";
                
                // Извлекаем описание
                $description = preg_replace('/^STRING: "(.+)"$/', '$1', $ifDescr[$i]);
                echo "DEBUG: Описание интерфейса: $description\n";
                
                $interface = [
                    'index' => $i + 1,
                    'description' => $description,
                    'type' => 'unknown'
                ];
                
                // Добавляем статус интерфейса
                if (isset($ifOperStatus[$i])) {
                    $status = preg_replace('/^INTEGER: (\d+)$/', '$1', $ifOperStatus[$i]);
                    $interface['status'] = $this->getInterfaceStatus((int)$status);
                    echo "DEBUG: Статус интерфейса: {$interface['status']}\n";
                }
                
                // Добавляем скорость интерфейса
                if (isset($ifSpeed[$i])) {
                    $speed = preg_replace('/^Gauge32: (\d+)$/', '$1', $ifSpeed[$i]);
                    $interface['speed'] = $this->formatSpeed((int)$speed);
                    echo "DEBUG: Скорость интерфейса: {$interface['speed']}\n";
                }
                
                // Добавляем MAC-адрес
                if (isset($ifPhysAddress[$i])) {
                    $mac = preg_replace('/^Hex-STRING: (.+)$/', '$1', $ifPhysAddress[$i]);
                    if ($mac !== '00 00 00 00 00 00') {
                        $interface['mac'] = trim($mac);
                        echo "DEBUG: MAC-адрес интерфейса: {$interface['mac']}\n";
                    }
                }
                
                // Определяем тип интерфейса
                $index = $i + 1;
                if ($index <= 24) {
                    $interface['type'] = 'physical';
                } elseif ($index <= 26) {
                    $interface['type'] = 'combo';
                } elseif (strpos($description, '802.1Q') === 0) {
                    $interface['type'] = 'vlan';
                } else {
                    $interface['type'] = 'system';
                }
                echo "DEBUG: Тип интерфейса: {$interface['type']}\n";
                
                $interfaces[] = $interface;
            }
            
            echo "\nDEBUG: Всего обработано интерфейсов: " . count($interfaces) . "\n";
            
        } catch (Exception $e) {
            echo "DEBUG: Произошла ошибка: " . $e->getMessage() . "\n";
            throw new Exception("Ошибка получения информации об интерфейсах: " . $e->getMessage());
        }
        
        return $interfaces;
    }

    // Вспомогательная функция для форматирования скорости
    private function formatSpeed($speedValue) {
        if ($speedValue <= 0) {
            return "Нет линка";
        }
        if ($speedValue >= 1000000000) {
            return round($speedValue / 1000000000, 1) . " Гбит/с";
        }
        if ($speedValue >= 1000000) {
            return round($speedValue / 1000000) . " Мбит/с";
        }
        return $speedValue . " бит/с";
    }

    // Вспомогательная функция для получения статуса интерфейса
    private function getInterfaceStatus($status) {
        $statuses = [
            1 => "UP",
            2 => "DOWN",
            3 => "TESTING",
            4 => "UNKNOWN",
            5 => "DORMANT",
            6 => "NOT PRESENT",
            7 => "LOWER LAYER DOWN"
        ];
        return isset($statuses[$status]) ? $statuses[$status] : "UNKNOWN";
    }

    public function getApiDocs() {
        $docs = [
            'description' => 'API для управления коммутаторами D-Link через SNMP',
            'version' => '1.0.0',
            'security' => [
                'description' => 'Проверка SNMP community строк',
                'checks' => [
                    'read_only' => [
                        'description' => 'Проверка read-only community через запрос sysDescr',
                        'oid' => '.1.3.6.1.2.1.1.1.0'
                    ],
                    'read_write' => [
                        'description' => 'Проверка read-write community через запрос и установку sysContact',
                        'oid' => '.1.3.6.1.2.1.1.4.0'
                    ]
                ],
                'error_handling' => [
                    'read_only_fail' => 'Ошибка проверки read-only community',
                    'read_write_fail_read' => 'Ошибка проверки read-write community (чтение)',
                    'read_write_fail_write' => 'Ошибка проверки read-write community (запись)'
                ]
            ],
            'endpoints' => [
                'info' => [
                    'description' => 'Получение информации о коммутаторе',
                    'usage' => [
                        'cli' => 'php snmp_api.php <ip> info',
                        'http' => [
                            'method' => 'POST',
                            'endpoint' => '/',
                            'body' => [
                                'ip' => 'string (IP-адрес коммутатора)',
                                'action' => 'info'
                            ]
                        ],
                        'get' => [
                            'url' => '/snmp_api.php/info?ip=<ip>',
                            'example' => '/snmp_api.php/info?ip=10.2.0.65'
                        ]
                    ],
                    'returns' => [
                        'name' => 'Имя коммутатора',
                        'model' => 'Модель коммутатора',
                        'port_count' => 'Количество портов',
                        'max_bytes' => 'Размер маски в байтах'
                    ],
                    'examples' => [
                        'cli' => 'php snmp_api.php 10.2.0.65 info',
                        'curl' => 'curl -X POST -H "Content-Type: application/json" -d \'{"ip":"10.2.0.65","action":"info"}\' http://localhost:8000/snmp_api.php',
                        'browser' => 'http://localhost:8000/snmp_api.php/info?ip=10.2.0.65'
                    ]
                ],
                'get' => [
                    'description' => 'Получение информации о VLAN на портах',
                    'usage' => [
                        'cli' => 'php snmp_api.php <ip> get <ports>',
                        'http' => [
                            'method' => 'POST',
                            'endpoint' => '/',
                            'body' => [
                                'ip' => 'string (IP-адрес коммутатора)',
                                'action' => 'get',
                                'ports' => 'string (номера портов, например: "1-4" или "1,2,3,4")'
                            ]
                        ],
                        'get' => [
                            'url' => '/snmp_api.php/get?ip=<ip>&ports=<ports>',
                            'example' => '/snmp_api.php/get?ip=10.2.0.65&ports=1-4'
                        ]
                    ],
                    'returns' => 'Список VLAN для каждого порта с указанием типа (tagged/untagged)',
                    'examples' => [
                        'cli' => 'php snmp_api.php 10.2.0.65 get 1-4',
                        'curl' => 'curl -X POST -H "Content-Type: application/json" -d \'{"ip":"10.2.0.65","action":"get","ports":"1-4"}\' http://localhost:8000/snmp_api.php',
                        'browser' => 'http://localhost:8000/snmp_api.php/get?ip=10.2.0.65&ports=1-4'
                    ]
                ],
                'add' => [
                    'description' => 'Добавление портов в VLAN',
                    'usage' => [
                        'cli' => 'php snmp_api.php <ip> add <ports> <vlan> [tagged]',
                        'http' => [
                            'method' => 'POST',
                            'endpoint' => '/',
                            'body' => [
                                'ip' => 'string (IP-адрес коммутатора)',
                                'action' => 'add',
                                'ports' => 'string (номера портов)',
                                'vlan' => 'integer (номер VLAN)',
                                'tagged' => 'boolean (опционально, по умолчанию false)'
                            ]
                        ],
                        'get' => [
                            'url' => '/snmp_api.php/add?ip=<ip>&ports=<ports>&vlan=<vlan>&tagged=<tagged>',
                            'example' => '/snmp_api.php/add?ip=10.2.0.65&ports=1-4&vlan=100&tagged=0'
                        ]
                    ],
                    'notes' => 'Параметр tagged определяет тип добавления порта в VLAN (true - tagged, false - untagged)',
                    'examples' => [
                        'cli' => 'php snmp_api.php 10.2.0.65 add 1-4 100',
                        'curl' => 'curl -X POST -H "Content-Type: application/json" -d \'{"ip":"10.2.0.65","action":"add","ports":"1-4","vlan":100,"tagged":false}\' http://localhost:8000/snmp_api.php',
                        'browser' => 'http://localhost:8000/snmp_api.php/add?ip=10.2.0.65&ports=1-4&vlan=100&tagged=0'
                    ]
                ],
                'remove' => [
                    'description' => 'Удаление портов из VLAN',
                    'usage' => [
                        'cli' => 'php snmp_api.php <ip> remove <ports> <vlan>',
                        'http' => [
                            'method' => 'POST',
                            'endpoint' => '/',
                            'body' => [
                                'ip' => 'string (IP-адрес коммутатора)',
                                'action' => 'remove',
                                'ports' => 'string (номера портов)',
                                'vlan' => 'integer (номер VLAN)'
                            ]
                        ],
                        'get' => [
                            'url' => '/snmp_api.php/remove?ip=<ip>&ports=<ports>&vlan=<vlan>',
                            'example' => '/snmp_api.php/remove?ip=10.2.0.65&ports=1-4&vlan=100'
                        ]
                    ],
                    'examples' => [
                        'cli' => 'php snmp_api.php 10.2.0.65 remove 1-4 100',
                        'curl' => 'curl -X POST -H "Content-Type: application/json" -d \'{"ip":"10.2.0.65","action":"remove","ports":"1-4","vlan":100}\' http://localhost:8000/snmp_api.php',
                        'browser' => 'http://localhost:8000/snmp_api.php/remove?ip=10.2.0.65&ports=1-4&vlan=100'
                    ]
                ],
                'interfaces' => [
                    'description' => 'Получение информации об интерфейсах коммутатора',
                    'usage' => [
                        'cli' => 'php snmp_api.php <ip> interfaces',
                        'http' => [
                            'method' => 'POST',
                            'endpoint' => '/',
                            'body' => [
                                'ip' => 'string (IP-адрес коммутатора)',
                                'action' => 'interfaces'
                            ]
                        ],
                        'get' => [
                            'url' => '/snmp_api.php/interfaces?ip=<ip>',
                            'example' => '/snmp_api.php/interfaces?ip=10.2.0.65'
                        ]
                    ],
                    'returns' => [
                        'Физические порты' => 'Список физических портов с их статусом и скоростью',
                        'VLAN интерфейсы' => 'Список VLAN интерфейсов',
                        'Системные интерфейсы' => 'Список системных интерфейсов'
                    ],
                    'examples' => [
                        'cli' => 'php snmp_api.php 10.2.0.65 interfaces',
                        'curl' => 'curl -X POST -H "Content-Type: application/json" -d \'{"ip":"10.2.0.65","action":"interfaces"}\' http://localhost:8000/snmp_api.php',
                        'browser' => 'http://localhost:8000/snmp_api.php/interfaces?ip=10.2.0.65'
                    ]
                ],
                'help' => [
                    'description' => 'Получение документации по API',
                    'usage' => [
                        'cli' => 'php snmp_api.php help',
                        'http' => [
                            'method' => 'POST',
                            'endpoint' => '/',
                            'body' => [
                                'action' => 'help'
                            ]
                        ],
                        'get' => [
                            'url' => '/snmp_api.php/help',
                            'example' => '/snmp_api.php/help'
                        ]
                    ],
                    'returns' => 'Полная документация по API',
                    'examples' => [
                        'cli' => 'php snmp_api.php help',
                        'curl' => 'curl -X POST -H "Content-Type: application/json" -d \'{"action":"help"}\' http://localhost:8000/snmp_api.php',
                        'browser' => 'http://localhost:8000/snmp_api.php/help'
                    ]
                ]
            ]
        ];

        if (php_sapi_name() === 'cli') {
            return $this->formatCliDocs($docs);
        }
        
        return $docs;
    }

    private function formatCliDocs($docs, $indent = 0) {
        $output = "";
        $pad = str_repeat(" ", $indent);
        
        foreach ($docs as $key => $value) {
            if (is_array($value)) {
                $output .= "$pad$key:\n";
                $output .= $this->formatCliDocs($value, $indent + 2);
            } else {
                $output .= "$pad$key: $value\n";
            }
        }
        
        return $output;
    }

    private function checkSnmpCommunity($community, $type = 'read-only') {
        try {
            // Проверяем доступность коммутатора через sysDescr (для read-only)
            if ($type === 'read-only') {
                $result = snmp2_get($this->ip, $community, '.1.3.6.1.2.1.1.1.0');
                if ($result === false) {
                    throw new Exception("Ошибка проверки read-only community");
                }
            } else {
                // Для read-write пробуем получить и установить sysContact
                // Сначала сохраняем текущее значение
                $currentContact = snmp2_get($this->ip, $community, '.1.3.6.1.2.1.1.4.0');
                if ($currentContact === false) {
                    throw new Exception("Ошибка проверки read-write community (чтение)");
                }
                
                // Пробуем установить то же самое значение обратно
                $result = snmp2_set($this->ip, $community, '.1.3.6.1.2.1.1.4.0', 's', $currentContact);
                if ($result === false) {
                    throw new Exception("Ошибка проверки read-write community (запись)");
                }
            }
            
            return true;
        } catch (Exception $e) {
            throw new Exception("Ошибка проверки " . $type . " community: " . $e->getMessage());
        }
    }
}

// Обновляем CLI интерфейс
if (php_sapi_name() === 'cli') {
    if ($argc < 2) {
        die("Использование: php snmp_api.php <ip> <action> [ports] [vlan] [tagged]\n" .
            "Для получения полной документации используйте: php snmp_api.php help\n\n" .
            "Примечание: При каждом обращении к коммутатору выполняется автоматическая проверка\n" .
            "доступности и корректности SNMP community строк.\n");
    }

    try {
        if ($argv[1] === 'help') {
            $snmp = new DlinkSNMP('localhost');
            echo $snmp->getApiDocs();
            exit(0);
        }

        $ip = $argv[1];
        $action = $argv[2];
        $ports = isset($argv[3]) ? $argv[3] : null;
        $vlan = isset($argv[4]) ? $argv[4] : null;
        $tagged = isset($argv[5]) ? (bool)$argv[5] : false;

        $snmp = new DlinkSNMP($ip);
        
        switch ($action) {
            case 'info':
                $info = $snmp->getSwitchInfo();
                echo "=== Информация о коммутаторе ===\n";
                if (isset($info['name'])) echo "Имя: {$info['name']}\n";
                if (isset($info['model'])) echo "Модель: {$info['model']}\n";
                echo "Количество портов: {$info['port_count']}\n";
                echo "Размер маски (байт): {$info['max_bytes']}\n";
                break;

            case 'get':
                if (!$ports) {
                    die("Необходимо указать порты\n");
                }
                $result = $snmp->getPortVlan($ports);
                foreach ($result as $portInfo) {
                    echo "=== Порт {$portInfo['port']} ===\n";
                    if (empty($portInfo['vlans'])) {
                        echo "Порт {$portInfo['port']} не найден ни в одном VLAN\n";
                    } else {
                        foreach ($portInfo['vlans'] as $vlanInfo) {
                            echo "Порт {$portInfo['port']} находится в VLAN {$vlanInfo['vlan']} ({$vlanInfo['type']})\n";
                        }
                    }
                }
                break;

            case 'add':
                if ($vlan === null) {
                    die("Для добавления портов необходимо указать VLAN\n");
                }
                $result = $snmp->addPortsToVlan($ports, $vlan, $tagged);
                echo "Порты $ports успешно добавлены в VLAN $vlan как " . ($tagged ? "tagged" : "untagged") . "\n";
                break;

            case 'remove':
                if ($vlan === null) {
                    die("Для удаления портов необходимо указать VLAN\n");
                }
                $result = $snmp->removePortsFromVlan($ports, $vlan);
                echo "Порты $ports успешно удалены из VLAN $vlan\n";
                break;

            case 'interfaces':
                $interfaces = $snmp->getInterfaces();
                echo "=== Интерфейсы коммутатора ===\n\n";
                
                echo "Физические порты:\n";
                echo "----------------\n";
                foreach ($interfaces as $interface) {
                    if ($interface['type'] === 'physical' || $interface['type'] === 'combo') {
                        $portType = $interface['type'] === 'physical' ? "Медный порт" : "Combo порт";
                        echo "Порт {$interface['index']} ($portType)\n";
                        echo "Описание: {$interface['description']}\n";
                        if (isset($interface['status'])) {
                            echo "Статус: {$interface['status']}\n";
                        }
                        if (isset($interface['speed'])) {
                            echo "Скорость: {$interface['speed']}\n";
                        }
                        if (isset($interface['mac'])) {
                            echo "MAC: {$interface['mac']}\n";
                        }
                        echo "----------------\n";
                    }
                }
                
                echo "\nVLAN интерфейсы:\n";
                echo "----------------\n";
                foreach ($interfaces as $interface) {
                    if ($interface['type'] === 'vlan') {
                        echo "Интерфейс: {$interface['description']}\n";
                        if (isset($interface['status'])) {
                            echo "Статус: {$interface['status']}\n";
                        }
                        echo "----------------\n";
                    }
                }
                
                echo "\nСистемные интерфейсы:\n";
                echo "----------------\n";
                foreach ($interfaces as $interface) {
                    if ($interface['type'] === 'system') {
                        echo "Интерфейс: {$interface['description']}\n";
                        if (isset($interface['status'])) {
                            echo "Статус: {$interface['status']}\n";
                        }
                        if (isset($interface['mac'])) {
                            echo "MAC: {$interface['mac']}\n";
                        }
                        echo "----------------\n";
                    }
                }
                break;

            default:
                die("Неизвестное действие: $action\n");
        }
    } catch (Exception $e) {
        die("Ошибка: " . $e->getMessage() . "\n");
    }
    exit(0);
}

// Обновляем HTTP интерфейс
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json; charset=utf-8');
    
    try {
        $input = json_decode(file_get_contents('php://input'), true);
        
        if (!isset($input['action'])) {
            throw new Exception("Необходимо указать действие");
        }

        if ($input['action'] === 'help') {
            $snmp = new DlinkSNMP('localhost');
            $docs = $snmp->getApiDocs();
            echo json_encode([
                'success' => true,
                'data' => $docs,
                'note' => 'При каждом обращении к коммутатору выполняется автоматическая проверка доступности и корректности SNMP community строк.'
            ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
            exit;
        }
        
        if (!isset($input['ip'])) {
            throw new Exception("Необходимо указать IP-адрес");
        }
        
        $snmp = new DlinkSNMP($input['ip']);
        $result = null;
        
        switch ($input['action']) {
            case 'info':
                $info = $snmp->getSwitchInfo();
                echo json_encode([
                    'success' => true,
                    'data' => $info
                ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
                break;

            case 'get':
                if (!isset($input['ports'])) {
                    throw new Exception("Необходимо указать порты");
                }
                $result = $snmp->getPortVlan($input['ports']);
                break;
                
            case 'add':
                if (!isset($input['ports']) || !isset($input['vlan'])) {
                    throw new Exception("Необходимо указать порты и VLAN");
                }
                $tagged = isset($input['tagged']) ? $input['tagged'] : false;
                $result = $snmp->addPortsToVlan($input['ports'], $input['vlan'], $tagged);
                break;
                
            case 'remove':
                if (!isset($input['ports']) || !isset($input['vlan'])) {
                    throw new Exception("Необходимо указать порты и VLAN");
                }
                $result = $snmp->removePortsFromVlan($input['ports'], $input['vlan']);
                break;
                
            case 'interfaces':
                $interfaces = $snmp->getInterfaces();
                echo "=== Интерфейсы коммутатора ===\n\n";
                
                echo "Физические порты:\n";
                echo "----------------\n";
                foreach ($interfaces as $interface) {
                    if ($interface['type'] === 'physical' || $interface['type'] === 'combo') {
                        $portType = $interface['type'] === 'physical' ? "Медный порт" : "Combo порт";
                        echo "Порт {$interface['index']} ($portType)\n";
                        echo "Описание: {$interface['description']}\n";
                        if (isset($interface['status'])) {
                            echo "Статус: {$interface['status']}\n";
                        }
                        if (isset($interface['speed'])) {
                            echo "Скорость: {$interface['speed']}\n";
                        }
                        if (isset($interface['mac'])) {
                            echo "MAC: {$interface['mac']}\n";
                        }
                        echo "----------------\n";
                    }
                }
                
                echo "\nVLAN интерфейсы:\n";
                echo "----------------\n";
                foreach ($interfaces as $interface) {
                    if ($interface['type'] === 'vlan') {
                        echo "Интерфейс: {$interface['description']}\n";
                        if (isset($interface['status'])) {
                            echo "Статус: {$interface['status']}\n";
                        }
                        echo "----------------\n";
                    }
                }
                
                echo "\nСистемные интерфейсы:\n";
                echo "----------------\n";
                foreach ($interfaces as $interface) {
                    if ($interface['type'] === 'system') {
                        echo "Интерфейс: {$interface['description']}\n";
                        if (isset($interface['status'])) {
                            echo "Статус: {$interface['status']}\n";
                        }
                        if (isset($interface['mac'])) {
                            echo "MAC: {$interface['mac']}\n";
                        }
                        echo "----------------\n";
                    }
                }
                break;
                
            default:
                throw new Exception("Неизвестное действие");
        }
        
        echo json_encode([
            'success' => true,
            'data' => $result
        ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
        
    } catch (Exception $e) {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error' => $e->getMessage()
        ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    }
} elseif ($_SERVER['REQUEST_METHOD'] === 'GET') {
    // Парсим URL для получения команды
    $path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
    $pathParts = explode('/', trim($path, '/'));
    $scriptParts = explode('/', $_SERVER['SCRIPT_NAME']);
    $baseScript = end($scriptParts);
    
    // Если запрос к корню - показываем HTML интерфейс
    if (count($pathParts) <= 1 || end($pathParts) === $baseScript) {
        header('Content-Type: text/html; charset=utf-8');
        // Используем HEREDOC для большого HTML блока
        echo <<<HTML
<!DOCTYPE html>
<html>
<head>
    <title>D-Link SNMP API</title>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .container { max-width: 800px; margin: 0 auto; }
        .endpoint { margin-bottom: 20px; padding: 10px; border: 1px solid #ddd; }
        .method { color: #666; }
        .url { color: #007bff; }
        .description { margin: 10px 0; }
        .params { margin-left: 20px; }
        .try-it { margin-top: 10px; }
        input, select { margin: 5px; padding: 5px; }
        button { padding: 5px 10px; background: #007bff; color: white; border: none; cursor: pointer; }
        button:hover { background: #0056b3; }
        #result { margin-top: 20px; padding: 10px; background: #f8f9fa; white-space: pre-wrap; }
        .examples {
            margin: 10px 0;
            padding: 10px;
            background: #f8f9fa;
            border-radius: 4px;
        }
        .examples h4 {
            margin: 0 0 10px 0;
            color: #666;
        }
        .tab-container {
            margin-bottom: 10px;
        }
        .tab-buttons {
            display: flex;
            gap: 2px;
            margin-bottom: 10px;
        }
        .tab-button {
            padding: 8px 16px;
            background: #e9ecef;
            border: none;
            cursor: pointer;
            border-radius: 4px 4px 0 0;
            font-size: 14px;
        }
        .tab-button:hover {
            background: #dee2e6;
        }
        .tab-button.active {
            background: #007bff;
            color: white;
        }
        .tab-content {
            display: none;
            padding: 15px;
            background: #fff;
            border: 1px solid #dee2e6;
            border-radius: 0 0 4px 4px;
        }
        .tab-content.active {
            display: block;
        }
        .tab-content pre {
            margin: 0;
            white-space: pre-wrap;
            font-family: monospace;
            font-size: 14px;
            background: #f8f9fa;
            padding: 10px;
            border-radius: 4px;
            color: #333;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>D-Link SNMP API</h1>
        <div class="endpoint">
            <h3>Получение информации о коммутаторе</h3>
            <div class="method">GET /snmp_api.php/info</div>
            <div class="description">Получение информации о коммутаторе (модель, имя, количество портов)</div>
            <div class="examples">
                <h4>Примеры использования:</h4>
                <div class="tab-container">
                    <div class="tab-buttons">
                        <button class="tab-button active" onclick="showTab(this, 'cli-info')">CLI</button>
                        <button class="tab-button" onclick="showTab(this, 'curl-info')">CURL</button>
                        <button class="tab-button" onclick="showTab(this, 'url-info')">URL</button>
                    </div>
                    <div id="cli-info" class="tab-content active">
                        <pre>php snmp_api.php 10.2.0.65 info</pre>
                    </div>
                    <div id="curl-info" class="tab-content">
                        <pre>curl -X POST -H "Content-Type: application/json" \\
     -d '{"ip":"10.2.0.65","action":"info"}' \\
     http://localhost:8000/snmp_api.php</pre>
                    </div>
                    <div id="url-info" class="tab-content">
                        <pre>http://localhost:8000/snmp_api.php/info?ip=10.2.0.65</pre>
                    </div>
                </div>
            </div>
            <div class="try-it">
                <input type="text" id="ip-info" placeholder="IP-адрес коммутатора">
                <button onclick="tryEndpoint('info')">Выполнить</button>
            </div>
        </div>
        
        <div class="endpoint">
            <h3>Получение информации о VLAN на портах</h3>
            <div class="method">GET /snmp_api.php/get</div>
            <div class="description">Получение информации о VLAN на указанных портах</div>
            <div class="examples">
                <h4>Примеры использования:</h4>
                <div class="tab-container">
                    <div class="tab-buttons">
                        <button class="tab-button active" onclick="showTab(this, 'cli-get')">CLI</button>
                        <button class="tab-button" onclick="showTab(this, 'curl-get')">CURL</button>
                        <button class="tab-button" onclick="showTab(this, 'url-get')">URL</button>
                    </div>
                    <div id="cli-get" class="tab-content active">
                        <pre>php snmp_api.php 10.2.0.65 get 1-4</pre>
                    </div>
                    <div id="curl-get" class="tab-content">
                        <pre>curl -X POST -H "Content-Type: application/json" \\
     -d '{"ip":"10.2.0.65","action":"get","ports":"1-4"}' \\
     http://localhost:8000/snmp_api.php</pre>
                    </div>
                    <div id="url-get" class="tab-content">
                        <pre>http://localhost:8000/snmp_api.php/get?ip=10.2.0.65&ports=1-4</pre>
                    </div>
                </div>
            </div>
            <div class="try-it">
                <input type="text" id="ip-get" placeholder="IP-адрес коммутатора">
                <input type="text" id="ports-get" placeholder="Порты (например: 1-4)">
                <button onclick="tryEndpoint('get')">Выполнить</button>
            </div>
        </div>
        
        <div class="endpoint">
            <h3>Добавление портов в VLAN</h3>
            <div class="method">GET /snmp_api.php/add</div>
            <div class="description">Добавление указанных портов в VLAN (tagged или untagged)</div>
            <div class="examples">
                <h4>Примеры использования:</h4>
                <div class="tab-container">
                    <div class="tab-buttons">
                        <button class="tab-button active" onclick="showTab(this, 'cli-add')">CLI</button>
                        <button class="tab-button" onclick="showTab(this, 'curl-add')">CURL</button>
                        <button class="tab-button" onclick="showTab(this, 'url-add')">URL</button>
                    </div>
                    <div id="cli-add" class="tab-content active">
                        <pre>php snmp_api.php 10.2.0.65 add 1-4 100</pre>
                    </div>
                    <div id="curl-add" class="tab-content">
                        <pre>curl -X POST -H "Content-Type: application/json" \\
     -d '{"ip":"10.2.0.65","action":"add","ports":"1-4","vlan":100,"tagged":false}' \\
     http://localhost:8000/snmp_api.php</pre>
                    </div>
                    <div id="url-add" class="tab-content">
                        <pre>http://localhost:8000/snmp_api.php/add?ip=10.2.0.65&ports=1-4&vlan=100&tagged=0</pre>
                    </div>
                </div>
            </div>
            <div class="try-it">
                <input type="text" id="ip-add" placeholder="IP-адрес коммутатора">
                <input type="text" id="ports-add" placeholder="Порты">
                <input type="number" id="vlan-add" placeholder="VLAN ID">
                <select id="tagged-add">
                    <option value="0">Untagged</option>
                    <option value="1">Tagged</option>
                </select>
                <button onclick="tryEndpoint('add')">Выполнить</button>
            </div>
        </div>
        
        <div class="endpoint">
            <h3>Удаление портов из VLAN</h3>
            <div class="method">GET /snmp_api.php/remove</div>
            <div class="description">Удаление указанных портов из VLAN</div>
            <div class="examples">
                <h4>Примеры использования:</h4>
                <div class="tab-container">
                    <div class="tab-buttons">
                        <button class="tab-button active" onclick="showTab(this, 'cli-remove')">CLI</button>
                        <button class="tab-button" onclick="showTab(this, 'curl-remove')">CURL</button>
                        <button class="tab-button" onclick="showTab(this, 'url-remove')">URL</button>
                    </div>
                    <div id="cli-remove" class="tab-content active">
                        <pre>php snmp_api.php 10.2.0.65 remove 1-4 100</pre>
                    </div>
                    <div id="curl-remove" class="tab-content">
                        <pre>curl -X POST -H "Content-Type: application/json" \\
     -d '{"ip":"10.2.0.65","action":"remove","ports":"1-4","vlan":100}' \\
     http://localhost:8000/snmp_api.php</pre>
                    </div>
                    <div id="url-remove" class="tab-content">
                        <pre>http://localhost:8000/snmp_api.php/remove?ip=10.2.0.65&ports=1-4&vlan=100</pre>
                    </div>
                </div>
            </div>
            <div class="try-it">
                <input type="text" id="ip-remove" placeholder="IP-адрес коммутатора">
                <input type="text" id="ports-remove" placeholder="Порты">
                <input type="number" id="vlan-remove" placeholder="VLAN ID">
                <button onclick="tryEndpoint('remove')">Выполнить</button>
            </div>
        </div>
        
        <div class="endpoint">
            <h3>Получение информации об интерфейсах</h3>
            <div class="method">GET /snmp_api.php/interfaces</div>
            <div class="description">Получение информации о всех интерфейсах коммутатора</div>
            <div class="examples">
                <h4>Примеры использования:</h4>
                <div class="tab-container">
                    <div class="tab-buttons">
                        <button class="tab-button active" onclick="showTab(this, 'cli-interfaces')">CLI</button>
                        <button class="tab-button" onclick="showTab(this, 'curl-interfaces')">CURL</button>
                        <button class="tab-button" onclick="showTab(this, 'url-interfaces')">URL</button>
                    </div>
                    <div id="cli-interfaces" class="tab-content active">
                        <pre>php snmp_api.php 10.2.0.65 interfaces</pre>
                    </div>
                    <div id="curl-interfaces" class="tab-content">
                        <pre>curl -X POST -H "Content-Type: application/json" \\
     -d '{"ip":"10.2.0.65","action":"interfaces"}' \\
     http://localhost:8000/snmp_api.php</pre>
                    </div>
                    <div id="url-interfaces" class="tab-content">
                        <pre>http://localhost:8000/snmp_api.php/interfaces?ip=10.2.0.65</pre>
                    </div>
                </div>
            </div>
            <div class="try-it">
                <input type="text" id="ip-interfaces" placeholder="IP-адрес коммутатора">
                <button onclick="tryEndpoint('interfaces')">Выполнить</button>
            </div>
        </div>
        
        <div class="endpoint">
            <h3>Получение документации</h3>
            <div class="method">GET /snmp_api.php/help</div>
            <div class="description">Получение полной документации по API</div>
            <div class="examples">
                <h4>Примеры использования:</h4>
                <div class="tab-container">
                    <div class="tab-buttons">
                        <button class="tab-button active" onclick="showTab(this, 'cli-help')">CLI</button>
                        <button class="tab-button" onclick="showTab(this, 'curl-help')">CURL</button>
                        <button class="tab-button" onclick="showTab(this, 'url-help')">URL</button>
                    </div>
                    <div id="cli-help" class="tab-content active">
                        <pre>php snmp_api.php help</pre>
                    </div>
                    <div id="curl-help" class="tab-content">
                        <pre>curl -X POST -H "Content-Type: application/json" \\
     -d '{"action":"help"}' \\
     http://localhost:8000/snmp_api.php</pre>
                    </div>
                    <div id="url-help" class="tab-content">
                        <pre>http://localhost:8000/snmp_api.php/help</pre>
                    </div>
                </div>
            </div>
            <div class="try-it">
                <button onclick="tryEndpoint('help')">Получить документацию</button>
            </div>
        </div>
        
        <div id="result"></div>
    </div>
    
    <script>
    function showTab(button, tabId) {
        // Находим контейнер вкладок
        const tabContainer = button.closest('.tab-container');
        
        // Деактивируем все кнопки и скрываем все содержимое
        tabContainer.querySelectorAll('.tab-button').forEach(btn => btn.classList.remove('active'));
        tabContainer.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
        
        // Активируем выбранную кнопку и показываем соответствующее содержимое
        button.classList.add('active');
        document.getElementById(tabId).classList.add('active');
    }
    
    async function tryEndpoint(action) {
        const ip = document.getElementById('ip-' + action).value;
        let url = '/snmp_api.php/' + action + '?ip=' + encodeURIComponent(ip);
        
        if (action === "get" || action === "add" || action === "remove") {
            const ports = document.getElementById('ports-' + action).value;
            if (ports) {
                url += '&ports=' + encodeURIComponent(ports);
            }
        }
        
        if (action === "add" || action === "remove") {
            const vlan = document.getElementById('vlan-' + action).value;
            if (vlan) {
                url += '&vlan=' + encodeURIComponent(vlan);
            }
        }
        
        if (action === "add") {
            const tagged = document.getElementById("tagged-add").value;
            if (tagged) {
                url += '&tagged=' + encodeURIComponent(tagged);
            }
        }
        
        try {
            const response = await fetch(url);
            const data = await response.json();
            document.getElementById("result").textContent = JSON.stringify(data, null, 2);
        } catch (err) {
            document.getElementById("result").textContent = "Ошибка: " + (err.message || "Неизвестная ошибка");
        }
    }
    </script>
</body>
</html>
HTML;
        exit;
    }
    
    // Получаем команду из URL
    $command = end($pathParts);
    
    header('Content-Type: application/json; charset=utf-8');
    
    try {
        // Проверяем наличие IP в параметрах
        if (!isset($_GET['ip']) && $command !== 'help') {
            throw new Exception("Необходимо указать IP-адрес");
        }
        
        if ($command === 'help') {
            $snmp = new DlinkSNMP('localhost');
            $docs = $snmp->getApiDocs();
            echo json_encode([
                'success' => true,
                'data' => $docs
            ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
            exit;
        }
        
        $snmp = new DlinkSNMP($_GET['ip']);
        $result = null;
        
        switch ($command) {
            case 'info':
                $result = $snmp->getSwitchInfo();
                break;
                
            case 'get':
                if (!isset($_GET['ports'])) {
                    throw new Exception("Необходимо указать порты");
                }
                $result = $snmp->getPortVlan($_GET['ports']);
                break;
                
            case 'add':
                if (!isset($_GET['ports']) || !isset($_GET['vlan'])) {
                    throw new Exception("Необходимо указать порты и VLAN");
                }
                $tagged = isset($_GET['tagged']) ? (bool)$_GET['tagged'] : false;
                $result = $snmp->addPortsToVlan($_GET['ports'], $_GET['vlan'], $tagged);
                break;
                
            case 'remove':
                if (!isset($_GET['ports']) || !isset($_GET['vlan'])) {
                    throw new Exception("Необходимо указать порты и VLAN");
                }
                $result = $snmp->removePortsFromVlan($_GET['ports'], $_GET['vlan']);
                break;
                
            case 'interfaces':
                $interfaces = $snmp->getInterfaces();
                echo "=== Интерфейсы коммутатора ===\n\n";
                
                echo "Физические порты:\n";
                echo "----------------\n";
                foreach ($interfaces as $interface) {
                    if ($interface['type'] === 'physical' || $interface['type'] === 'combo') {
                        $portType = $interface['type'] === 'physical' ? "Медный порт" : "Combo порт";
                        echo "Порт {$interface['index']} ($portType)\n";
                        echo "Описание: {$interface['description']}\n";
                        if (isset($interface['status'])) {
                            echo "Статус: {$interface['status']}\n";
                        }
                        if (isset($interface['speed'])) {
                            echo "Скорость: {$interface['speed']}\n";
                        }
                        if (isset($interface['mac'])) {
                            echo "MAC: {$interface['mac']}\n";
                        }
                        echo "----------------\n";
                    }
                }
                
                echo "\nVLAN интерфейсы:\n";
                echo "----------------\n";
                foreach ($interfaces as $interface) {
                    if ($interface['type'] === 'vlan') {
                        echo "Интерфейс: {$interface['description']}\n";
                        if (isset($interface['status'])) {
                            echo "Статус: {$interface['status']}\n";
                        }
                        echo "----------------\n";
                    }
                }
                
                echo "\nСистемные интерфейсы:\n";
                echo "----------------\n";
                foreach ($interfaces as $interface) {
                    if ($interface['type'] === 'system') {
                        echo "Интерфейс: {$interface['description']}\n";
                        if (isset($interface['status'])) {
                            echo "Статус: {$interface['status']}\n";
                        }
                        if (isset($interface['mac'])) {
                            echo "MAC: {$interface['mac']}\n";
                        }
                        echo "----------------\n";
                    }
                }
                break;
                
            default:
                throw new Exception("Неизвестное действие");
        }
        
        echo json_encode([
            'success' => true,
            'data' => $result
        ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
        
    } catch (Exception $e) {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error' => $e->getMessage()
        ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    }
} else {
    http_response_code(405);
    echo json_encode([
        'success' => false,
        'error' => 'Метод не поддерживается'
    ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
}
?>
