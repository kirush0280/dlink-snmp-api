<?php
require 'config.php';
require 'Logger.php';

class DlinkSNMP {
    private $ip;
    private $readOnlyCommunity;
    private $readWriteCommunity;
    private $portCount;
    private $maxBytes;
    private $logger;

    public function __construct($ip) {
        $this->logger = Logger::getInstance();
        $this->logger->info("Инициализация DlinkSNMP для IP: $ip");
        
        $config = include 'config.php';
        $this->ip = $ip;
        $this->readOnlyCommunity = $config['snmp']['read_only_community'];
        $this->readWriteCommunity = $config['snmp']['read_write_community'];
        
        // Пропускаем проверку для вызова help
        if ($ip !== 'localhost') {
            try {
                // Проверяем read-only community
                $this->logger->debug("Проверка read-only community...");
                $this->checkSnmpCommunity($this->readOnlyCommunity, 'read-only');
                $this->logger->info("Read-only community работает корректно");
                
                // Проверяем read-write community
                $this->logger->debug("Проверка read-write community...");
                $this->checkSnmpCommunity($this->readWriteCommunity, 'read-write');
                $this->logger->info("Read-write community работает корректно");
                
                // Определяем количество портов при инициализации
                $this->portCount = $this->getPortCount();
                $this->logger->info("Определено количество портов: {$this->portCount}");
                
                // Вычисляем количество байт для маски на основе количества портов
                $this->maxBytes = ceil($this->portCount / 8);
                $this->logger->debug("Установлен размер маски: {$this->maxBytes} байт");
            } catch (Exception $e) {
                $this->logger->error("Ошибка инициализации SNMP: " . $e->getMessage());
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

    // Получение подробной информации о VLAN'ах
    public function getVlanDetails() {
        $vlans = [];
        $result = snmp2_real_walk($this->ip, $this->readOnlyCommunity, ".1.3.6.1.2.1.17.7.1.4.3.1.1");
        
        if (is_array($result)) {
            foreach ($result as $oid => $value) {
                if (preg_match('/\.(\d+)$/', $oid, $matches)) {
                    $vlanId = $matches[1];
                    $vlanInfo = [
                        'id' => $vlanId,
                        'name' => preg_replace('/STRING: "(.*)"/', '$1', $value),
                        'ports' => [
                            'tagged' => [],
                            'untagged' => []
                        ]
                    ];
                    
                    // Получаем маски для tagged и untagged портов
                    $taggedMask = $this->getVlanMask($vlanId, 'tagged');
                    $untaggedMask = $this->getVlanMask($vlanId, 'untagged');
                    
                    // Анализируем маски и определяем порты
                    if ($taggedMask) {
                        for ($port = 1; $port <= $this->portCount; $port++) {
                            $byteIndex = floor(($port - 1) / 8);
                            $bitInByte = 7 - (($port - 1) % 8);
                            $bitMask = 1 << $bitInByte;
                            
                            if ($byteIndex < count($taggedMask)) {
                                if (hexdec($taggedMask[$byteIndex]) & $bitMask) {
                                    // Проверяем, не является ли порт untagged
                                    $isUntagged = false;
                                    if ($untaggedMask && $byteIndex < count($untaggedMask)) {
                                        if (hexdec($untaggedMask[$byteIndex]) & $bitMask) {
                                            $isUntagged = true;
                                        }
                                    }
                                    
                                    if (!$isUntagged) {
                                        $vlanInfo['ports']['tagged'][] = $port;
                                    }
                                }
                            }
                        }
                    }
                    
                    if ($untaggedMask) {
                        for ($port = 1; $port <= $this->portCount; $port++) {
                            $byteIndex = floor(($port - 1) / 8);
                            $bitInByte = 7 - (($port - 1) % 8);
                            $bitMask = 1 << $bitInByte;
                            
                            if ($byteIndex < count($untaggedMask)) {
                                if (hexdec($untaggedMask[$byteIndex]) & $bitMask) {
                                    $vlanInfo['ports']['untagged'][] = $port;
                                }
                            }
                        }
                    }
                    
                    $vlans[] = $vlanInfo;
                }
            }
        }
        
        return $vlans;
    }

    // Проверка существования VLAN
    private function checkVlanExists($vlanId) {
        return $this->getVlanMask($vlanId) !== null;
    }

    // Логирование текущего состояния VLAN'ов
    private function logVlanState($operation) {
        $this->logger->info("=== Текущее состояние VLAN'ов перед операцией: $operation ===");
        
        // Получаем список всех VLAN'ов
        $vlans = $this->getVlanDetails();
        
        foreach ($vlans as $vlan) {
            $this->logger->info("VLAN {$vlan['id']} ({$vlan['name']})");
            $this->logger->info("  Tagged порты: " . (empty($vlan['ports']['tagged']) ? "нет" : implode(", ", $vlan['ports']['tagged'])));
            $this->logger->info("  Untagged порты: " . (empty($vlan['ports']['untagged']) ? "нет" : implode(", ", $vlan['ports']['untagged'])));
        }
        $this->logger->info("================================================");
    }

    private function validateVlanId($vlanId) {
        if (!is_numeric($vlanId)) {
            throw new Exception("VLAN ID должен быть числом");
        }
        
        $vlanId = intval($vlanId);
        if ($vlanId < 1 || $vlanId > 4094) {
            throw new Exception("VLAN ID должен быть в диапазоне от 1 до 4094");
        }
        
        return $vlanId;
    }

    private function validatePorts($portsStr) {
        $parts = explode(',', $portsStr);
        $allPorts = [];
        
        foreach ($parts as $part) {
            if (strpos($part, '-') !== false) {
                list($start, $end) = explode('-', $part);
                if (!is_numeric($start) || !is_numeric($end)) {
                    throw new Exception("Некорректный формат портов: $part");
                }
                if ($start > $end) {
                    throw new Exception("Начальный порт больше конечного: $part");
                }
                if ($start < 1 || $end > $this->portCount) {
                    throw new Exception("Порты должны быть в диапазоне от 1 до {$this->portCount}");
                }
                $allPorts = array_merge($allPorts, range($start, $end));
            } else {
                if (!is_numeric($part)) {
                    throw new Exception("Некорректный номер порта: $part");
                }
                $port = intval($part);
                if ($port < 1 || $port > $this->portCount) {
                    throw new Exception("Порт $port выходит за пределы диапазона (1-{$this->portCount})");
                }
                $allPorts[] = $port;
            }
        }
        
        return array_unique($allPorts);
    }

    private function handleSnmpError($operation, $details = '') {
        $error = error_get_last();
        $errorMessage = $error ? $error['message'] : 'Неизвестная ошибка';
        $this->logger->error("Ошибка SNMP при $operation: $errorMessage $details");
        throw new Exception("Ошибка SNMP при $operation: $errorMessage");
    }

    // Обновляем метод createVlan с новыми проверками
    public function createVlan($vlanId) {
        try {
            $vlanId = $this->validateVlanId($vlanId);
            $this->logVlanState("создание VLAN $vlanId");
            $this->logger->info("Попытка создания VLAN $vlanId");
            
            // Добавляем отладочный вывод
            $this->logger->debug("Используемая read-write community строка: " . $this->readWriteCommunity);
            
            // Проверяем, не существует ли уже VLAN
            if ($this->checkVlanExists($vlanId)) {
                $this->logger->warning("VLAN $vlanId уже существует");
                throw new Exception("VLAN $vlanId уже существует");
            }

            // 1. Создаем VLAN через dot1qVlanStaticRowStatus
            $this->logger->debug("Создание VLAN $vlanId через dot1qVlanStaticRowStatus");
            $result = snmp2_set($this->ip, $this->readWriteCommunity,
                              ".1.3.6.1.2.1.17.7.1.4.3.1.5.$vlanId",
                              'i', 4); // createAndGo(4)
            
            if ($result === false) {
                $this->handleSnmpError("создании VLAN", "VLAN ID: $vlanId");
            }

            // Добавляем задержку для обработки операции коммутатором
            sleep(2);

            // 2. Устанавливаем имя VLAN
            $this->logger->debug("Установка имени для VLAN $vlanId");
            $result = snmp2_set($this->ip, $this->readWriteCommunity,
                              ".1.3.6.1.2.1.17.7.1.4.3.1.1.$vlanId",
                              's', "$vlanId");
            
            if ($result === false) {
                $this->handleSnmpError("установке имени VLAN", "VLAN ID: $vlanId");
            }

            // Проверяем, что VLAN действительно создан
            if (!$this->checkVlanExists($vlanId)) {
                $this->logger->error("VLAN $vlanId не был создан");
                throw new Exception("VLAN не был создан");
            }

            $this->logger->info("VLAN $vlanId успешно создан");
            return true;
        } catch (Exception $e) {
            $this->logger->error("Ошибка создания VLAN $vlanId: " . $e->getMessage());
            throw new Exception("Ошибка создания VLAN: " . $e->getMessage());
        }
    }

    // Удаление VLAN
    public function deleteVlan($vlanId) {
        try {
            $this->logVlanState("удаление VLAN $vlanId");
            $this->logger->info("Попытка удаления VLAN $vlanId");
            
            // Проверяем существование VLAN
            if (!$this->checkVlanExists($vlanId)) {
                $this->logger->warning("VLAN $vlanId не существует");
                throw new Exception("VLAN $vlanId не существует");
            }

            // Получаем информацию о VLAN
            $vlanDetails = $this->getVlanDetails();
            $vlanInfo = null;
            foreach ($vlanDetails as $vlan) {
                if ($vlan['id'] == $vlanId) {
                    $vlanInfo = $vlan;
                    break;
                }
            }

            if (!$vlanInfo) {
                $this->logger->error("Не удалось получить информацию о VLAN $vlanId");
                throw new Exception("Не удалось получить информацию о VLAN $vlanId");
            }

            // Проверяем, нет ли портов в VLAN
            if (!empty($vlanInfo['ports']['tagged']) || !empty($vlanInfo['ports']['untagged'])) {
                $this->logger->warning("VLAN $vlanId содержит порты. Сначала удалите все порты из VLAN");
                throw new Exception("VLAN $vlanId содержит порты. Сначала удалите все порты из VLAN.");
            }

            // Удаляем VLAN через dot1qVlanStaticRowStatus
            $this->logger->debug("Удаление VLAN $vlanId через dot1qVlanStaticRowStatus");
            $result = snmp2_set($this->ip, $this->readWriteCommunity,
                              ".1.3.6.1.2.1.17.7.1.4.3.1.5.$vlanId",
                              'i', 6); // destroy(6)
            
            if ($result === false) {
                $this->logger->error("Ошибка удаления VLAN $vlanId");
                throw new Exception("Ошибка удаления VLAN");
            }

            $this->logger->info("VLAN $vlanId успешно удален");
            return true;
        } catch (Exception $e) {
            $this->logger->error("Ошибка удаления VLAN $vlanId: " . $e->getMessage());
            throw new Exception("Ошибка удаления VLAN: " . $e->getMessage());
        }
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

    // Обновляем метод addPortsToVlan с новыми проверками
    public function addPortsToVlan($portsStr, $vlanId, $tagged = false) {
        try {
            $vlanId = $this->validateVlanId($vlanId);
            $validatedPorts = $this->validatePorts($portsStr);
            
            if (!$this->checkVlanExists($vlanId)) {
                throw new Exception("VLAN $vlanId не существует");
            }

            $this->logVlanState("добавление портов " . implode(',', $validatedPorts) . " в VLAN $vlanId как " . ($tagged ? "tagged" : "untagged"));
            
            // Получаем текущие маски
            $currentTaggedMask = $this->getVlanMask($vlanId, 'tagged');
            $currentUntaggedMask = $this->getVlanMask($vlanId, 'untagged');
            
            if (!$currentTaggedMask || !$currentUntaggedMask) {
                throw new Exception("Не удалось получить текущие маски портов");
            }
            
            // Создаем маску для новых портов
            $newPortsMask = $this->createPortMask(implode(',', $validatedPorts));
            
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
                    $this->handleSnmpError("добавлении tagged портов", "VLAN ID: $vlanId, Порты: $portsStr");
                }
            } else {
                // Для untagged портов
                $untaggedValues = array_map(function($current, $new) {
                    return sprintf("%02X", hexdec($current) | hexdec($new));
                }, $currentUntaggedMask, $newPortsMask);
                
                $result = snmp2_set($this->ip, $this->readWriteCommunity,
                                  ".1.3.6.1.2.1.17.7.1.4.3.1.4.$vlanId",
                                  'x', implode(" ", $untaggedValues));
                
                if ($result === false) {
                    $this->handleSnmpError("добавлении untagged портов", "VLAN ID: $vlanId, Порты: $portsStr");
                }
            }
            
            return true;
        } catch (Exception $e) {
            $this->logger->error("Ошибка добавления портов в VLAN: " . $e->getMessage());
            throw new Exception("Ошибка добавления портов в VLAN: " . $e->getMessage());
        }
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
                'vlans' => [
                    'description' => 'Получение списка VLAN с подробной информацией',
                    'usage' => [
                        'cli' => 'php snmp_api.php <ip> vlans',
                        'http' => [
                            'method' => 'POST',
                            'endpoint' => '/',
                            'body' => [
                                'ip' => 'string (IP-адрес коммутатора)',
                                'action' => 'vlans'
                            ]
                        ],
                        'get' => [
                            'url' => '/snmp_api.php/vlans?ip=<ip>',
                            'example' => '/snmp_api.php/vlans?ip=10.2.0.65'
                        ]
                    ],
                    'returns' => [
                        'vlan_id' => 'Идентификатор VLAN',
                        'name' => 'Имя VLAN',
                        'ports' => [
                            'tagged' => 'Список портов с тегированным трафиком',
                            'untagged' => 'Список портов с нетегированным трафиком'
                        ]
                    ],
                    'examples' => [
                        'cli' => 'php snmp_api.php 10.2.0.65 vlans',
                        'curl' => 'curl -X POST -H "Content-Type: application/json" -d \'{"ip":"10.2.0.65","action":"vlans"}\' http://localhost:8000/snmp_api.php',
                        'browser' => 'http://localhost:8000/snmp_api.php/vlans?ip=10.2.0.65'
                    ]
                ],
                'create' => [
                    'description' => 'Создание нового VLAN',
                    'usage' => [
                        'cli' => 'php snmp_api.php <ip> create <vlan_id>',
                        'http' => [
                            'method' => 'POST',
                            'endpoint' => '/',
                            'body' => [
                                'ip' => 'string (IP-адрес коммутатора)',
                                'action' => 'create',
                                'vlan' => 'integer (номер VLAN)'
                            ]
                        ],
                        'get' => [
                            'url' => '/snmp_api.php/create?ip=<ip>&vlan=<vlan>',
                            'example' => '/snmp_api.php/create?ip=10.2.0.65&vlan=100'
                        ]
                    ],
                    'returns' => [
                        'success' => 'true/false',
                        'message' => 'Сообщение об успехе или ошибке'
                    ],
                    'examples' => [
                        'cli' => 'php snmp_api.php 10.2.0.65 create 100',
                        'curl' => 'curl -X POST -H "Content-Type: application/json" -d \'{"ip":"10.2.0.65","action":"create","vlan":100}\' http://localhost:8000/snmp_api.php',
                        'browser' => 'http://localhost:8000/snmp_api.php/create?ip=10.2.0.65&vlan=100'
                    ]
                ],
                'delete' => [
                    'description' => 'Удаление VLAN',
                    'usage' => [
                        'cli' => 'php snmp_api.php <ip> delete <vlan_id>',
                        'http' => [
                            'method' => 'POST',
                            'endpoint' => '/',
                            'body' => [
                                'ip' => 'string (IP-адрес коммутатора)',
                                'action' => 'delete',
                                'vlan' => 'integer (номер VLAN)'
                            ]
                        ],
                        'get' => [
                            'url' => '/snmp_api.php/delete?ip=<ip>&vlan=<vlan>',
                            'example' => '/snmp_api.php/delete?ip=10.2.0.65&vlan=100'
                        ]
                    ],
                    'returns' => [
                        'success' => 'true/false',
                        'message' => 'Сообщение об успехе или ошибке'
                    ],
                    'notes' => [
                        'Перед удалением VLAN необходимо удалить все порты из него',
                        'Если в VLAN есть порты, операция удаления будет отклонена'
                    ],
                    'examples' => [
                        'cli' => 'php snmp_api.php 10.2.0.65 delete 100',
                        'curl' => 'curl -X POST -H "Content-Type: application/json" -d \'{"ip":"10.2.0.65","action":"delete","vlan":100}\' http://localhost:8000/snmp_api.php',
                        'browser' => 'http://localhost:8000/snmp_api.php/delete?ip=10.2.0.65&vlan=100'
                    ]
                ],
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
                // Для read-write пробуем получить и установить sysName
                $currentName = snmp2_get($this->ip, $community, '.1.3.6.1.2.1.1.5.0');
                if ($currentName === false) {
                    throw new Exception("Ошибка проверки read-write community (чтение)");
                }
                
                // Извлекаем текущее имя из строки вида 'STRING: "name"'
                if (preg_match('/STRING: "(.*)"/', $currentName, $matches)) {
                    $currentName = $matches[1];
                }
                
                // Пробуем установить то же самое значение обратно
                $result = snmp2_set($this->ip, $community, '.1.3.6.1.2.1.1.5.0', 's', $currentName);
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
    $logger = Logger::getInstance();
    $logger->info("Запуск CLI интерфейса");
    
    if ($argc < 2) {
        $logger->warning("Недостаточно аргументов командной строки");
        die("Использование: php snmp_api.php <ip> <action> [ports] [vlan] [tagged]\n" .
            "Для получения полной документации используйте: php snmp_api.php help\n\n" .
            "Примечание: При каждом обращении к коммутатору выполняется автоматическая проверка\n" .
            "доступности и корректности SNMP community строк.\n");
    }

    try {
        if ($argv[1] === 'help') {
            $logger->info("Запрошена справка");
            $snmp = new DlinkSNMP('localhost');
            echo $snmp->getApiDocs();
            exit(0);
        }

        $ip = $argv[1];
        $action = $argv[2];
        
        $logger->info("Выполнение команды: $action для IP: $ip");
        
        // Специальная обработка для команд create и delete
        if (($action === 'create' || $action === 'delete') && isset($argv[3])) {
            $vlan = intval($argv[3]);
            $ports = null;
        } else {
            $ports = isset($argv[3]) ? $argv[3] : null;
            $vlan = isset($argv[4]) ? intval($argv[4]) : null;
        }
        
        $tagged = isset($argv[5]) ? (bool)$argv[5] : false;

        $logger->debug("Параметры команды: IP=$ip, Action=$action, Ports=" . ($ports ?? 'null') . 
                      ", VLAN=" . ($vlan ?? 'null') . ", Tagged=" . ($tagged ? 'true' : 'false'));

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
                    die("Для добавления портов необходимо указать VLAN\n" .
                        "Использование: php snmp_api.php <ip> add <ports> <vlan> [tagged]\n");
                }
                $result = $snmp->addPortsToVlan($ports, $vlan, $tagged);
                echo "Порты $ports успешно добавлены в VLAN $vlan как " . ($tagged ? "tagged" : "untagged") . "\n";
                break;

            case 'remove':
                if ($vlan === null) {
                    die("Для удаления портов необходимо указать VLAN\n" .
                        "Использование: php snmp_api.php <ip> remove <ports> <vlan>\n");
                }
                $result = $snmp->removePortsFromVlan($ports, $vlan);
                echo "Порты $ports успешно удалены из VLAN $vlan\n";
                break;

            case 'create':
                if ($vlan === null) {
                    die("Для создания VLAN необходимо указать ID\n" .
                        "Использование: php snmp_api.php <ip> create <vlan_id>\n");
                }
                $result = $snmp->createVlan($vlan);
                echo "VLAN $vlan успешно создан\n";
                break;

            case 'delete':
                echo "DEBUG: Вход в case 'delete'\n";
                echo "DEBUG: vlan = " . ($vlan ?? 'null') . "\n";
                if ($vlan === null) {
                    die("Для удаления VLAN необходимо указать ID\n" .
                        "Использование: php snmp_api.php <ip> delete <vlan_id>\n");
                }
                $result = $snmp->deleteVlan($vlan);
                echo "VLAN $vlan успешно удален\n";
                break;

            case 'vlans':
                $vlans = $snmp->getVlanDetails();
                echo "=== Список VLAN'ов ===\n";
                foreach ($vlans as $vlan) {
                    echo "\nVLAN {$vlan['id']} ({$vlan['name']})\n";
                    echo "Tagged порты: " . (empty($vlan['ports']['tagged']) ? "нет" : implode(", ", $vlan['ports']['tagged'])) . "\n";
                    echo "Untagged порты: " . (empty($vlan['ports']['untagged']) ? "нет" : implode(", ", $vlan['ports']['untagged'])) . "\n";
                }
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
                
            case 'create':
                if (!isset($input['vlan'])) {
                    throw new Exception("Необходимо указать ID VLAN");
                }
                $result = $snmp->createVlan($input['vlan']);
                break;
                
            case 'delete':
                echo "DEBUG: Вход в case 'delete'\n";
                echo "DEBUG: vlan = " . ($input['vlan'] ?? 'null') . "\n";
                if ($input['vlan'] === null) {
                    throw new Exception("Необходимо указать ID VLAN");
                }
                $result = $snmp->deleteVlan($input['vlan']);
                echo "VLAN " . $input['vlan'] . " успешно удален\n";
                break;

            case 'vlans':
                $result = $snmp->getVlanDetails();
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
        .returns {
            margin: 10px 0;
            padding: 10px;
            background: #e9ecef;
            border-radius: 4px;
        }
        .returns h4 {
            margin: 0 0 10px 0;
            color: #666;
        }
        .returns pre {
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
            <div class="returns">
                <h4>Возвращаемые данные:</h4>
                <pre>{
    "success": true,
    "data": {
        "name": "имя коммутатора",
        "model": "модель коммутатора",
        "port_count": "количество портов",
        "max_bytes": "размер маски в байтах"
    }
}</pre>
            </div>
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
            <div class="returns">
                <h4>Возвращаемые данные:</h4>
                <pre>{
    "success": true,
    "data": [
        {
            "port": "номер порта",
            "vlans": [
                {
                    "vlan": "номер VLAN",
                    "type": "tagged/untagged"
                }
            ]
        }
    ]
}</pre>
            </div>
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
            <div class="returns">
                <h4>Возвращаемые данные:</h4>
                <pre>{
    "success": true,
    "data": true
}</pre>
            </div>
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
            <div class="returns">
                <h4>Возвращаемые данные:</h4>
                <pre>{
    "success": true,
    "data": true
}</pre>
            </div>
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
            <div class="returns">
                <h4>Возвращаемые данные:</h4>
                <pre>{
    "success": true,
    "data": [
        {
            "index": "номер интерфейса",
            "description": "описание интерфейса",
            "type": "тип интерфейса (physical/combo/vlan/system)",
            "status": "статус интерфейса",
            "speed": "скорость интерфейса",
            "mac": "MAC-адрес интерфейса"
        }
    ]
}</pre>
            </div>
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
            <div class="returns">
                <h4>Возвращаемые данные:</h4>
                <pre>{
    "success": true,
    "data": {
        "description": "описание API",
        "version": "версия API",
        "security": {
            "description": "информация о безопасности",
            "checks": {
                "read_only": {
                    "description": "проверка read-only community",
                    "oid": "OID для проверки"
                },
                "read_write": {
                    "description": "проверка read-write community",
                    "oid": "OID для проверки"
                }
            }
        },
        "endpoints": {
            "описание всех доступных эндпоинтов"
        }
    },
    "note": "дополнительная информация"
}</pre>
            </div>
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
        
        <div class="endpoint">
            <h3>Получение списка VLAN</h3>
            <div class="method">GET /snmp_api.php/vlans</div>
            <div class="description">Получение подробной информации о всех VLAN'ах на коммутаторе</div>
            <div class="returns">
                <h4>Возвращаемые данные:</h4>
                <pre>{
    "success": true,
    "data": [
        {
            "id": "номер VLAN",
            "name": "имя VLAN",
            "ports": {
                "tagged": ["список портов с тегированным трафиком"],
                "untagged": ["список портов с нетегированным трафиком"]
            }
        }
    ]
}</pre>
            </div>
            <div class="examples">
                <h4>Примеры использования:</h4>
                <div class="tab-container">
                    <div class="tab-buttons">
                        <button class="tab-button active" onclick="showTab(this, 'cli-vlans')">CLI</button>
                        <button class="tab-button" onclick="showTab(this, 'curl-vlans')">CURL</button>
                        <button class="tab-button" onclick="showTab(this, 'url-vlans')">URL</button>
                    </div>
                    <div id="cli-vlans" class="tab-content active">
                        <pre>php snmp_api.php 10.2.0.65 vlans</pre>
                    </div>
                    <div id="curl-vlans" class="tab-content">
                        <pre>curl -X POST -H "Content-Type: application/json" \\
     -d '{"ip":"10.2.0.65","action":"vlans"}' \\
     http://localhost:8000/snmp_api.php</pre>
                    </div>
                    <div id="url-vlans" class="tab-content">
                        <pre>http://localhost:8000/snmp_api.php/vlans?ip=10.2.0.65</pre>
                    </div>
                </div>
            </div>
            <div class="try-it">
                <input type="text" id="ip-vlans" placeholder="IP-адрес коммутатора">
                <button onclick="tryEndpoint('vlans')">Выполнить</button>
            </div>
        </div>

        <div class="endpoint">
            <h3>Создание VLAN</h3>
            <div class="method">GET /snmp_api.php/create</div>
            <div class="description">Создание нового VLAN на коммутаторе</div>
            <div class="returns">
                <h4>Возвращаемые данные:</h4>
                <pre>{
    "success": true,
    "data": true
}</pre>
            </div>
            <div class="examples">
                <h4>Примеры использования:</h4>
                <div class="tab-container">
                    <div class="tab-buttons">
                        <button class="tab-button active" onclick="showTab(this, 'cli-create')">CLI</button>
                        <button class="tab-button" onclick="showTab(this, 'curl-create')">CURL</button>
                        <button class="tab-button" onclick="showTab(this, 'url-create')">URL</button>
                    </div>
                    <div id="cli-create" class="tab-content active">
                        <pre>php snmp_api.php 10.2.0.65 create 100</pre>
                    </div>
                    <div id="curl-create" class="tab-content">
                        <pre>curl -X POST -H "Content-Type: application/json" \\
     -d '{"ip":"10.2.0.65","action":"create","vlan":100}' \\
     http://localhost:8000/snmp_api.php</pre>
                    </div>
                    <div id="url-create" class="tab-content">
                        <pre>http://localhost:8000/snmp_api.php/create?ip=10.2.0.65&vlan=100</pre>
                    </div>
                </div>
            </div>
            <div class="try-it">
                <input type="text" id="ip-create" placeholder="IP-адрес коммутатора">
                <input type="number" id="vlan-create" placeholder="VLAN ID">
                <button onclick="tryEndpoint('create')">Выполнить</button>
            </div>
        </div>

        <div class="endpoint">
            <h3>Удаление VLAN</h3>
            <div class="method">GET /snmp_api.php/delete</div>
            <div class="description">Удаление VLAN с коммутатора</div>
            <div class="returns">
                <h4>Возвращаемые данные:</h4>
                <pre>{
    "success": true,
    "data": true
}</pre>
            </div>
            <div class="notes">
                <p><strong>Важно:</strong> Перед удалением VLAN необходимо удалить все порты из него.</p>
                <p>Если в VLAN есть порты, операция удаления будет отклонена.</p>
            </div>
            <div class="examples">
                <h4>Примеры использования:</h4>
                <div class="tab-container">
                    <div class="tab-buttons">
                        <button class="tab-button active" onclick="showTab(this, 'cli-delete')">CLI</button>
                        <button class="tab-button" onclick="showTab(this, 'curl-delete')">CURL</button>
                        <button class="tab-button" onclick="showTab(this, 'url-delete')">URL</button>
                    </div>
                    <div id="cli-delete" class="tab-content active">
                        <pre>php snmp_api.php 10.2.0.65 delete 100</pre>
                    </div>
                    <div id="curl-delete" class="tab-content">
                        <pre>curl -X POST -H "Content-Type: application/json" \\
     -d '{"ip":"10.2.0.65","action":"delete","vlan":100}' \\
     http://localhost:8000/snmp_api.php</pre>
                    </div>
                    <div id="url-delete" class="tab-content">
                        <pre>http://localhost:8000/snmp_api.php/delete?ip=10.2.0.65&vlan=100</pre>
                    </div>
                </div>
            </div>
            <div class="try-it">
                <input type="text" id="ip-delete" placeholder="IP-адрес коммутатора">
                <input type="number" id="vlan-delete" placeholder="VLAN ID">
                <button onclick="tryEndpoint('delete')">Выполнить</button>
            </div>
        </div>

        <style>
            .notes {
                margin: 10px 0;
                padding: 10px;
                background: #fff3cd;
                border: 1px solid #ffeeba;
                border-radius: 4px;
            }
            .notes p {
                margin: 5px 0;
                color: #856404;
            }
            .notes strong {
                color: #533f03;
            }
        </style>
        
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
                
            case 'create':
                if (!isset($_GET['vlan'])) {
                    throw new Exception("Необходимо указать ID VLAN");
                }
                $result = $snmp->createVlan($_GET['vlan']);
                break;
                
            case 'delete':
                echo "DEBUG: Вход в case 'delete'\n";
                echo "DEBUG: vlan = " . ($_GET['vlan'] ?? 'null') . "\n";
                if ($_GET['vlan'] === null) {
                    throw new Exception("Необходимо указать ID VLAN");
                }
                $result = $snmp->deleteVlan($_GET['vlan']);
                echo "VLAN " . $_GET['vlan'] . " успешно удален\n";
                break;

            case 'vlans':
                $result = $snmp->getVlanDetails();
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
